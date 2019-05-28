/*
 * Copyright (c) 2006-2017, Parallels International GmbH
 * Copyright (c) 2017-2019 Virtuozzo International GmbH. All rights reserved.
 *
 * This file is part of OpenVZ. OpenVZ is free software; you can redistribute
 * it and/or modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 *
 * Our contact details: Virtuozzo International GmbH, Vordergasse 59, 8200
 * Schaffhausen, Switzerland.
 *
 */
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <vz/libvzsock.h>

#include "util.h"
#include "channel.h"
#include "migssh.h"
#include "common.h"
#include "bincom.h"

pid_t tar_dst_pid = -1;

void MigrateSshChannel::killSshChannel()
{
	if (!isConnected())
		return;
/* TODO: add functions for ssl and vza ang move to MigrateChannel */
	logger(LOG_DEBUG, "close channel");
	vzsock_close(&ctx);
}

static int generate_askpass(const char *pass, char *path, size_t size)
{
	int fd;
	FILE *fp;
	char tmpdir[PATH_MAX+1];
	const char *p;

	path[0] = '\0';
	if (pass == NULL)
		return 0;

	if (strlen(pass) == 0)
		return 0;

	/* get temporary directory */
	if (get_tmp_dir(tmpdir, sizeof(tmpdir)))
		tmpdir[0] = '\0';

	snprintf(path, size, "%s/askpass.XXXXXX", tmpdir);
	if ((fd = mkstemp(path)) == -1)
		return putErr(MIG_ERR_SYSTEM, "mkstemp(%s) : %m", path);

	if ((fp = fdopen(fd, "w")) == NULL) {
		close(fd);
		unlink(path);
		return putErr(MIG_ERR_SYSTEM, "fdopen(%s) : %m", path);
	}
	fprintf(fp, "#!/bin/sh\necho \"");
	for (p = pass; *p; p++) {
		if (strchr("\\\"$`", *p))
			fputc('\\', fp);
		fputc(*p, fp);
	}
	fprintf(fp, "\"\nrm -f \"%s\"\n", path);
	fclose(fp);
	chmod(path, S_IRUSR|S_IXUSR);

	return 0;
}

/* copy <dir> to remote host by tar via ssh */
int ssh_send_data(
		struct vzsock_ctx *ctx,
		void *conn,
		const char * cmd,
		char * const *tar_argv)
{
	int rc = 0;
	char buffer[2*PATH_MAX+100];
	char reply[BUFSIZ+1];
	pid_t ssh_pid = -1, tar_pid = -1, pid;
	int status;
	char path[PATH_MAX];
	const char *ssh_argv[MAX_ARGS];
	int in[2], out[2];
	int ret;
	char password[BUFSIZ];
	size_t size;
	int i;
	char dst[BUFSIZ];
	struct string_list_el *p;
	bool use_sparse = false;
	int wait_tar[2], wait_ssh[2];
	fd_set wait_fds;
	int wait_max, sel_num;

	if (VZMoptions.dst_user)
		snprintf(dst, sizeof(dst), "%s@%s",
			VZMoptions.dst_user, VZMoptions.dst_addr);
	else
		strncpy(dst, VZMoptions.dst_addr, sizeof(dst));

	size = sizeof(password);
	if ((ret = vzsock_get(ctx, VZSOCK_DATA_PASSWORD, (void *)password, &size)))
		return putErr(MIG_ERR_VZSOCK, "vzsock_get() return %d", ret);

	/* if password is needs, create askpass file */
	if ((rc = generate_askpass(password, path, sizeof(path))))
		return rc;

	init_pipes(in); init_pipes(out);
	init_pipes(wait_tar); init_pipes(wait_ssh);
	if ((open_pipes(in) < 0) || (open_pipes(out) < 0) ||
			(open_pipes(wait_tar) < 0) || (open_pipes(wait_ssh) < 0)){
		rc = putErr(MIG_ERR_SYSTEM, "pipe() error, %m");
		goto cleanup;
	}

	do_nonblock(out[0]);

	/* send command to dst */
	if ((ret = vzsock_send(ctx, conn, cmd, strlen(cmd) + 1))) {
		rc = putErr(MIG_ERR_VZSOCK, "vzsock_send() return %d", ret);
		goto cleanup;
	}

	/* and wait reply with target dir */
	size = sizeof(reply);
	if ((ret = vzsock_recv_str(ctx, conn, reply, &size))) {
		rc = putErr(MIG_ERR_VZSOCK, "vzsock_recv_str() return %d", ret);
		goto cleanup;
	}

	/* run tar server on destination node */
	for (i = 0; tar_argv[i]; i++) {
		if (	(strcmp("--sparse", tar_argv[i]) == 0) ||
			(strcmp("-S", tar_argv[i]) == 0))
		{
			use_sparse = true;
			break;
		}
	}
	snprintf(buffer, sizeof(buffer),
	"echo $$ > %s/" PID_FILE "; %s -p %s --same-owner -x -C %s",
		reply, BIN_TAR, use_sparse ? "-S" : "", reply);

	ssh_argv[0] = "ssh";
	for (p = VZMoptions.ssh_options.tqh_first, i = 0; p && i < MAX_ARGS-5; p = p->e.tqe_next, i++)
		ssh_argv[i+1] = p->s;
	ssh_argv[i+1] = dst;
	ssh_argv[i+2] = buffer;
	ssh_argv[i+3] = NULL;

	if (debug_level >= LOG_DEBUG)
		dump_args("dst: ", (char* const*)ssh_argv);

	ssh_pid = fork();
	if (ssh_pid < 0) {
		rc = putErr(MIG_ERR_SYSTEM, "fork() : %m");
		goto cleanup;
	} else if (ssh_pid == 0) {
		int fd;
		/* allow C-c for child */
		signal(SIGINT, SIG_DFL);
		/* redirect stdout to out and stdin to in */
		close(STDIN_FILENO); close(STDOUT_FILENO);
		close(in[1]); close(out[0]);
		dup2(in[0], STDIN_FILENO);
		dup2(out[1], STDOUT_FILENO);
		if ((fd = open("/dev/null", O_WRONLY)) != -1) {
			close(STDERR_FILENO);
			dup2(fd, STDERR_FILENO);
		}
		close(in[0]); close(out[1]);
		if (strlen(path)) {
			setenv("DISPLAY", "dummy", 0);
			setenv("SSH_ASKPASS", path, 1);
		}
		setsid();
		close(wait_ssh[0]); close(wait_tar[1]); close(wait_tar[0]);
		execvp(ssh_argv[0], (char *const *)ssh_argv);
		exit(MIG_ERR_SYSTEM);
	}
	close_safe(&in[0]); close_safe(&out[1]);
	while ((pid = waitpid(ssh_pid, &status, WNOHANG)) == -1)
		if (errno != EINTR)
			break;

	if (pid < 0) {
		rc = putErr(MIG_ERR_SYSTEM, "waitpid() error: %m");
		goto cleanup;
	}

	if (debug_level >= LOG_DEBUG)
		dump_args("src: ", tar_argv);

	tar_pid = fork();
	if (tar_pid < 0) {
		rc = putErr(MIG_ERR_SYSTEM, "fork() error: %m");
		goto cleanup;
	} else if (tar_pid == 0) {
		int fd;
		/* allow C-c for child */
		signal(SIGINT, SIG_DFL);
		/* redirect stdout to out and stdin to in */
		close(STDOUT_FILENO); close(STDIN_FILENO);
		dup2(in[1], STDOUT_FILENO);
		dup2(out[0], STDIN_FILENO);
		if ((fd = open("/dev/null", O_WRONLY)) != -1) {
			close(STDERR_FILENO);
			dup2(fd, STDERR_FILENO);
		}
		close(in[1]); close(out[0]);
		close(wait_tar[0]); close(wait_ssh[1]); close(wait_ssh[0]);
		execvp(tar_argv[0], (char *const *)tar_argv);
		exit(MIG_ERR_SYSTEM);
	}
	close_safe(&in[1]); close_safe(&out[0]);
	close_safe(&wait_tar[1]); close_safe(&wait_ssh[1]);

	if ((ret = vzsock_send(ctx, conn, "ssh_started", strlen("ssh_started") + 1))) {
		rc = putErr(MIG_ERR_VZSOCK, "vzsock_send() return %d", ret);
		goto cleanup;
	}

	rc = 0;

	while (tar_pid != -1 || ssh_pid != -1) {
		FD_ZERO(&wait_fds);
		wait_max = 0;
		if (ssh_pid != -1) {
			FD_SET(wait_ssh[0], &wait_fds);
			wait_max = wait_max > wait_ssh[0] ? wait_max : wait_ssh[0];
		}
		if (tar_pid != -1) {
			FD_SET(wait_tar[0], &wait_fds);
			wait_max = wait_max > wait_tar[0] ? wait_max : wait_tar[0];
		}

		while (((sel_num = select(wait_max + 1, &wait_fds, NULL, NULL, NULL)) < 0 ) && (errno == EINTR));

		if (sel_num == -1) {
			rc = putErr(MIG_ERR_SYSTEM, "select() : %m");
			goto cleanup;
		}

		if (ssh_pid != -1 && FD_ISSET(wait_ssh[0], &wait_fds)) {
			if (waitpid(ssh_pid, &status, 0) < 0) {
				rc = putErr(MIG_ERR_SYSTEM, "waitpid(%i) : %m", ssh_pid);
				goto cleanup;
			}
			ssh_pid = -1;
			if ((rc = check_exit_status((char *)ssh_argv[0], status))) {
				/* remote task failed or signaled, send SIGTERM to
				local task and exit immediately */
				goto cleanup;
			}
		}
		if (tar_pid != -1 && FD_ISSET(wait_tar[0], &wait_fds)) {
			if (waitpid(tar_pid, &status, 0) < 0) {
				rc = putErr(MIG_ERR_SYSTEM, "waitpid(%i) : %m", tar_pid);
				goto cleanup;
			}
			tar_pid = -1;
			if (WIFEXITED(status)) {
				int retcode = WEXITSTATUS(status);
				/* https://jira.sw.ru/browse/PCLIN-29957
				   note : this function calls for tar only */
				if (retcode) {
					logger(LOG_ERR, "%s exited with code %d",
							tar_argv[0], retcode);
					if (retcode != 1) {
						rc = MIG_ERR_SYSTEM;
						goto cleanup;
					}
					logger(LOG_WARNING, "Ignore %s exit code %d, continue",
							tar_argv[0], retcode);
				}
			} else {
				rc = putErr(MIG_ERR_SYSTEM,
					"%s exited with status %d", tar_argv[0], status);
				/* local task failed or signaled, send SIGTERM to
				remote task and exit immediately */
				goto cleanup;
			}
		}
	}
cleanup:
	if (tar_pid >= 0)
		term_clean(tar_pid, 60);
	if (ssh_pid >= 0)
		term_clean(ssh_pid, 60);

	close_pipes(in);
	close_pipes(out);
	close_pipes(wait_tar);
	close_pipes(wait_ssh);

	if (strlen(path))
		unlink(path);

	return rc;
}

/* Filesystem objects coping via tar:
   - run ssh with tar on src
   - wait tar exiting on dst */
int ssh_recv_data(
		struct vzsock_ctx *ctx,
		void *conn,
		char * const args[],
		const char *dst,
		long timeout)
{
	(void) ctx;
	(void) args;
	int ret;
	char path[PATH_MAX+1];
	char buf[BUFSIZ];
	FILE *fp;
	time_t tstart;
	size_t size;

	snprintf(path, sizeof(path), "%s/" PID_FILE, dst);
	if (access(dst, F_OK)) {
		return putErr(MIG_ERR_SYSTEM,
			"Directory %s does not exist before tar", dst);
	}

	/* return basedir for path */
	if ((ret = vzsock_send(ctx, conn, dst, strlen(dst) + 1)))
		return putErr(MIG_ERR_VZSOCK, "vzsock_send() return %d", ret);

	/* and wait reply */
	size = sizeof(buf);
	if ((ret = vzsock_recv_str(ctx, conn, buf, &size)))
		putErr(MIG_ERR_VZSOCK, "vzsock_recv_str() return %d", ret);

	tstart = time(NULL);
	while (access(path, R_OK)) {
		if (tstart + timeout < time(NULL))
			/* it is not a bug -
			   do not wait ssh and continue */
			return 0;
		sleep(1);
	}
	if ((fp = fopen(path, "r")) != NULL) {
		if (fgets(buf, sizeof(buf), fp) != NULL) {
			tar_dst_pid = atol(buf);
		}
		fclose(fp);
	}
	unlink(path);
	if (tar_dst_pid < 0)
		return 0;
	/* and wait */
	logger(LOG_DEBUG, "wait 'ssh ... " BIN_TAR " ...' with pid %d", tar_dst_pid);
	while (kill(tar_dst_pid, 0) == 0)
		sleep(1);
	tar_dst_pid = -1;
	logger(LOG_DEBUG, "continue ... %s", strerror(errno));
	return 0;
}

/*
  connect()/accept() via ssh forwarded ports:
*/

MigrateSshChannel::MigrateSshChannel()
{
	m_sFwdPort = (char *)"4422";
	m_nFwdSrvSock = -1;
}

int MigrateSshChannel::fwdAddPort(CVZMOptions *options)
{
	char buffer[BUFSIZ];

	string_list_add(&options->ssh_options, "-L");
	snprintf(buffer, sizeof(buffer),
		"%s:localhost:%s", m_sFwdPort, m_sFwdPort);
	string_list_add(&options->ssh_options, buffer);
	return 0;
}

int MigrateSshChannel::fwdBind()
{
	int rc = 0;
	int ret;
	struct addrinfo hints, *res, *ressave;
	int on = 1;
	int i;
	int ai_family[2] = { AF_INET, AF_INET6 };

	if (m_nFwdSrvSock != -1) {
		logger(LOG_WARNING,
			"MigrateSshChannel::fwdBind() : socket already bound");
		return 0;
	}

	for (i = 0; (i < 2) && (m_nFwdSrvSock == -1); i++) {
		memset(&hints, 0, sizeof(struct addrinfo));
		/*
		   AI_PASSIVE flag: the resulting address is used to bind
		   to a socket for accepting incoming connections.
		   So, when the hostname==NULL, getaddrinfo function will
		   return one entry per allowed protocol family containing
		   the unspecified address for that family.
		*/
		hints.ai_flags    = AI_PASSIVE;
		hints.ai_family   = ai_family[i];
		hints.ai_socktype = SOCK_STREAM;

		if ((ret = getaddrinfo(NULL, m_sFwdPort, &hints, &ressave)))
			return putErr(MIG_ERR_SYSTEM,
				"getaddrinfo error: %s", gai_strerror(ret));

		/*
		   Try open socket with each address getaddrinfo returned,
		   until getting a valid listening socket.
		*/
		m_nFwdSrvSock = -1;
		for (res = ressave; res && (m_nFwdSrvSock < 0); res = res->ai_next) {
			m_nFwdSrvSock = socket(res->ai_family,
						res->ai_socktype, res->ai_protocol);
			if (m_nFwdSrvSock < 0) {
				putErr(MIG_ERR_SYSTEM, "socket() : %m");
				continue;
			}
			if (setsockopt(m_nFwdSrvSock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0)
				logger(LOG_ERR, "setsockopt() : %m");
			if (bind(m_nFwdSrvSock, res->ai_addr, res->ai_addrlen)) {
				putErr(MIG_ERR_SYSTEM, "bind() : %m");
				close(m_nFwdSrvSock);
				m_nFwdSrvSock = -1;
			}
		}
	}
	if (m_nFwdSrvSock == -1) {
		rc = putErr(MIG_ERR_SYSTEM,
				"socket error : could not open socket");
		goto cleanup_0;
	}

        freeaddrinfo(ressave);
	return 0;

	close(m_nFwdSrvSock);
	m_nFwdSrvSock = -1;
cleanup_0:
        freeaddrinfo(ressave);

	return rc;
}

void MigrateSshChannel::fwdSrvClose()
{
	if (m_nFwdSrvSock == -1)
		close(m_nFwdSrvSock);
	m_nFwdSrvSock = -1;
}

int MigrateSshChannel::fwdSendData(const char *cmd, char * const *argv)
{
	int rc = 0;
	char buffer[BUFSIZ];
	int ret;
	int sock;

	/* send command to dst */
	if ((rc = ch_send_str(&ctx, conn, cmd)))
		return rc;
	/* wait target hostname in reply */
	if ((rc = ch_read_reply(&ctx, conn, &ret, buffer, sizeof(buffer))))
		return rc;
	if (ret)
		return putErr(ret, buffer);

	if (sock_connect(buffer, m_sFwdPort, VZMoptions.tmo.val, &sock)) {
		return putErr(MIG_ERR_CANT_CONNECT,
			"can't connect to host %s port %s", buffer, m_sFwdPort);
	}
	do_block(sock);

	ret = 0;
	rc = vzm_execve(argv, NULL, sock, sock, &ret);
	/* to close used socket */
	close(sock);
	if ((rc) && (ret == 1)) {
		/* https://jira.sw.ru/browse/PCLIN-29957
		   note : this function calls for tar only */
		logger(LOG_WARNING, "Ignore %s exit code %d, continue",
					argv[0], ret);
		rc = 0;
	}
	return rc;
}

int MigrateSshChannel::fwdRecvData(char * const argv[])
{
	int rc = 0;
	int sock = -1;
	struct sockaddr_storage addr;
	socklen_t addrlen = sizeof(addr);
	char buffer[BUFSIZ];

	if (sock_listen(m_nFwdSrvSock, VZMoptions.tmo.val))
		return putErr(MIG_ERR_CANT_CONNECT, "can't accept connection");

	if (getsockname(m_nFwdSrvSock, (struct sockaddr *)&addr, &addrlen))
		return putErr(MIG_ERR_CANT_CONNECT, "getsockname() : %m");
	if (getnameinfo((struct sockaddr *)&addr, addrlen,
			buffer, sizeof(buffer), NULL, 0, NI_NUMERICHOST))
		return putErr(MIG_ERR_CANT_CONNECT, "getnameinfo() : %m");

	/* send reply with bound address and success retcode for syncronization */
	if ((rc = sendReply(0, buffer)))
		return rc;

	if (sock_accept(m_nFwdSrvSock, VZMoptions.tmo.val, &sock))
		return putErr(MIG_ERR_CANT_CONNECT, "can't accept connection");

	do_block(sock);
	rc = vzm_execve(argv, NULL, sock, sock, NULL);
	close(sock);

	return rc;
}
