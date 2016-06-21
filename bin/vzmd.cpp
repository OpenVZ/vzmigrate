/* $Id$
 *
 * Copyright (c) 2008-2016 Parallels IP Holdings GmbH
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
 * Our contact details: Parallels IP Holdings GmbH, Vordergasse 59, 8200
 * Schaffhausen, Switzerland.
 *
 * vzmigrate daemon
 */
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <getopt.h>

#include <vzctl/libvzctl.h>

#include <vz/libvzsock.h>

#include "common.h"
#include "util.h"
#include "bincom.h"
//#include "ssl.h"
#include "migchannel.h"
#include "veentry.h"
#include "migratedst.h"
#include "server.h"

int test_mode = 0;

static MigrateStateCommon *conn = NULL;

/* global vz config data */
struct vz_data *vzcnf = NULL;
void *istorage_ctx = NULL;

static char progname[NAME_MAX + 1];
static char pidfile[PATH_MAX + 1];

/* this function call by logger() & putErr() to send message to client */
void print_out(int level, const char * str)
{
	if (conn == NULL)
		return;
	conn->channel.sendErrMsg(level + MIG_ERR_DEBUG_OUT, "%s", str);
}

static int parse_ve_entry(char *token, CNewVEsList *ve_list)
{
	int rc;
	char *arg = token;
	char *p;
	ctid_t src_ctid;
	ctid_t dst_ctid;
	char *root_path = NULL;
	char *priv_path = NULL;

	/* Read entry as :
	<src_ctid>[:<dst_ctid>[:<dst_priv_dir>[:<dst_root_dir>]]]
	*/

	// Read 'source' ctid
	if ((p = strchr(arg, ':')) == NULL) {
		SET_CTID(src_ctid, arg);
		SET_CTID(dst_ctid, src_ctid);
		goto finish;
	} else {
		*p = '\0';
		SET_CTID(src_ctid, arg);
		SET_CTID(dst_ctid, src_ctid);
	}

	// Read 'dst' ctid
	arg = ++p;
	if ((p = strchr(arg, ':')) == NULL) {
		SET_CTID(dst_ctid, arg);
		goto finish;
	} else {
		*p = '\0';
		SET_CTID(dst_ctid, arg);
	}

	// Read 'dst' priv_path
	arg = ++p;
	if ((p = strchr(arg, ':')) == NULL) {
		if (*arg != '/')
			return putErr(MIG_ERR_USAGE, "Bad path %s", arg);
		priv_path = strdup(arg);
		goto finish;
	} else {
		*p = '\0';
		if (*arg != '/')
			return putErr(MIG_ERR_USAGE, "Bad path %s", arg);
		priv_path = strdup(arg);
	}

	// Read 'dst' root_path
	arg = ++p;
	if (*arg != '/')
		return putErr(MIG_ERR_USAGE, "Bad path %s", arg);
	root_path = strdup(arg);

finish:
	VEObj * ve = new VEObj(dst_ctid);
	if (ve == NULL)
		return putErr(MIG_ERR_SYSTEM, "new() : %m");

	(*ve_list)[std::string(ve->ctid())] = ve;

	ve->setPrivate(priv_path);
	ve->setRoot(root_path);
	if ((rc = ve->init_empty()))
		return rc;

	return 0;
}

int process_connection(struct vzsock_ctx *ctx, int sock)
{
	int rc;
	void (*print_func_old)(int level, const char * str);
	char *reply, *p, *token;
	unsigned long long options;
	int dlevel;
	void *cn;
	int ret;

	signal(SIGCHLD, SIG_DFL);
	signal(SIGINT, SIG_DFL);

	if ((ret = vzsock_accept_conn(ctx, (void *)&sock, &cn)))
		return putErr(MIG_ERR_VZSOCK,
			"vzsock_accept_conn() return %d", ret);

	if ((conn = new(MigrateStateCommon)) == NULL) {
		rc = putErr(MIG_ERR_SYSTEM, "new() : %m");
		goto cleanup_0;
	}

	/* TODO !!! */
	conn->channel.ctx = *ctx;
	conn->channel.conn = cn;

	/* redirect err msg in socket */
	print_func_old = print_func;
	print_func = print_out;

	/* wait package with binary name */
	if ((reply = conn->channel.readPkt(PACKET_SEPARATOR, &rc)) == NULL) {
		rc = putErr(rc, "can't read package from client");
		goto cleanup_1;
	}
	p = reply + strlen(CMD_BINARY) + 1;
	logger(LOG_DEBUG, "%s", reply);
	if (strcmp(p, "vzmigrate") == 0) {
		VZMoptions.bintype = BIN_DEST;
		if ((g_veList = new CNewVEsList()) == NULL) {
			rc = putErr(MIG_ERR_SYSTEM, "new() : %m");
			goto cleanup_1;
		}
	} else if (strcmp(p, "vzmtemplate") == 0) {
		rc = putErr(MIG_ERR_PROTOCOL, "vzmtemplate is not supported for PCS7", p);
		goto cleanup_1;
	} else {
		rc = putErr(MIG_ERR_PROTOCOL, "unknown binary %s", p);
		goto cleanup_1;
	}

	/* send reply with version */
	if ((rc = conn->channel.sendReply(0, CMD_VERSION " %d", MIGRATE_VERSION)))
		goto cleanup_2;

	/* wait package with remote version, options and debug level  */
	if ((reply = conn->channel.readPkt(PACKET_SEPARATOR, &rc)) == NULL) {
		rc = putErr(rc, "can't read package from client");
		goto cleanup_2;
	}
	logger(LOG_DEBUG, "%s", reply);
	if (sscanf(reply, CMD_START_PARAMS " %d %llu %d",
		&VZMoptions.remote_version, &options, &dlevel) != 3)
	{
		rc = putErr(MIG_ERR_PROTOCOL,
			"unknown remote version : %s", reply);
		goto cleanup_2;
	}
	VZMoptions.options = OPT_SOCKET;
	/* Use debug_level, OPT_ONLINE and OPT_EZTEMPLATE.
	   vzmdest get this parameters via command line */
	VZMoptions.options |= options & (OPT_ONLINE|OPT_EZTEMPLATE);
	/* do not decrease own debug level */
	if (dlevel > debug_level)
		debug_level = dlevel;

	if ((rc = conn->channel.sendReply(0, "")))
		goto cleanup_2;

	/* wait package */
	if ((reply = conn->channel.readPkt(PACKET_SEPARATOR, &rc)) == NULL)
		goto cleanup_2;
	logger(LOG_DEBUG, "%s", reply);

	/* process arguments list */
	for (p = reply + strlen(CMD_ARGUMENTS) + 1; ;p = NULL) {
		if ((token = strtok(p, " ")) == NULL)
			break;
		/* process VEID:private:root record */
		if ((rc = parse_ve_entry(token, g_veList)))
			goto cleanup_2;
	}

	if ((rc = conn->channel.sendReply(0, "")))
		goto cleanup_2;

	rc = main_loop();

	print_func = print_func_old;

cleanup_2:
	delete g_veList;
	g_veList = NULL;
cleanup_1:
	delete conn;
	conn = NULL;
cleanup_0:
	vzsock_close_conn(ctx, cn);

	return rc;
}

static void usage()
{
	fprintf(stderr, "@PRODUCT_NAME_LONG@ vzmigrate daemon\n");
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "%s [-v] [-t]\n", progname);
	fprintf(stderr, "%s -h\n", progname);
	fprintf(stderr,"  Options:\n");
	fprintf(stderr,"    -h/--help           show usage and exit\n");
	fprintf(stderr,"    -v/--verbose        be verbose\n");
	fprintf(stderr,"    -t/--test           test mode (do not daemonize)\n");
}

static int parse_cmd_line(int argc, char *argv[])
{
	int c;
	struct option options[] =
	{
		{"verbose", no_argument, NULL, 'v'},
		{"test", no_argument, NULL, 't'},
		{"help", no_argument, NULL, 'h'},
		{ NULL, 0, NULL, 0 }
	};

	while (1)
	{
		c = getopt_long(argc, argv, "vht", options, NULL);
		if (c == -1)
			break;
		switch (c)
		{
		case 'v':
			debug_level = LOG_DEBUG;
			break;
		case 't':
			test_mode = 1;
			break;
		case 'h':
			usage();
			exit(0);
		default:
			usage();
			exit(-MIG_ERR_USAGE);
		}
	}
	return 0;
}

void terminate(int)
{
	// send sigterm to all processes in group
	kill(0, SIGTERM);

	unlink(pidfile);
	exit(-MIG_ERR_TERM);
}

int main(int argc, char *argv[])
{
	int rc;
	pid_t pid;
	int fd;
	struct sockaddr_storage addr;
	socklen_t addrsize;
	int srvsock;
	struct sigaction sigact;
	FILE *fp;
	struct stat st;
	struct vzsock_ctx ctx;
	int sock;

	static struct vz_data vz_conf;

	strncpy(progname, basename(argv[0]), sizeof(progname));
	snprintf(pidfile, sizeof(pidfile), "/var/run/%s.pid", progname);

	if (stat(pidfile, &st) == 0) {
		if ((fp = fopen(pidfile, "rw")) == NULL) {
			rc = putErr(MIG_ERR_SYSTEM, "fopen('%s') : %m", pidfile);
			goto cleanup_0;
		}
		fscanf(fp, "%d", &pid);
		if (kill(pid, 0) == 0) {
			rc = putErr(MIG_ERR_ALREDY_RUNNING,
				"%s already running with pid %d",
				progname, pid);
			goto cleanup_0;
		}
	} else {
		if ((fp = fopen(pidfile, "w")) == NULL) {
			rc = putErr(MIG_ERR_SYSTEM, "fopen('%s') : %m", pidfile);
			goto cleanup_0;
		}
	}

	/* init vzctl */
	if ((rc = vzctl2_lib_init())) {
		rc = putErr(MIG_ERR_VZCTL, "vzctl initialize error %d", rc);
		goto cleanup_1;
	}

	/* suppress libvzctl stderr and stdout */
/* vzctl logger() conflict with vzmigrate logger(): FIXME
	vzctl2_set_log_quiet(1);*/

/* TODO: reread config by SIGHUP */
	/* read global vz config */
	vzcnf = &vz_conf;
	if ((rc = vz_data_load(vzcnf)))
		goto cleanup_2;

	parse_cmd_line(argc, argv);

	open_logger("vzmd");

	snprintf(VZMoptions.tmo.str, sizeof(VZMoptions.tmo.str),
			"%ld", VZMoptions.tmo.val);

	if ((rc = init_sock_server(&ctx, &srvsock)))
		goto cleanup_4;

	if (!test_mode) {
		pid = fork();
		if (pid < 0) {
			rc = putErr(MIG_ERR_SYSTEM, "fork() : %m");
			goto cleanup_5;
		}
		if (pid > 0) {
			/* parent process */
			exit(0);
		}

		/* do not close all descriptors:
		   vzctl lib has open descriptor, ssl too */
		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		close(STDERR_FILENO);

		if (setsid() == -1) {
			rc = putErr(MIG_ERR_SYSTEM, "setsid() : %m");
			goto cleanup_5;
		}
		pid = fork();
		if (pid < 0) {
			rc = putErr(MIG_ERR_SYSTEM, "fork() : %m");
			goto cleanup_5;
		}
		if (pid > 0) {
			/* parent process */
			exit(0);
		}

		/*
		 * now we are in a new session and process
		 * group than process that started the
		 * daemon. We also have no controlling
		 * terminal */
		chdir("/");
		umask(0);

		fprintf(fp, "%d\n", getpid());
		fclose(fp);

		if ((fd = open("/dev/null", O_RDWR)) == -1) {
			rc = putErr(MIG_ERR_SYSTEM, "open('/dev/null') : %m");
			goto cleanup_5;
		}
		dup2(fd, STDIN_FILENO);
		dup2(fd, STDOUT_FILENO);
		dup2(fd, STDERR_FILENO);

		signal(SIGCHLD, SIG_IGN);
		signal(SIGTSTP, SIG_IGN);
		signal(SIGTTOU, SIG_IGN);
		signal(SIGTTIN, SIG_IGN);
		signal(SIGINT, SIG_IGN);
/* TODO : reload configs for SIGHUP */
		signal(SIGHUP, SIG_IGN);
	}

	sigemptyset(&sigact.sa_mask);
	sigact.sa_handler = terminate;
	sigact.sa_flags = 0;
	sigaction(SIGTERM, &sigact, NULL);

/* TODO: other signals ? */
/* TODO: lockf(/var/run/vzmd.pid) */

	logger(LOG_INFO, "Started");
	// Apply IO limits if any
	vz_setiolimit();

	while (1) {
		addrsize = sizeof(addr);
		if ((sock = accept(srvsock, (struct sockaddr *)&addr, &addrsize)) < 0)
		{
			rc = putErr(MIG_ERR_SYSTEM, "accept() : %m");
			goto cleanup_5;
		}

		pid = fork();
		if (pid < 0) {
			logger(LOG_ERR, "fork() : %m");
		} else if (pid == 0) {
			if (addr.ss_family == AF_INET) {
				struct sockaddr_in *addr_in = (struct sockaddr_in *)&addr;
				logger(LOG_INFO, "Incoming connection from %s", inet_ntoa(addr_in->sin_addr));
			} else {
				logger(LOG_INFO, "Incoming connection");
			}
			close(srvsock);
			rc = process_connection(&ctx, sock);
			exit(-rc);
		}
		close(sock);
	}

cleanup_5:
	close(srvsock);
	vzsock_close(&ctx);

cleanup_4:
	closelog();

cleanup_2:
	vzctl2_lib_close();

cleanup_1:
	fclose(fp);
	unlink(pidfile);

cleanup_0:
	exit(-rc);
}

