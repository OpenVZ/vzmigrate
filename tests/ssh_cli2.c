/*
 * Copyright (c) 2016-2017, Parallels International GmbH
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
 * Our contact details: Parallels International GmbH, Vordergasse 59, 8200
 * Schaffhausen, Switzerland.
 */

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <limits.h>

// common ssh args
const char * ssh_args[1000] =
{
"ssh", "-T", "-q", "-c",
/* blowfish is faster then DES3,
but arcfour is faster then blowfish, according #84995 */
"arcfour",
"-o", "StrictHostKeyChecking=no",
"-o", "CheckHostIP=no",
"-o", "UserKnownHostsFile=/dev/null",
"-o", "PreferredAuthentications=publickey,password,keyboard-interactive",
"10.30.21.117",
"tar -p -S --same-owner -x -C /vz/tmp/",
NULL
};

int main(int argc, char **argv)
{
	int rc = 0;
	pid_t ssh_pid, tar_pid, pid;
	int status;
	int retcode;
	long flags;
	const char *tar_argv[] =
		{"tar", "-c", "-S", "--ignore-failed-read", "-f", "-", "-C", "/vz/template/", "centos", NULL};
	int in[2], out[2];
	char *password = "1q2w3e";

	if ((pipe(in) < 0) || (pipe(out) < 0)) {
		fprintf(stderr, "pipe() err : %m\n");
		return -1;
	}

	flags = fcntl(out[0], F_GETFL, &flags);
	flags = flags | O_NONBLOCK;
//	fcntl(out[0], F_SETFL, flags);

	ssh_pid = fork();
	if (ssh_pid < 0) {
		close(in[1]); close(out[0]);
		close(in[0]); close(out[1]);
		fprintf(stderr, "fork() err : %m\n");
		return -1;
	} else if (ssh_pid == 0) {
//		int fd;
		/* allow C-c for child */
		signal(SIGINT, SIG_DFL);
		/* redirect stdout to out and stdin to in */
		close(STDIN_FILENO); close(STDOUT_FILENO);
		close(in[1]); close(out[0]);
		dup2(in[0], STDIN_FILENO);
		dup2(out[1], STDOUT_FILENO);
/*
		if ((fd = open("/dev/null", O_WRONLY)) != -1) {
			close(STDERR_FILENO);
			dup2(fd, STDERR_FILENO);
		}
*/
		close(in[0]); close(out[1]);
		setsid();
		if (password) {
			/* if password is needs, create askpass file */
			int fd;
			FILE *fp;
			char path[PATH_MAX+1];

			snprintf(path, sizeof(path), "/tmp/askpass.XXXXXX");
			if ((fd = mkstemp(path)) == -1) {
				fprintf(stderr, "mkstemp() err : %m\n");
				return -1;
			}
			if ((fp = fdopen(fd, "w")) == NULL) {
				close(fd);
				unlink(path);
				fprintf(stderr, "fdopen(%s) : %m\n", path);
				return -1;
			}
			fprintf(fp, "#!/bin/sh\necho \"%s\"\nrm -f \"%s\"\n",
				password, path);
			fclose(fp);
			chmod(path, S_IRUSR|S_IXUSR);
			setenv("DISPLAY", "dummy", 0);
			setenv("SSH_ASKPASS", path, 1);
		}
		execvp(ssh_args[0], (char *const *)ssh_args);
		exit(-1);
	}
	close(in[0]); close(out[1]);
	while ((pid = waitpid(ssh_pid, &status, WNOHANG)) == -1)
		if (errno != EINTR)
			break;

	if (pid < 0) {
		close(in[1]); close(out[0]);
		fprintf(stderr, "waitpid() : %m\n");
		return -1;
	}

	/* run reader on this node */
	tar_pid = fork();
	if (tar_pid < 0) {
		close(in[1]); close(out[0]);
		fprintf(stderr, "fork() : %m\n");
		return -1;
	} else if (tar_pid == 0) {
//		int fd;
		/* allow C-c for child */
		signal(SIGINT, SIG_DFL);
		/* redirect stdout to out and stdin to in */
		close(STDOUT_FILENO); close(STDIN_FILENO);
		dup2(in[1], STDOUT_FILENO);
		dup2(out[0], STDIN_FILENO);
/*
		if ((fd = open("/dev/null", O_WRONLY)) != -1) {
			close(STDERR_FILENO);
			dup2(fd, STDERR_FILENO);
		}
*/
		close(in[1]); close(out[0]);
		execvp(tar_argv[0], (char *const *)tar_argv);
		exit(-1);
	}
	close(in[1]); close(out[0]);

	rc = 0;
	while (1) {
		while ((pid = waitpid(-1, &status, 0)) == -1)
			if (errno != EINTR)
				break;
		if (pid < 0) {
			fprintf(stderr, "waitpid() : %m\n");
			return -1;
		}

		if (pid == ssh_pid) {
			ssh_pid = -1;
			if (WIFEXITED(status)) {
				if ((retcode = WEXITSTATUS(status))) {
					fprintf(stderr, "%s failed, exitcode=%d\n",
						ssh_args[0], retcode);
					rc = -1;
				}
			} else if (WIFSIGNALED(status)) {
				fprintf(stderr, "%s got signal %d\n",
					ssh_args[0], WTERMSIG(status));
				rc = -1;
			} else {
				fprintf(stderr, "%s exited with status %d\n",
					ssh_args[0], status);
				rc = -1;
			}
			if (rc) {
				/* remote task failed or signaled, send SIGTERM to
				local task and exit immediately */
				if (tar_pid >= 0)
					kill(tar_pid, SIGTERM);
				return rc;
			}
			if (tar_pid == -1)
				break;
		} else if (pid == tar_pid) {
			tar_pid = -1;
			if (WIFEXITED(status)) {
				if ((retcode = WEXITSTATUS(status))) {
					fprintf(stderr, "%s failed, exitcode=%d\n",
						tar_argv[0], retcode);
					rc = -1;
				}
			} else if (WIFSIGNALED(status)) {
				fprintf(stderr, "%s got signal %d\n",
					tar_argv[0], WTERMSIG(status));
				rc = -1;
			} else {
				fprintf(stderr, "%s exited with status %d\n",
					tar_argv[0], status);
				rc = -1;
			}
			if (rc) {
				/* local task failed or signaled, send SIGTERM to
				remote task and exit immediately */
				if (ssh_pid >= 0)
					kill(ssh_pid, SIGTERM);
				return rc;
			}
			if (ssh_pid == -1)
				break;
		}
	}
	return 0;
}
