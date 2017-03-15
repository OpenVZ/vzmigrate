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
#include <string.h>
#include <stdlib.h>
#include <error.h>
#include <limits.h>
#include <getopt.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>

#define VZM_ERR_SYSTEM	1
#define VZ_TMP_DIR	"/vz/tmp"

int vzm_error(int err_code, const char * format, ...)
{
	va_list ap;
	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);
	return err_code;
}

/* get temporary directory */
int get_tmp_dir(char *path, size_t sz)
{
	int i;
	struct stat st;
	char *tmp_dirs[] = {VZ_TMP_DIR, "/var/tmp/", "/tmp/", NULL};
	char *tmp;

	/* use TMP envdir if exist */
	if ((tmp = getenv("TMP"))) {
		strncpy(path, tmp, sz);
		if (stat(path, &st) == 0) {
			if (S_ISDIR(st.st_mode)) {
				return 0;
			}
		}
	}
	/* check available tmpdir */
	for (i = 0; tmp_dirs[i]; i++) {
		if (stat(tmp_dirs[i], &st))
			continue;
		if (!S_ISDIR(st.st_mode))
			continue;
		strncpy(path, tmp_dirs[i], sz);
		return 0;
	}
	return -1;
}

int vzm_init(int arg)
{
	return 0;
}

int vzm_connect(const char *password, char *const *argv,
	int *ssh_in, int *ssh_out, pid_t *ssh_pid)
{
	int in[2], out[2];
	pid_t pid;
	long flags;
	int status, retcode;
	size_t size;

	if ((pipe(in) < 0) || (pipe(out) < 0))
		return vzm_error(VZM_ERR_SYSTEM, "pipe() error, %m");

	flags = fcntl(out[0], F_GETFL, &flags);
	flags = flags | O_NONBLOCK;
	fcntl(out[0], F_SETFL, flags);

	pid = fork();
	if (pid < 0) {
		close(in[1]); close(out[0]);
		close(in[0]); close(out[1]);
		return vzm_error(VZM_ERR_SYSTEM, "fork() : %m");
	} else if (pid == 0) {
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
		setsid();
		if (password) {
			/* if password is needs, create askpass file */
			int fd;
			FILE *fp;
			char tmpdir[PATH_MAX+1];
			char path[PATH_MAX+1];

			/* get temporary directory */
			if (get_tmp_dir(tmpdir, sizeof(tmpdir)))
				tmpdir[0] = '\0';

			snprintf(path, sizeof(path), "%s/askpass.XXXXXX", tmpdir);
			if ((fd = mkstemp(path)) == -1)
				return vzm_error(VZM_ERR_SYSTEM, "mkstemp(%s) : %m", path);

			if ((fp = fdopen(fd, "w")) == NULL) {
				close(fd);
				unlink(path);
				return vzm_error(VZM_ERR_SYSTEM, "fdopen(%s) : %m", path);
			}
			fprintf(fp, "#!/bin/sh\necho \"%s\"\nrm -f \"%s\"\n",
				password, path);
			fclose(fp);
			chmod(path, S_IRUSR|S_IXUSR);
			setenv("DISPLAY", "dummy", 0);
			setenv("SSH_ASKPASS", path, 1);
		}
		execvp(argv[0], argv);
		exit(VZM_ERR_SYSTEM);
	}
	close(in[0]); close(out[1]);

	while ((pid = waitpid(pid, &status, WNOHANG)) == -1)
		if (errno != EINTR)
			break;

	if (pid < 0) {
		close(in[1]); close(out[0]);
		return vzm_error(VZM_ERR_SYSTEM, "waitpid() error: %m");
	}
	if (WIFEXITED(status)) {
		if ((retcode = WEXITSTATUS(status))) {
			return vzm_error(VZM_ERR_SYSTEM,
				"%s failed, exitcode=%d", argv[0], retcode);
		}
	} else if (WIFSIGNALED(status)) {
		return vzm_error(VZM_ERR_SYSTEM, "%s got signal %d",
			argv[0], WTERMSIG(status));
	} else {
		return vzm_error(VZM_ERR_SYSTEM, "%s exited with status %d",
				argv[0], status);
	}

	*ssh_in = in[1];
	*ssh_out = out[0];
	*ssh_pid = pid;
	return 0;
}

