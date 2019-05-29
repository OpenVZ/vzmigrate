/*
 * Copyright (c) 2001-2017, Parallels International GmbH
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
 * Small pipe bash
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <sys/file.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <errno.h>
#include <stdarg.h>

#include "common.h"
#include "bincom.h"

#include <pwd.h>

static int fl = -1;
static int sock = -1;
static int lsock = -1;
static char lockfile[PATH_MAX+1];
static char sockfile[PATH_MAX+1];

long io_timeout = IO_TIMEOUT;

#define SIDE_DEST	1
#define SIDE_SRC	0

struct stream_side
{
	int in;
	int out;

	char buf[4096];
	int rc;
	int cur;
} fd[2];

/* fixme: UNIX_MAX_PATH=108 so better way is get hash from argv[2] */
static int get_lock(const char* name)
{
	snprintf(lockfile, sizeof(lockfile), VZMPIPE_DIR "%s" LOCK_FILE, name);
	if ((fl = open(lockfile, O_CREAT | O_TRUNC | O_RDWR, 0600)) < 0)
		return putErr(MIG_ERR_SYSTEM,"open(%s) error: %m", lockfile);
	if (flock(fl, LOCK_EX | LOCK_NB) < 0)
		return putErr(MIG_ERR_SYSTEM,"flock(%s) error: %m", lockfile);
	return 0;
}

static int create_stream(const char* name)
{
	int oldmask;
	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));

	addr.sun_family = AF_LOCAL;
	snprintf(addr.sun_path, sizeof(addr.sun_path),
	         VZMPIPE_DIR "%s" STREAM_FILE, name);
	strncpy(sockfile, addr.sun_path, sizeof(sockfile));

	lsock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (lsock < 0)
		return putErr(MIG_ERR_SYSTEM,"socket() error: %m");

	unlink(addr.sun_path);
	oldmask = umask(0177);
	if (bind(lsock, (struct sockaddr *) &addr, sizeof(addr)) < 0)
		return putErr(MIG_ERR_SYSTEM,
			"bind() to %s error", addr.sun_path);
	umask(oldmask);

	if (listen(lsock, SOMAXCONN) < 0)
		return putErr(MIG_ERR_SYSTEM,
			"listen() of %s error", addr.sun_path);
	return 0;
}

static void mainloop()
{
	fd_set rset;
	fd_set wset;
	int max;

	fd[SIDE_DEST].in = fd[SIDE_SRC].out = -1;
	fd[SIDE_DEST].out = STDOUT_FILENO;
	fd[SIDE_SRC].in = STDIN_FILENO;

	FD_ZERO(&wset);
	FD_ZERO(&rset);
	FD_SET(fd[SIDE_SRC].in, &rset);
	FD_SET(lsock, &rset);
	max = 1 + lsock;

	if (do_nonblock(STDOUT_FILENO) < 0)
		return;

	while (1)
	{
		int i;
		fd_set rcset = rset;
		fd_set wcset = wset;

		if (select(max, &rcset, &wcset, NULL, NULL) <= 0)
			return;

		if (lsock > 0 && FD_ISSET(lsock, &rcset))
		{
			fd[SIDE_DEST].in = fd[SIDE_SRC].out = sock
			                                      = accept(lsock, NULL, NULL);
			if (sock < 0)
				return;
			FD_SET(sock, &rset);
			FD_CLR(lsock, &rset);
			max = 1 + sock;

			if (do_nonblock(sock) < 0)
				return;

			close(lsock);
			lsock = -1;
		}

		for (i = 0; i <= 1; i++)
		{
			if (fd[i].in < 0 || !FD_ISSET(fd[i].in, &rcset))
				continue;
			fd[i].rc = read(fd[i].in, fd[i].buf, sizeof(fd[i].buf));
			if (fd[i].rc <= 0 || fd[i].out < 0)
				return;
			fd[i].cur = 0;
			FD_SET(fd[i].out, &wset);
			FD_CLR(fd[i].in, &rset);
		}

		for (i = 0; i <= 1; i++)
		{
			int rc;
			int sb;
			if (fd[i].out < 0 || !FD_ISSET(fd[i].out, &wcset))
				continue;
			sb = fd[i].rc - fd[i].cur;
			rc = write(fd[i].out, fd[i].buf+fd[i].cur, sb);
			if (rc < 0)
			{
				if (errno == EAGAIN)
					continue;
				else
					return;
			}

			if (rc == sb)
			{
				FD_SET(fd[i].in, &rset);
				FD_CLR(fd[i].out, &wset);
			}
			else
				fd[i].cur += rc;
		}
	}

	return;
}

static void failed(int code, int err, const char * format, ...)
{
	va_list pvar;
	va_start(pvar, format);
	vfprintf(stderr, format, pvar);
	fprintf(stderr, err ? " : [%d] %s\n" : "\n", err, strerror(err));
	va_end(pvar);
	exit(code);
}

#define AUTHORIZED_FILE "/%s/.ssh/authorized_keys"
static int set_ssh_key(const char * user)
{
	struct passwd * pw;
	char auth[PATH_MAX];
	char buf[BUFSIZ];
	char key[BUFSIZ];
	FILE * fd;
	char * p;

	if (fgets(key, sizeof(key), stdin) == NULL)
		failed(2, errno, "get key");
	if ((p = strrchr(key, '\n')))
		p[0] = 0;

	pw = getpwnam(user);
	if (pw == NULL)
		// no such user
		failed(2, errno, "no such user");

	sprintf(auth, AUTHORIZED_FILE, pw->pw_dir);

	fd = fopen(auth, "r");
	if (fd != NULL)
	{
		while (fgets(buf, sizeof(buf), fd))
		{
			if ((p = strrchr(buf, '\n')))
				p[0] = 0;
			if (!strcmp(buf, key))
				return 0;
		}
		fclose(fd);
	}

	fd = fopen(auth, "a");
	if (fd == NULL)
		failed(2, errno, "open '%s'", auth);

	fprintf(fd, "%s\n", key);
	return 0;
}

void cleanup(int)
{
	/* cleanup */
	if (sock >= 0)
		close(sock);
	if (lsock >= 0)
		close(lsock);
	if (strlen(sockfile))
		unlink(sockfile);
	if (fl >= 0)
		close(fl);
	if (strlen(lockfile))
		unlink(lockfile);
}

/* send data via stdin */
int send(const char * data, size_t size)
{
	int rc;
	size_t sent;
	fd_set fds;
	struct timeval tv;
	int fd = STDOUT_FILENO;

	if (size == 0)
		return 0;
	sent = 0;
	while (1) {
		while (1) {
			rc = write(fd, data + sent, (size_t)(size - sent));
			if (rc > 0) {
				sent += rc;
				if (sent >= size)
					return 0;
				continue;
			}
			if (errno == EAGAIN)
				break;
			else
				return putErr(MIG_ERR_CONN_BROKEN,
					MIG_MSG_SEND_PKT);
		}

		/* wait next data in socket */
		do {
			FD_ZERO(&fds);
			FD_SET(fd, &fds);
			tv.tv_sec = io_timeout;
			tv.tv_usec = 0;
			rc = select(fd + 1, NULL, &fds, NULL, &tv);
			if (rc == 0)
				return putErr(MIG_ERR_CONN_TIMEOUT,
					"can't send : timeout exceeded (%s sec)",
					io_timeout);
			else if (rc <= 0)
				return putErr(MIG_ERR_CONN_BROKEN,
					MIG_MSG_SEND_PKT);
		} while (!FD_ISSET(fd, &fds));
	}

	/* but we never should be here */
	return putErr(MIG_ERR_CONN_BROKEN, MIG_MSG_SEND_PKT);
}

int main(int argc, char ** argv)
{
	int rc = 0;
	char buffer[BUFSIZ + 1];
	struct sigaction sigact;

	*lockfile = '\0';
	*sockfile = '\0';
	/* ssh call bash as : bash -c command */
	if (argc != 3)
		rc = putErr(MIG_ERR_SYSTEM, "usage");
	else if (!strcmp(argv[1], "-s"))
		exit(set_ssh_key(argv[2]));
	else if ((rc = get_lock(argv[2])) != 0)
		;
	else
		rc = create_stream(argv[2]);

	sigact.sa_flags = 0;
	sigemptyset(&sigact.sa_mask);
	sigact.sa_handler = cleanup;
	sigaction(SIGTERM, &sigact, NULL);
	sigaction(SIGPIPE, &sigact, NULL);

	if (rc) {
		snprintf(buffer, sizeof(buffer), "|%d|%s", rc, getError());
		send(buffer, strlen(buffer) + 1);
		cleanup(0);
		exit(1);
	}

	strcpy(buffer, "|0|");
	rc = send(buffer, strlen(buffer) + 1);

	if (rc == 0)
		mainloop();

	cleanup(0);
	exit(1);
}

