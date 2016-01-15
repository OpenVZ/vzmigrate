/*
 * Copyright (c) 2016 Parallels IP Holdings GmbH
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
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <errno.h>

#include <vz/libvzsock.h>

#include "common.h"

int ch_send(
		struct vzsock_ctx *ctx,
		void *conn,
		const char *data,
		size_t size)
{
	int ret;

	if ((ret = vzsock_send(ctx, conn, data, size)))
		return putErr(MIG_ERR_VZSOCK, "vzsock_send() return %d", ret);
	return 0;
}
// set default function for data transter
int (*vzm_send)(struct vzsock_ctx *ctx, void *conn, const char * data, size_t size) = ch_send;

int vzsock_logger(int level, const char *fmt, va_list pvar)
{
	vprint_log(level, fmt, pvar);
	return 0;
}

/* expects messages to be in format |code|msg, if not is is treated as it were |0|msg */
/* if code > 0 - it is a log message, it printed to log and filtered out */
/* otherwise it is command execution result, set code and reply accordingly */
int recv_filter(char * buffer, int *code, char *reply, size_t *size)
{
	char *p = buffer;
	*code = 0;

	// find opening |
	if (*p != '|') {
		snprintf(reply, *size, "%s", p);
		return 0;
	}

	// find closing |
	for (p++; *p != '\0' && *p != '|'; p++);
	if (*p != '|') {
		*reply = '\0';
		return 0;
	}

	// get |code|
	*p++ = '\0';
	*code = strtol(buffer + 1, NULL, 10);

	if (*code >= MIG_ERR_DEBUG_OUT) {
		logger(LOG_DEBUG, "%s", p);
		return 1;
	}

	snprintf(reply, *size, "%s", p);

        return 0;
}



/* To read reply from 'DESTINATION' side as |errcode|:replymessage */
int ch_read_reply(
		struct vzsock_ctx *ctx,
		void *conn,
		int *code,
		char *reply,
		size_t size)
{
	int ret;

	if ((ret = vzsock_recv_str(ctx, conn, reply, &size)))
		return putErr(MIG_ERR_VZSOCK, "vzsock_recv_str() return %d", ret);
	*code = ctx->code;
	return 0;
}

/* return retcode from reply only */
int ch_read_retcode(
		struct vzsock_ctx *ctx,
		void *conn)
{
	char buffer[BUFSIZ];
	int rc, code;

	if ((rc = ch_read_reply(ctx, conn, &code, buffer, sizeof(buffer))))
		return rc;

	if (code && strlen(buffer))
		putErr(code, buffer);

	return code;
}

int ch_send_str(
		struct vzsock_ctx *ctx,
		void *conn,
		const char *str)
{
	return (*vzm_send)(ctx, conn, str, strlen(str)+1);
}

int ch_recv_str(
		struct vzsock_ctx *ctx,
		void *conn,
		char *buffer,
		size_t size)
{
	int ret;

	if ((ret = vzsock_recv_str(ctx, conn, buffer, &size)))
		return putErr(MIG_ERR_VZSOCK, "vzsock_recv() return %d", ret);
	return 0;
}

int ch_recv(
		struct vzsock_ctx *ctx,
		void *conn,
		char separator,
		char *buffer,
		size_t size)
{
	int ret;

	if ((ret = vzsock_recv(ctx, conn, separator, buffer, &size)))
		return putErr(MIG_ERR_VZSOCK, "vzsock_recv() return %d", ret);
	return 0;
}

/* Send packet and receive reply, return 'errcode' from reply */
int ch_send_cmd(
		struct vzsock_ctx *ctx,
		void *conn,
		const char *cmd)
{
	int rc;

	if ((rc = (*vzm_send)(ctx, conn, cmd, strlen(cmd)+1)))
		return rc;

	return ch_read_retcode(ctx, conn);
}

/* accept incoming connection on socket srvcosk during timeout "tmo" */
int sock_listen(int srvsock, long tmo)
{
	int rc = 0;
	time_t start_t;
	int flags = fcntl(srvsock, F_GETFL);

	/* suppose that we will use one port for all additional connection,
	   we can get EADDRINUSE for this port. Will try to listen
	   during timeout */
	fcntl(srvsock, F_SETFL, flags & ~O_NONBLOCK);
	start_t = time(NULL);
	while (1) {
		if (listen(srvsock, SOMAXCONN) == 0)
			break;

		if (errno != EADDRINUSE) {
			rc = putErr(MIG_ERR_SYSTEM, "listen() : %m");
			goto cleanup;
		}
		if (time(NULL) - start_t >= tmo) {
			rc = putErr(MIG_ERR_CONN_TIMEOUT,
				"listen() : timeout exceeded (%d sec)", tmo);
			goto cleanup;
		}
		sleep(1);
	}
cleanup:
	fcntl(srvsock, F_SETFL, flags);
	return rc;
}

/* accept incoming connection on socket srvsock during timeout "tmo" */
int sock_accept(int srvsock, long tmo, int *sock)
{
	int rc = 0;
	int ret;
	fd_set fds;
	struct timeval tv;
	struct sockaddr_storage addr;
	socklen_t addrsize;
	int flags = fcntl(srvsock, F_GETFL);

	fcntl(srvsock, F_SETFL, flags | O_NONBLOCK);
	while(1) {
		addrsize = sizeof(addr);
		if ((*sock = accept(srvsock,
				(struct sockaddr *)&addr, &addrsize)) >= 0)
			break;
		if (errno == EINTR) {
			continue;
		} else if ((errno != EAGAIN) && (errno != EWOULDBLOCK)) {
			rc = putErr(MIG_ERR_SYSTEM, "accept() : %m");
			goto cleanup;
		}

		do {
			FD_ZERO(&fds);
			FD_SET(srvsock, &fds);
			if (tmo) {
				tv.tv_sec = tmo;
				tv.tv_usec = 0;
				ret = select(srvsock + 1, &fds, NULL, NULL, &tv);
			} else {
				ret = select(srvsock + 1, &fds, NULL, NULL, NULL);
			}
			if (ret == 0) {
				rc = putErr(MIG_ERR_CONN_TIMEOUT, "select()"
					" : timeout exceeded (%d sec)", tmo);
				goto cleanup;
			} else if (ret == -1) {
				rc = putErr(MIG_ERR_SYSTEM, "select() : %m");
				goto cleanup;
			}
		} while (!FD_ISSET(srvsock, &fds));
	}
cleanup:
	fcntl(srvsock, F_SETFL, flags);
	return rc;
}

/* connect to "host:service" during timeout "tmo" */
int sock_connect(const char *host, const char *service, long tmo, int *out_sock)
{
	int ret;
	int rc = 0;
	fd_set fds;
	struct timeval tv;
	struct addrinfo hints;
	struct addrinfo *ai;
	struct addrinfo *ailist;
	int sock = -1;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_flags = AI_NUMERICHOST;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if ((ret = getaddrinfo(host, service, &hints, &ailist)))
		return putErr(MIG_ERR_SYSTEM,
			"getaddrinfo() : %s", gai_strerror(ret));

	for (ai = ailist; ai && (sock < 0); ai = ai->ai_next) {
		sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (sock < 0)
			continue;

		while(1) {
			if (connect(sock, ai->ai_addr, ai->ai_addrlen) == 0)
				goto cleanup;
			if (errno == EINTR) {
				continue;
			} else if (errno != EINPROGRESS) {
				logger(LOG_WARNING, "connect() : %m");
				break;
			}

			do {
				FD_ZERO(&fds);
				FD_SET(sock, &fds);
				if (tmo) {
					tv.tv_sec = tmo;
					tv.tv_usec = 0;
					/* writable event - see connect() man page */
					ret = select(sock + 1, NULL, &fds, NULL, &tv);
				} else {
					ret = select(sock + 1, NULL, &fds, NULL, NULL);
				}
				if (ret == 0) {
					logger(LOG_WARNING, "select() : "
						"timeout exceeded (%d sec)", tmo);
					goto next;
				} else if (ret == -1) {
					logger(LOG_WARNING, "select() : %m");
					goto next;
				}
			} while (!FD_ISSET(sock, &fds));
		}
next:
		close(sock);
		sock = -1;
	}
cleanup:
	freeaddrinfo(ailist);
	if (sock == -1) {
		rc = MIG_ERR_CANT_CONNECT;
		logger(LOG_ERR, "can't connect to %s:%s", host, service);
	} else {
		logger(LOG_DEBUG, "connection to %s:%s established",
				host, service);
		*out_sock = sock;
	}
	return rc;
}

/*
  read from nonblocking descriptor <fd> string, separated by <separator>.
  will write '\0' on the end of string
*/
int sock_read(
		int fd,
		long tmo,
		char separator,
		char *data,
		size_t *size)
{
	int rc;
	char * p;
	fd_set fds;
	size_t sz = 0;

	p = data;
	*p = '\0';
	while (1) {
		/* read data */
		while (1) {
			errno = 0;
			rc = read(fd, p, 1);
			if (rc > 0) {
				sz += rc;
				if (*p == separator) {
					*p = '\0';
					*size = sz;
					return 0;
				}
				p++;
				if (p >= data + *size)
					return putErr(MIG_ERR_CONN_TOOLONG,
						"read() : too long message");
				continue;
			} else if (rc == 0) {
				/* end of file */
				*p = '\0';
				*size = sz;
				return 0;
			}
			if (errno == EAGAIN)
				/* wait next data */
				break;
			else
				return putErr(MIG_ERR_CONN_BROKEN,
					"read() : %m");
		}

		/* wait next data in socket */
		do {
			FD_ZERO(&fds);
			FD_SET(fd, &fds);
			if (tmo) {
				struct timeval tv;
				tv.tv_sec = tmo;
				tv.tv_usec = 0;
				rc = select(fd + 1, &fds, NULL, NULL, &tv);
			} else {
				rc = select(fd + 1, &fds, NULL, NULL, NULL);
			}
			if (rc == 0)
				return putErr(MIG_ERR_CONN_TIMEOUT, "select()"
					" : timeout exceeded (%d sec)", tmo);
			else if (rc == -1)
				return putErr(MIG_ERR_CONN_BROKEN,
					"select() : %m");
		} while (!FD_ISSET(fd, &fds));
	}

	/* but we never should be here */
	return MIG_ERR_CONN_BROKEN;
}

/* 
 * Current function needed to workaround bug in splice system call used in
 * CRIU during online migration. Due to this bug splice system call work
 * correctly only with AF_INET sockets, but the only supported domain for
 * standard socketpair call is AF_UNIX. Current issue fixed in upstream kernel,
 * but it is too hard for now to backport these patches to our kernel.
 */
int inet_socketpair(int type, int protocol, int sv[2])
{
	int lfd = -1;
	int sfd = -1;
	int cfd = -1;
	struct sockaddr_in saddr;
	struct sockaddr_in caddr;
	socklen_t saddrlen;

	/* create listening socket and client socket */
	lfd = socket(AF_INET, type, protocol);
	cfd = socket(AF_INET, type, protocol);
	if ((lfd == -1) || (cfd == -1)) {
		putErr(-1, MIG_MSG_INTERNAL, "socket", errno);
		goto err;
	}

	/* start listen */
	if (listen(lfd, 1) == -1) {
		putErr(-1, MIG_MSG_INTERNAL, "listen", errno);
		goto err;
	}

	/* get ephemeral port number allocated to listening socket */
	memset(&saddr, 0, sizeof(saddr));
	saddrlen = sizeof(saddr);
	if (getsockname(lfd, (struct sockaddr*)&saddr, &saddrlen) == -1) {
		putErr(-1, MIG_MSG_INTERNAL, "getsockname", errno);
		goto err;
	}

	/* prepare server address needed to connect client socket */
	memset(&caddr, 0, sizeof(caddr));
	caddr.sin_family = AF_INET;
	caddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	caddr.sin_port = saddr.sin_port;

	/* connect client socket */
	if (connect(cfd, (struct sockaddr*)&caddr, sizeof(caddr)) == -1) {
		putErr(-1, MIG_MSG_INTERNAL, "connect", errno);
		goto err;
	}

	/* accept server socket */
	sfd = accept(lfd, NULL, NULL);
	if (sfd == -1) {
		putErr(-1, MIG_MSG_INTERNAL, "accept", errno);
		goto err;
	}

	close(lfd);
	sv[0] = sfd;
	sv[1] = cfd;
	return 0;

err:
	close(lfd);
	close(sfd);
	close(cfd);
	return -1;
}
