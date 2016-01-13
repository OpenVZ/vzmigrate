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

#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "sendfile.h"

int main(int argc, char **argv, char **envp)
{
	int rc;
	int srv_sock, sock;
	struct sockaddr_in saddr;
	struct sockaddr_in caddr;
	socklen_t caddr_len;
	unsigned short port = SENDFILE_TEST_PORT;
	char *fname;
	int fd;
	struct command cmd;
	size_t size;
	off_t offset, off;
	int pipefd[2];
	ssize_t bytes, bytes_sent, bytes_in_pipe;

	if ( argc != 2 ) {
		fprintf(stderr, "Usage: %s target_path\n", argv[0]);
		exit(1);
	}
	fname = argv[1];

	if ((srv_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		fprintf(stderr, "socket() err : %m\n");
		exit(1);
	}

	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = INADDR_ANY;
	saddr.sin_port = htons(port);

	if (bind(srv_sock, (struct sockaddr *)&saddr, sizeof(saddr))) {
		fprintf(stderr, "bind() err : %m\n");
		exit(1);
	}

	if (listen(srv_sock, SOMAXCONN)) {
		fprintf(stderr, "listen() err : %m\n");
		exit(1);
	}

	caddr_len = sizeof(caddr);
	if ((sock = accept(srv_sock, (struct sockaddr *)&caddr, &caddr_len)) < 0) {
		fprintf(stderr, "accept() err : %m\n");
		exit(1);
	}

	if (pipe(pipefd) < 0) {
		fprintf(stderr, "pipe() : %m\n");
		exit(1);
	}

	rc = read(sock, (void *)&cmd, sizeof(cmd));
	if (rc < 0) {
		fprintf(stderr, "read() : %m\n");
		exit(1);
	} else if (rc != sizeof(cmd)) {
		fprintf(stderr, "read() : wait %lu, read %d\n", sizeof(cmd), rc);
		exit(1);
	}
	size = cmd.data;

	fd = creat(fname, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		fprintf(stderr, "creat(%s) : %m\n", fname);
		exit(1);
	}

	fcntl(sock, F_SETFL, fcntl(sock, F_GETFL) | O_NONBLOCK);
	fcntl(pipefd[1], F_SETFL, fcntl(pipefd[1], F_GETFL) | O_NONBLOCK);

	fcntl(pipefd[0], F_SETFL, fcntl(pipefd[0], F_GETFL) | O_NONBLOCK);
	fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);

	for (offset = 0; offset < size;) {
		bytes_sent = splice(sock, NULL, pipefd[1], NULL, size - offset, SPLICE_F_NONBLOCK);
		if (bytes_sent < 0) {
			if (errno == EAGAIN)
				continue;
			perror("splice()");
			exit(1);
		}
		if (bytes_sent == 0) {
			perror("splice()");
			exit(1);
		}
		bytes_in_pipe = bytes_sent;
		while (bytes_in_pipe > 0) {
			off = offset;
			bytes = splice(pipefd[0], NULL, fd, &off, bytes_in_pipe, SPLICE_F_NONBLOCK);
			// ! for /dev/null splice() does not change offset
			if (bytes < 0) {
				if (errno == EAGAIN)
					continue;
				perror("splice");
				exit(1);
			}
			bytes_in_pipe -= bytes;
			offset += bytes;
		}
//		printf("receive %lu data\n", bytes_sent);
	}
	close(fd);
	close(sock);
	close(srv_sock);

	return 0;
}

//http://blog.superpat.com/2010/06/01/zero-copy-in-linux-with-sendfile-and-splice/
