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
#include <sys/wait.h>

#include "util.h"

int main(int argc, char **argv, char **envp)
{
	int rc;
	int sock;
	struct sockaddr_in saddr;
	struct sockaddr_in caddr;
	int caddr_len;
	unsigned short port = 1812;
	int fd, ferr;
	char *dir;
	struct string_list arglist;

	if ( argc != 2 ) {
		fprintf(stderr, "Usage: %s dir\n", argv[0]);
		exit(1);
	}
	dir = argv[1];

	string_list_init(&arglist);
	string_list_add(&arglist, "tar");
	string_list_add(&arglist, "-p");
	string_list_add(&arglist, "-S");
	string_list_add(&arglist, "--same-owner");
	string_list_add(&arglist, "-x");
	string_list_add(&arglist, "-C");
	string_list_add(&arglist, dir);

	if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		fprintf(stderr, "socket() err : %m\n");
		exit (1);
	}

	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = INADDR_ANY;
	saddr.sin_port = htons(port);

	if (bind(sock, (struct sockaddr *)&saddr, sizeof(saddr))) {
		fprintf(stderr, "bind() err : %m\n");
		rc = 1;
		goto cleanup;
	}

	if (listen(sock, SOMAXCONN)) {
		fprintf(stderr, "listen() err : %m\n");
		rc = 1;
		goto cleanup;
	}

	caddr_len = sizeof(caddr);
	if ((fd = accept(sock, (struct sockaddr *)&caddr, &caddr_len)) < 0) {
		fprintf(stderr, "accept() err : %m\n");
		rc = 1;
		goto cleanup;
	}

//	fcntl(fd, F_SETFL, fcntl(sock, F_GETFL)|O_NONBLOCK);
	ferr = dup(STDERR_FILENO);
	rc = run_rw(fd, fd, ferr, &arglist);
	close(ferr);
	printf("rc = %d\n", rc);
	close(fd);
cleanup:
	close(sock);
	string_list_clean(&arglist);

	return rc;
}
