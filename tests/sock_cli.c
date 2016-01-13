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
#include <time.h>

int main(int argc, char **argv, char **envp)
{
	int rc = 0;
	char *srv;
	int sock;
	unsigned long addr;
	struct sockaddr_in saddr;
	unsigned short port = 1812;
	int max_size = 813*1024*1024;
	int i, j;
//	char buf[10*1024*1024];
	char buf[16384];

	if ( argc != 2 ) {
		fprintf(stderr, "Usage: %s addr\n", argv[0]);
		exit(1);
	}
	srv = argv[1];

	srand(time(NULL));

	if ((addr = inet_addr(srv)) == INADDR_NONE) {
		/* need to resolve address */
		struct hostent *host;
		if ((host = gethostbyname(srv)) == NULL) {
			fprintf(stderr, "gethostbyname(%s) err : %m\n", srv);
			exit(1);
		}
		memcpy(&addr, host->h_addr, sizeof(addr));
	}

	if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		fprintf(stderr, "socket() err : %m\n");
		exit (1);
	}

	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = addr;
	saddr.sin_port = htons(port);

	if (connect(sock, (struct sockaddr *)&saddr, sizeof(saddr))) {
		// if (errno != EINPROGRESS) - for NONBLOCK
		fprintf(stderr, "connect() : %m\n");
		rc = 1;
		goto cleanup;
	}

//	fcntl(sock, F_SETFL, fcntl(sock, F_GETFL)|O_NONBLOCK);
	i = 0;
	while (i < max_size) {
		for (j = 0; (j < sizeof(buf)) && (i < max_size); j++, i++) {
			buf[j] = (char) (255.0*rand()/(RAND_MAX+1.0));
		}
		if (write(sock, buf, j) < 0) {
			fprintf(stderr, "write() : %m\n");
			rc = 1;
			goto cleanup;
		}
	}
	printf("%d bytes wrote\n", i);
cleanup:
	close(sock);

	return rc;
}
