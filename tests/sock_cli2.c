/*
 * Copyright (c) 2016-2017, Parallels International GmbH
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
#include <libgen.h>
#include <linux/limits.h>

#include "util.h"

int main(int argc, char **argv, char **envp)
{
	int rc;
	char *srv;
	int sock, ferr;
	unsigned long addr;
	struct sockaddr_in saddr;
	unsigned short port = 1812;
	struct string_list arglist;
	char *dir, *name;
	char path[PATH_MAX+1];

	if ( argc != 3 ) {
		fprintf(stderr, "Usage: %s address path\n", argv[0]);
		exit(1);
	}
	srv = argv[1];
	strncpy(path, argv[2], sizeof(path));
	name = basename(path);
	dir = dirname(path);

	string_list_init(&arglist);
	string_list_add(&arglist, "tar");
	string_list_add(&arglist, "-c");
	string_list_add(&arglist, "-S");
	string_list_add(&arglist, "--ignore-failed-read");
	string_list_add(&arglist, "-f");
	string_list_add(&arglist, "-");
	string_list_add(&arglist, "-C");
	string_list_add(&arglist, dir);
	string_list_add(&arglist, name);

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
		fprintf(stderr, "connect() err : %m\n");
		rc = 1;
		goto cleanup;
	}

//	fcntl(sock, F_SETFL, fcntl(sock, F_GETFL)|O_NONBLOCK);
/*
	fd = open("/dev/null", O_WRONLY);
*/
	ferr = dup(STDERR_FILENO);
	rc = run_rw(sock, sock, ferr, &arglist);
	close(ferr);
	printf("rc = %d\n", rc);
cleanup:
	close(sock);
	string_list_clean(&arglist);

	return rc;
}
