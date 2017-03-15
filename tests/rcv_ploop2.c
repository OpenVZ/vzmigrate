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
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <getopt.h>
#include <pthread.h>
#include <linux/types.h>
#include <linux/limits.h>

#include "../bin/ploop.h"

#include "sendfile.h"

void show_usage(const char *name)
{
	fprintf(stderr, "Usage: %s [options] file\n", name);
	fprintf(stderr, "\t-h, --help\n");
	fprintf(stderr, "\t-v, --verbose\n");
	fprintf(stderr, "\t-p, --port N        set port number\n");
	fprintf(stderr, "\t-t, --timeout N     set connection timeout in seconds\n");
}

int main(int argc, char **argv, char **envp)
{
	int rc;
	int c;
	char *p;

	int srv_sock, sock;
	struct sockaddr_in saddr;
	struct sockaddr_in caddr;
	socklen_t caddr_len;
	unsigned short port = SENDFILE_TEST_PORT;

	char *fname;
	size_t tmo = 600;
	int verbose = 0;
	struct ploop_online_copy_data data;

	static char short_options[] = "hvp:t:";
	static struct option long_options[] =
	{
		{"help", no_argument, NULL, 'h'},
		{"verbose", no_argument, NULL, 'v'},
		{"port", required_argument, NULL, 'p'},
		{"timeout", required_argument, NULL, 't'},
	};

	while ((c = getopt_long(argc, argv, short_options, long_options, NULL)) != -1)
	{
		switch (c) {
		case 'h':
			show_usage(argv[0]);
			exit(0);
		case 'v':
			verbose = 1;
			break;
		case 'p':
			port = strtoul(optarg, &p, 10);
			if (*p != '\0') {
				fprintf(stderr, "Invalid port number : %s\n", optarg);
				exit(1);
			}
			break;
		case 't':
			tmo = strtol(optarg, &p, 10);
			if (*p != '\0') {
				fprintf(stderr, "Invalid timeout : %s\n", optarg);
				exit(1);
			}
			break;
		default:
			show_usage(argv[0]);
			exit(1);
		}
	}
	if (argc - optind < 1) {
		show_usage(argv[0]);
		exit(1);
	}
	fname = argv[optind];

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
	/* set socket nonblock */
	if ((fcntl(sock, F_SETFL, fcntl(sock, F_GETFL) | O_NONBLOCK)) == -1) {
		fprintf(stderr, "fcntl() err : %m\n");
		exit(1);
	}

	rc = ploop_dst_online_copy_image_1(fname, sock, tmo, &data);
	if (rc)
		return rc;

	rc = ploop_dst_online_copy_image_2(&data);
	if (rc)
		return rc;

	close(sock);
	close(srv_sock);

	return rc;
}

//http://blog.superpat.com/2010/06/01/zero-copy-in-linux-with-sendfile-and-splice/
