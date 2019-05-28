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
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <getopt.h>

#include "sendfile.h"

static int verbose = 0;

void show_usage(const char *name)
{
	fprintf(stderr, "Usage: %s [options] hostname file\n", name);
	fprintf(stderr, "\t-h, --help\n");
	fprintf(stderr, "\t-v, --verbose\n");
	fprintf(stderr, "\t-p, --port N        set port number\n");
	fprintf(stderr, "\t-b, --blocksize N   set data block size\n");
}

int send_data(int fd, int sock, size_t size, size_t blksize)
{
	int rc = 0;
	struct command cmd;

	off_t offset;
	ssize_t read_bytes, write_bytes;
	void *buffer;

	cmd.id = CMD_SIZE;
	cmd.data = size;
	rc = write(sock, (void *)&cmd, sizeof(cmd));
	if (rc < 0) {
		perror("write()");
		return -1;
	}

	if (posix_memalign(&buffer, 4096, blksize)) {
                perror("posix_memalign()");
		return -1;
	}

	offset = 0;
	do {
		read_bytes = pread(fd, buffer, blksize, offset);
		if (read_bytes < 0) {
			perror("pread()");
			rc = 1;
			break;
		}
		offset += read_bytes;
		if (verbose)
			printf("read %ld data, total %lu\n", read_bytes, offset);

		write_bytes = write(sock, buffer, read_bytes);
		if (write_bytes < 0) {
			perror("write()");
			rc = -1;
			break;
		}
		if (verbose)
			printf("write %ld data\n", write_bytes);
	} while (read_bytes > 0);

	free(buffer);
	return rc;
}

int main(int argc, char **argv, char **envp)
{
	int rc = 0;
	int c;
	char *hostname;
	char *fname;
	size_t blksize = 0x4000;
	char *p;

	unsigned long addr;
	struct sockaddr_in saddr;
	unsigned short port = SENDFILE_TEST_PORT;
	struct stat st;

	int sock;
	int fd;

	static char short_options[] = "hvp:b:";
	static struct option long_options[] =
	{
		{"help", no_argument, NULL, 'h'},
		{"verbose", no_argument, NULL, 'v'},
		{"port", required_argument, NULL, 'p'},
		{"blocksize", required_argument, NULL, 'b'},
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
		case 'b':
			blksize = strtol(optarg, &p, 10);
			if (*p != '\0') {
				fprintf(stderr, "Invalid blocksize : %s\n", optarg);
				exit(1);
			}
			break;
		default:
			show_usage(argv[0]);
			exit(1);
		}
	}
	if (argc - optind < 2) {
		show_usage(argv[0]);
		exit(1);
	}
	hostname = argv[optind];
	fname = argv[optind+1];

	if ((addr = inet_addr(hostname)) == INADDR_NONE) {
		/* need to resolve address */
		struct hostent *host;
		if ((host = gethostbyname(argv[1])) == NULL) {
			fprintf(stderr, "gethostbyname(%s) err : %m\n", hostname);
			exit(1);
		}
		memcpy(&addr, host->h_addr, sizeof(addr));
	}
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = addr;
	saddr.sin_port = htons(port);

	if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		fprintf(stderr, "socket() err : %m\n");
		exit(1);
	}
	if (connect(sock, (struct sockaddr *)&saddr, sizeof(saddr))) {
		fprintf(stderr, "connect() err : %m\n");
		exit(1);
	}

	if (stat(fname, &st) < 0) {
		fprintf(stderr, "stat() : %m\n");
		exit(1);
	}
	fd = open(fname, O_RDONLY|O_DIRECT);
	if (fd == -1) {
		perror("open()");
		exit(1);
	}

	rc = send_data(fd, sock, st.st_size, blksize);
	close(fd);
	return rc;
}


