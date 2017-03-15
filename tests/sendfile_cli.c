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
#include <sys/sendfile.h>
#include <sys/mman.h>
#include <getopt.h>

#include "sendfile.h"

#define SENDFILE_MODE	0
#define MMAP_MODE	1

void show_usage(const char *name)
{
	fprintf(stderr, "Usage: %s [options] hostname file\n", name);
	fprintf(stderr, "\t-h, --help\n");
	fprintf(stderr, "\t-p, --port N        set port number\n");
	fprintf(stderr, "\t-b, --blocksize N   set data block size\n");
	fprintf(stderr, "\t-s, --sendfile      use sendfile()\n");
	fprintf(stderr, "\t-m, --map           use mmap()\n");
}

int snd_sendfile(int fd, int sock, size_t size, size_t blksize)
{
	off_t offset;
	ssize_t sent;

	for (offset = 0; offset < size;) {
		sent = sendfile(sock, fd, &offset,
			((size - offset) > blksize) ? blksize : size - offset);
		if (sent < 0) {
			perror("sendfile()");
			return -1;
		}
//		printf("send %ld data, total %lu\n", sent, offset);
	}
	return 0;
}

int snd_mmap(int fd, int sock, size_t size, size_t blksize)
{
	int rc = 0;
	void *data;
	off_t offset;
	ssize_t sent;

/*
	off_t start;
    for(start=0; start < size; start += 0x100000)
    {
        if(size - start > 0x100000)
            length = 0x100000;
        else
            length = size - start;
	data = mmap(NULL, length, PROT_READ, MAP_PRIVATE, fd, start);
*/

	data = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (data == NULL) {
		perror("mmap()");
		return -1;
	}

	for (offset = 0; offset < size;) {
		sent = write(sock, data + offset,
			((size - offset) > blksize) ? blksize : size - offset);
		if (sent < 0) {
			perror("write()");
			rc = -1;
			break;
		}
		offset += sent;
		printf("send %ld data, total %lu\n", sent, offset);
	}
	munmap(data, size);
	return rc;
}

int main(int argc, char **argv, char **envp)
{
	int rc;
	int c;
	char *hostname;
	char *fname;
	int mode = SENDFILE_MODE;
	size_t blksize = 16384;
	// see http://blog.superpat.com/2010/06/01/zero-copy-in-linux-with-sendfile-and-splice/
	char *p;

	int sock;
	unsigned long addr;
	struct sockaddr_in saddr;
	unsigned short port = SENDFILE_TEST_PORT;
	struct stat st;
	int fd;
	struct command cmd;
	size_t size;

	static char short_options[] = "hp:b:sm";
	static struct option long_options[] =
	{
		{"help", no_argument, NULL, 'h'},
		{"port", required_argument, NULL, 'p'},
		{"blocksize", required_argument, NULL, 'b'},
		{"sendfile", no_argument, NULL, 's'},
		{"map", no_argument, NULL, 'm'},
	};

	while ((c = getopt_long(argc, argv, short_options, long_options, NULL)) != -1)
	{
		switch (c) {
		case 'h':
			show_usage(argv[0]);
			exit(0);
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
		case 's':
			mode = SENDFILE_MODE;
			break;
		case 'm':
			mode = MMAP_MODE;
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
	size = st.st_size;

	cmd.id = CMD_SIZE;
	cmd.data = size;
	rc = write(sock, (void *)&cmd, sizeof(cmd));
	if (rc < 0) {
		fprintf(stderr, "write() : %m\n");
		exit(1);
	}

	fd = open(fname, O_RDONLY);
	if (fd == -1) {
		perror("open()");
		exit(1);
	}
	if (mode == MMAP_MODE)
		rc = snd_mmap(fd, sock, size, blksize);
	else
		rc = snd_sendfile(fd, sock, size, blksize);
	close(fd);
	return rc;
}


