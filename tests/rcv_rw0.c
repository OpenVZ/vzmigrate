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
#include <getopt.h>
#include <pthread.h>

#include "sendfile.h"

static int verbose = 0;

void show_usage(const char *name)
{
	fprintf(stderr, "Usage: %s [options] file\n", name);
	fprintf(stderr, "\t-h, --help\n");
	fprintf(stderr, "\t-v, --verbose\n");
	fprintf(stderr, "\t-p, --port N        set port number\n");
	fprintf(stderr, "\t-b, --blocksize N   set data block size\n");
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
	size_t blksize = 0x40000;
	int fd;
	struct command cmd;
	size_t size;
	mode_t mode = S_IRUSR | S_IWUSR;
	void *buffer;
	ssize_t bytes;
	off_t offset;

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
	if (argc - optind < 1) {
		show_usage(argv[0]);
		exit(1);
	}
	fname = argv[optind];

	if (posix_memalign(&buffer, 4096, blksize)) {
                perror("posix_memalign()");
		exit(1);
	}

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

	rc = read(sock, (void *)&cmd, sizeof(cmd));
	if (rc < 0) {
		fprintf(stderr, "read() : %m\n");
		exit(1);
	} else if (rc != sizeof(cmd)) {
		fprintf(stderr, "read() : wait %lu, read %d\n", sizeof(cmd), rc);
		exit(1);
	}
	size = cmd.data;

	fd = open(fname, O_WRONLY|O_CREAT/*|O_EXCL*/, mode);
	if (fd < 0) {
		fprintf(stderr, "open(%s) : %m\n", fname);
		exit(1);
	}

	offset = 0;
	do {
		bytes = read(sock, (void *)buffer, sizeof(buffer));
		if (bytes < 0) {
			perror("read()");
			rc = -1;
			break;
		}
		bytes = pwrite(fd, buffer, bytes, offset);
		if (bytes < 0) {
			perror("write()");
			rc = -1;
			break;
		}
		offset += bytes;
		if (verbose)
			printf("wrote %ld data, total %lu\n", bytes, offset);

	} while (offset < size);
	close(fd);
	close(sock);
	close(srv_sock);

	return rc;
}
