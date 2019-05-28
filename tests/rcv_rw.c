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
#include <getopt.h>
#include <pthread.h>

#include "sendfile.h"

static int verbose = 0;

struct rcv_data {
	int fd;
	void *buffer;
	size_t size;
	off_t offset;
	pthread_mutex_t read_mutex;
	pthread_cond_t read_cond;
	pthread_mutex_t write_mutex;
	pthread_cond_t write_cond;
};

void show_usage(const char *name)
{
	fprintf(stderr, "Usage: %s [options] file\n", name);
	fprintf(stderr, "\t-h, --help\n");
	fprintf(stderr, "\t-v, --verbose\n");
	fprintf(stderr, "\t-p, --port N        set port number\n");
	fprintf(stderr, "\t-b, --blocksize N   set data block size\n");
}

static int nread(int fd, void * buf, int len)
{
	int rd = 0;

	while (len) {
		int n;

		n = read(fd, buf, len);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			break;
		len -= n;
		buf += n;
		rd += n;
	}

	if (len == 0)
		return rd;

	errno = EIO;
	return -1;
}

static void *write_func(void* d)
{
	long rc = 0;
	struct rcv_data *data = (struct rcv_data *)d;
	ssize_t write_bytes = 0;

	pthread_mutex_lock(&data->write_mutex);
//printf("	write_mutex.lock\n");
	while (1) {
		/*
		   - unlock full buffer
		   - wait till main thread read data, put it into buffer and wake up this thread
		   - lock and write full buffer
		*/
//printf("	pthread_cond_wait(write) start\n");
		if (pthread_cond_wait(&data->write_cond, &data->write_mutex)) {
			perror("pthread_cond_wait()");
			rc = -1;
			break;
		}
//printf("pthread_cond_wait(write) end\n");
		if (data->size == 0) {
			if (verbose)
				printf("write thread completed\n");
			break;
		}

		write_bytes = pwrite(data->fd, data->buffer, data->size, data->offset);
		if (write_bytes < 0) {
			perror("write()");
			rc = -1;
			break;
		}
		if (verbose)
			printf("write %ld data\n", write_bytes);

		/* wait till write thread send buffer */
		pthread_mutex_lock(&data->read_mutex);
//printf("write_mutex.lock\n");
		/* and wake up write task */
		pthread_cond_signal(&data->read_cond);
//printf("pthread_cond_signal(write)\n");
		pthread_mutex_unlock(&data->read_mutex);
//printf("write_mutex.unlock\n");
	}
	pthread_mutex_unlock(&data->write_mutex);
//printf("	write_mutex.unlock\n");
	pthread_exit((void *)rc);
}

int recv_data(int fd, int sock, size_t size, size_t blksize)
{
	int rc = 0;
	long retcode;
	pthread_t write_th;

	off_t offset;
	ssize_t read_bytes = 0;
	void *buffer, *ptr;
	struct rcv_data data;

	data.fd = fd;

	if (posix_memalign(&buffer, 4096, blksize)) {
                perror("posix_memalign()");
		return -1;
	}
	if (posix_memalign(&data.buffer, 4096, blksize)) {
                perror("posix_memalign()");
		rc = -1;
		goto cleanup_0;
	}

	if (pthread_mutex_init(&data.read_mutex, NULL)) {
		perror("pthread_mutex_init()");
		rc = -1;
		goto cleanup_1;
	}
	if (pthread_cond_init(&data.read_cond, NULL)) {
		perror("pthread_cond_init()");
		rc = -1;
		goto cleanup_2;
	}
	if (pthread_mutex_init(&data.write_mutex, NULL)) {
		perror("pthread_mutex_init()");
		rc = -1;
		goto cleanup_3;
	}
	if (pthread_cond_init(&data.write_cond, NULL)) {
		perror("pthread_cond_init()");
		rc = -1;
		goto cleanup_4;
	}

	if (pthread_create(&write_th, NULL, write_func, (void*)&data) < 0) {
		perror("phtread_create()");
		rc = -1;
		goto cleanup_5;
	}

	pthread_mutex_lock(&data.read_mutex);
//	read_bytes = nread(sock, buffer, blksize);
	read_bytes = read(sock, buffer, blksize);
	if (read_bytes < 0) {
		perror("pread()");
		rc = 1;
		goto cleanup_5;
	}
	offset = 0;
	if (verbose)
		printf("read %ld data, total %lu\n", read_bytes, offset);

	do {
		if (pthread_kill(write_th, 0)) {
			perror("pthread_kill()");
			break;
		}

		/* wait till write thread send buffer */
		pthread_mutex_lock(&data.write_mutex);
//printf("write_mutex.lock\n");
		/* swap input and output buffers */
		ptr = data.buffer;
		data.buffer = buffer;
		data.size = read_bytes;
		data.offset = offset;
		buffer = ptr;
		offset += read_bytes;
		/* and wake up write task */
		pthread_cond_signal(&data.write_cond);
//printf("pthread_cond_signal(write)\n");
		pthread_mutex_unlock(&data.write_mutex);
//printf("write_mutex.unlock\n");
//if (!pthread_mutex_trylock(&data.write_mutex)) {
//printf("!!!!!!!!!!!!!!!!!!!!!!\n");
//pthread_mutex_unlock(&data.write_mutex);
//}

//		read_bytes = nread(sock, buffer, blksize);
		read_bytes = read(sock, buffer, blksize);
		if (read_bytes < 0) {
			perror("nread()");
			rc = -1;
			break;
		}
		if (verbose)
			printf("read %ld data, total %lu\n", read_bytes, offset);

		// now wait till write task frees its buffer
//printf("pthread_cond_wait(read) start\n");
		if (pthread_cond_wait(&data.read_cond, &data.read_mutex)) {
			perror("pthread_cond_wait()");
			rc = -1;
			break;
		}
//printf("pthread_cond_wait(read) end\n");


//if (!pthread_mutex_trylock(&data.write_mutex)) {
//printf("!!!!!!!!!!!!!!!!!!!!!!\n");
//pthread_mutex_unlock(&data.write_mutex);
//}
	} while (read_bytes > 0);
	pthread_mutex_unlock(&data.read_mutex);

	// to stop write task
	pthread_mutex_lock(&data.write_mutex);
	data.size = 0;
	pthread_cond_signal(&data.write_cond);
	pthread_mutex_unlock(&data.write_mutex);
	pthread_join(write_th, (void **)&retcode);
	printf("retcode = %ld, offset=%lu\n", retcode, offset);

cleanup_5:
	pthread_cond_destroy(&data.write_cond);
cleanup_4:
	pthread_mutex_destroy(&data.write_mutex);
cleanup_3:
	pthread_cond_destroy(&data.read_cond);
cleanup_2:
	pthread_mutex_destroy(&data.read_mutex);
cleanup_1:
	free(data.buffer);
cleanup_0:
	free(buffer);
	return rc;
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

	fd = open(fname, O_WRONLY|O_CREAT|O_EXCL, mode);
	if (fd < 0) {
		fprintf(stderr, "creat(%s) : %m\n", fname);
		exit(1);
	}

	rc = recv_data(fd, sock, size, blksize);

	close(fd);
	close(sock);
	close(srv_sock);

	return rc;
}

//http://blog.superpat.com/2010/06/01/zero-copy-in-linux-with-sendfile-and-splice/
