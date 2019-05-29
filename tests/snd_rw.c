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
#include <pthread.h>

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

struct file_read_thread_data {
	int sock;
	void *buffer;
	size_t size;
	pthread_mutex_t read_mutex;
	pthread_cond_t read_cond;
	pthread_mutex_t write_mutex;
	pthread_cond_t write_cond;
};

static int nwrite(int fd, void * buf, int len)
{
	int sent = 0;

	while (len) {
		int n;

		n = write(fd, buf, len);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (n == 0)
			break;
		len -= n;
		buf += n;
		sent += n;
	}

	if (len == 0)
		return sent;

	errno = EIO;
	return -1;
}

static void *write_func(void* d)
{
	long rc = 0;
	struct file_read_thread_data *data = (struct file_read_thread_data *)d;
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
//printf("	pthread_cond_wait(write) end\n");
		if (data->size == 0) {
			if (verbose)
				printf("write thread completed\n");
			break;
		}

//		write_bytes = nwrite(data->sock, data->buffer, data->size);
		write_bytes = write(data->sock, data->buffer, data->size);
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

int send_data(int fd, int sock, size_t size, size_t blksize)
{
	int rc = 0, ret;
	long retcode;
	struct command cmd;
	pthread_t write_th;

	off_t offset;
	ssize_t read_bytes = 0;
	void *buffer, *ptr;
	struct file_read_thread_data data;

	data.sock = sock;

	cmd.id = CMD_SIZE;
	cmd.data = size;
	ret = write(data.sock, (void *)&cmd, sizeof(cmd));
	if (ret < 0) {
		perror("write()");
		return -1;
	}

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
	read_bytes = pread(fd, buffer, blksize, 0);
	if (read_bytes < 0) {
		perror("pread()");
		rc = 1;
		goto cleanup_5;
	}

	offset = read_bytes;
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
		buffer = ptr;
		/* and wake up write task */
		pthread_cond_signal(&data.write_cond);
//printf("pthread_cond_signal(write)\n");
		pthread_mutex_unlock(&data.write_mutex);
//printf("write_mutex.unlock\n");
//if (!pthread_mutex_trylock(&data.write_mutex)) {
//printf("!!!!!!!!!!!!!!!!!!!!!!\n");
//pthread_mutex_unlock(&data.write_mutex);
//}

		read_bytes = pread(fd, buffer, blksize, offset);
		if (read_bytes < 0) {
			perror("pread()");
			rc = -1;
			break;
		}
		offset += read_bytes;
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
	int rc = 0;
	int c;
	char *hostname;
	char *fname;
	size_t blksize = 0x40000;
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


