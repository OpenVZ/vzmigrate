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
#include <sys/ioctl.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <getopt.h>
#include <pthread.h>
#include <mntent.h>
#include <linux/types.h>
#include <linux/limits.h>

#include <vz/vzctl.h>
#include <vz/config.h>
#include <vz/vzerror.h>

#include <ploop/ploop_if.h>
#include <ploop/ploop1_image.h>

#include "sendfile.h"
#include "ploop.h"

static int verbose = 0;

void show_usage(const char *name)
{
	fprintf(stderr, "Usage: %s [options] hostname veid\n", name);
	fprintf(stderr, "\t-h, --help\n");
	fprintf(stderr, "\t-v, --verbose\n");
	fprintf(stderr, "\t-p, --port N        set port number\n");
	fprintf(stderr, "\t-b, --blocksize N   set data block size\n");
}

struct snd_data {
	int sock;
	void *read_buffer;
	void *write_buffer;
	size_t size; // write_buffer size
	__u64   pos; // write_buffer pos
	pthread_mutex_t read_mutex;
	pthread_cond_t read_cond;
	pthread_mutex_t write_mutex;
	pthread_cond_t write_cond;
};

/* from vzmigrate/bin/util.c */
int get_ve_root(unsigned veid, char *root, size_t size)
{
	int rc = 0;
	char path[PATH_MAX + 1];
	vzctl_config_t * cfg;

	vzctl_get_env_conf_path(veid, path, sizeof(path));
	if ((cfg = vzctl_conf_open(path,
			VZCTL_CONF_SKIP_GLOBAL|VZCTL_CONF_BASE_SET)) == NULL) {
		fprintf(stderr, "vzctl_conf_open(%s) error: %s",
				path, vzctl_get_last_error());
		return -1;
	}

	if (vzctl_conf_parse(veid, cfg)) {
		vzctl_conf_close(cfg);
		fprintf(stderr, "vzctl_conf_parse() error: %s", vzctl_get_last_error());
		return -1;
	}
	if (cfg->env_data->fs->ve_root == NULL) {
		rc = -1;
		fprintf(stderr, "can't read VE_ROOT from CT#%u config", veid);
	} else {
		strncpy(root, cfg->env_data->fs->ve_root, size);
	}
	vzctl_conf_close(cfg);
	return rc;
}

/* from ploop-tools/ploop-copy.c */
static int get_image_info(char *device, char *image, size_t image_size, char *format, size_t format_size)
{
	char *pdev;
	FILE * fp;
	int len;
	char path[PATH_MAX+1];
	char buffer[BUFSIZ];

	if (memcmp(device, "/dev/", 5) == 0)
		pdev = device + 5;
	else
		pdev = device;

	snprintf(path, sizeof(path)-1, "/sys/block/%s/pdelta/0/image", pdev);
	fp = fopen(path, "r");
	if (fp == NULL) {
		fprintf(stderr, "fopen(%s) : %m\n", path);
		return -1;
	}
	if (fgets(buffer, sizeof(buffer), fp) == NULL) {
		perror("fgets()");
		fclose(fp);
		return -1;
	}
	fclose(fp);
	len = strlen(buffer);
	if (len > 0 && buffer[len-1] == '\n')
		buffer[len-1] = 0;
	strncpy(image, buffer, image_size);

	snprintf(path, sizeof(path)-1, "/sys/block/%s/pdelta/0/format", pdev);
	fp = fopen(path, "r");
	if (fp == NULL) {
		fprintf(stderr, "fopen(%s) : %m\n", path);
		return -1;
	}
	if (fgets(buffer, sizeof(buffer), fp) == NULL) {
		perror("fgets()");
		fclose(fp);
		return -1;
	}
	fclose(fp);
	len = strlen(buffer);
	if (len > 0 && buffer[len-1] == '\n')
		buffer[len-1] = 0;
	strncpy(format, buffer, format_size);

	return 0;
}


/* from ploop-tools/libploop.c */
static int fname_cmp(char *p1, char *p2)
{
	struct stat st1, st2;

	if (stat(p1, &st1) || stat(p2, &st2))
		return -1;

	if (st1.st_dev == st2.st_dev &&
	    st1.st_ino == st2.st_ino)
		return 0;
	return 1;
}

int ploop_get_dev_by_mnt(char *path, char *buf, int size)
{
	FILE *fp;
	struct mntent *ent;

	fp = fopen("/proc/mounts", "r");
	if (fp == NULL) {
		perror("fopen(/proc/mounts)");
		return -1;
	}
	while ((ent = getmntent(fp))) {
		if (strncmp(ent->mnt_fsname, "/dev/ploop", 10) != 0)
			continue;
		if (fname_cmp(path, ent->mnt_dir) == 0 ) {
			snprintf(buf, size, "%s", ent->mnt_fsname);
			fclose(fp);
			return 0;
		}
	}
	fclose(fp);
	return 1;
}

static int nwrite(int fd, void * buf, int len)
{
	int sent = 0;

	while (len) {
		int n;

		n = write(fd, buf, len);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			perror("write()");
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

	fprintf(stderr, "I/O error, len=%d\n", len);
	return -1;
}

static int send_block(struct snd_data *data)
{
	struct xfer_desc desc;
	int n;

	desc.marker = PLOOPCOPY_MARKER;
	desc.size = data->size;
	desc.pos = data->pos;
	n = nwrite(data->sock, (void  *)&desc, sizeof(desc));
	if (n < 0)
		return -1;
	n = nwrite(data->sock, data->write_buffer, data->size);
	if (n < 0)
		return -1;
	return n;
}

static void *write_func(void* d)
{
	long rc = 0;
	struct snd_data *data = (struct snd_data *)d;

	pthread_mutex_lock(&data->write_mutex);
	while (1) {
		/*
		   - unlock full buffer
		   - wait till main thread read data, put it into buffer and wake up this thread
		   - lock and write full buffer
		*/
		if (pthread_cond_wait(&data->write_cond, &data->write_mutex)) {
			perror("pthread_cond_wait()");
			rc = -1;
			break;
		}
		if (data->size == 0) {
			if (verbose)
				printf("write thread completed\n");
			break;
		}

		rc = send_block(data);
		if (rc < 0)
			break;
		if (verbose)
			printf("write %ld data\n", rc);

		/* wait till write thread send buffer */
		pthread_mutex_lock(&data->read_mutex);
		/* and wake up write task */
		pthread_cond_signal(&data->read_cond);
		pthread_mutex_unlock(&data->read_mutex);
	}
	pthread_mutex_unlock(&data->write_mutex);
	pthread_exit((void *)rc);
}

static ssize_t read_block(int devfd, int fd, void *buffer, __u64 pos, size_t size, __u64 *trackpos)
{
	ssize_t rc;

	/* *trackpos is max pos of read data */
	if (trackpos && (pos + size > *trackpos)) {
		*trackpos = pos + size;
		if (ioctl(devfd, PLOOP_IOC_TRACK_SETPOS, &trackpos)) {
			fprintf(stderr, "ioctl(PLOOP_IOC_TRACK_INIT)");
			return -1;
		}
	}
	rc = pread(fd, buffer, size, pos);
	if (rc == -1) {
		perror("pread");
		return -1;
	}
	return rc;
}

static int do_iter(
		int devfd,
		int fd,
		pthread_t write_th,
		struct snd_data *data,
		size_t blksize,
		__u64 pstart,
		__u64 pend,
		__u64 *trackpos)
{
	int rc;
	__u64 pos;
	char *ptr;
	ssize_t nbytes;
	size_t size;

	/* check that write task is ready */
	pthread_mutex_lock(&data->write_mutex);
	pthread_mutex_unlock(&data->write_mutex);

	pthread_mutex_lock(&data->read_mutex);
	nbytes = read_block(devfd, fd, data->read_buffer, pstart, blksize, trackpos);
	if (nbytes < 0)
		return -1;
	for (pos = pstart; pos < pend; ) {
		if (pthread_kill(write_th, 0)) {
			perror("pthread_kill()");
			break;
		}

		/* wait till write thread send buffer */
		pthread_mutex_lock(&data->write_mutex);
		/* swap input and output buffers */
		ptr = data->write_buffer;
		data->write_buffer = data->read_buffer;
		data->read_buffer = ptr;
		data->size = nbytes;
		data->pos = pos;
		pos += nbytes;
		/* and wake up write task */
		pthread_cond_signal(&data->write_cond);
		pthread_mutex_unlock(&data->write_mutex);

		size = pend - pos;
		if (size > blksize)
			size = blksize;

		nbytes = read_block(devfd, fd, data->read_buffer, pos, size, trackpos);
		if (nbytes < 0) {
			rc = -1;
			break;
		}
		if (verbose)
			printf("read %ld data, total %llu\n", nbytes, pos + nbytes);

		// now wait till write task frees its buffer
		if (pthread_cond_wait(&data->read_cond, &data->read_mutex)) {
			perror("pthread_cond_wait()");
			rc = -1;
			break;
		}
		if (nbytes == 0)
			break;
	}
	pthread_mutex_unlock(&data->read_mutex);
	return rc;
}

int copy_image(unsigned veid, int sock, size_t blksize)
{
	int rc = 0;
	long retcode;
	pthread_t write_th;

	char ve_root[PATH_MAX+1];
	char image[PATH_MAX+1];
	char format[PATH_MAX+1];

	vzctl_env_status_t ve_status;
	char device[PATH_MAX+1];

	struct snd_data data;

	int devfd = -1;
	int fd = -1;

	__u64 iterpos;
	__u64 trackpos;
	__u64 trackend;
	__u64 transmitted;
	__u64 xferred;
	int iter;
	struct ploop_track_extent e;

	data.sock = sock;

	rc = get_ve_root(veid, ve_root, sizeof(ve_root));
	if (rc)
		exit(1);

	rc = vzctl_get_env_status(veid, &ve_status, ENV_STATUS_ALL);
	if (rc) {
		fprintf(stderr, "vzctl_get_env_status(%u) : %s", veid, vzctl_get_last_error());
		exit(1);
	}
	if (!(ve_status.mask & ENV_STATUS_RUNNING) && !(ve_status.mask & ENV_STATUS_MOUNTED)) {
		fprintf(stderr, "CT %u is not running or mounted", veid);
		exit(1);
	}

	rc = ploop_get_dev_by_mnt(ve_root, device, sizeof(device));
	if (rc)
		exit(1);

	rc = get_image_info(device, image, sizeof(image), format, sizeof(format));
	if (rc)
		exit(1);


	if (posix_memalign(&data.read_buffer, 4096, blksize)) {
                perror("posix_memalign()");
		return -1;
	}
	if (posix_memalign(&data.write_buffer, 4096, blksize)) {
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

	devfd = open(device, O_RDONLY);
	if (devfd == -1) {
		fprintf(stderr, "open(%s): %m\n", device);
		rc = -1;
		goto cleanup_5;
	}

	if (ioctl(devfd, PLOOP_IOC_TRACK_INIT, &e)) {
		perror("ioctl(PLOOP_IOC_TRACK_INIT)");
		rc = -1;
		goto cleanup_6;
	}
// FIXME:tracker_on = 1;
	trackend = e.end;

	fd = open(image, O_RDONLY|O_DIRECT);
	if (fd == -1) {
		fprintf(stderr, "open(%s)", image);
		rc = -1;
		goto cleanup_7;
	}

	/* start send thread */
	if (pthread_create(&write_th, NULL, write_func, (void*)&data) < 0) {
		perror("phtread_create()");
		rc = -1;
		goto cleanup_8;
	}

	/* first iteration : skip first block */
	trackpos = 0;
	rc = do_iter(devfd, fd, write_th, &data, blksize, 0, trackend, &trackpos);
	if (rc)
		goto cleanup_9;
	transmitted = trackpos;

	iter = 1;
	iterpos = 0;
	xferred = 0;

	for (;;) {
		if (ioctl(devfd, PLOOP_IOC_TRACK_READ, &e)) {
			if (errno == EAGAIN)
				/* success : no more dirty blocks */
				break;
			perror("ioctl(PLOOP_IOC_TRACK_READ)");
			rc = -1;
			goto cleanup_9;
		}
		if (verbose) {
			fprintf(stdout, "TRACK %Lu-%Lu\n", e.start, e.end);
			fflush(stdout);
		}

		if (e.end > trackend)
			trackend = e.end;

		if (e.start < iterpos) {
			/* new iteration started */
			transmitted = xferred;
			xferred = 0;
			iter++;
			if (verbose) {
				fprintf(stdout, "iteration %d started\n", iter);
				fflush(stdout);
			}
		}
		iterpos = e.end;
		xferred += e.end - e.start;
		rc = do_iter(devfd, fd, write_th, &data, blksize, e.start, e.end, &trackpos);
		if (rc)
			goto cleanup_9;

		if (iter > 10 || (transmitted/2 < xferred)) {
			if (verbose) {
				fprintf(stdout,
					"iteration %d cancelled: prev iter data: %llu, current: %llu\n",
					iter, transmitted, xferred);
				fflush(stdout);
			}
			break;
		}
        }

	/* Live iterative transfers are done. Either we transferred
	 * everything or iterations did not converge. In any case
	 * now we must suspend VE disk activity. Now it is just
	 * call of an external program (something sort of
	 * "killall -9 writetest; sleep 1; umount /mnt2"), actual
	 * implementation must be intergrated to vzctl/vzmigrate
	 * and suspend VE with subsequent fsyncing FS.
	*/

	/* migrate memory and suspend CT */

	if (ioctl(devfd, PLOOP_IOC_SYNC, 0)) {
		perror("ioctl(PLOOP_IOC_SYNC)");
		rc = -1;
		goto cleanup_9;
	}

	iterpos = 0;
	for (;;) {
		if (ioctl(devfd, PLOOP_IOC_TRACK_READ, &e)) {
			if (errno == EAGAIN)
				// no more dirty blocks
				break;
			perror("ioctl(PLOOP_IOC_TRACK_READ)");
			rc = -1;
			goto cleanup_9;
		}
		if (verbose) {
			fprintf(stdout, "TRACK %Lu-%Lu\n", e.start, e.end);
			fflush(stdout);
		}
		if (e.start < iterpos) {
			fprintf(stderr, "Too many iterations on frozen FS, aborting\n");
			rc = -1;
			goto cleanup_9;
		}
		iterpos = e.end;

		rc = do_iter(devfd, fd, write_th, &data, blksize, e.start, e.end, NULL);
		if (rc)
			goto cleanup_9;
        }

	/* check that write thread already completed data transmition */
	pthread_mutex_lock(&data.write_mutex);
	pthread_mutex_unlock(&data.write_mutex);

	/* To send first block - must clear dirty flag on ploop1 image. */
	rc = pread(fd, data.write_buffer, blksize, 0);
	if (rc != blksize) {
		if (rc < 0)
			perror("read header");
		else
			fprintf(stderr, "short read header\n");
		goto cleanup_9;
	}

	if (strcmp(format, "ploop1") == 0) {
		struct ploop_pvd_header *vh = (struct ploop_pvd_header *)data.write_buffer;
		vh->m_DiskInUse = 0;
	}
	data.size = rc;
	data.pos = 0;
	rc = send_block(&data);
	if (rc == -1)
		goto cleanup_9;

	// send EOF
	data.size = 0;
	data.pos = 0;
	send_block(&data);

cleanup_9:
	// to stop write task
	pthread_mutex_lock(&data.write_mutex);
	data.size = 0;
	pthread_cond_signal(&data.write_cond);
	pthread_mutex_unlock(&data.write_mutex);
	pthread_join(write_th, (void **)&retcode);
	if (verbose)
		printf("write thread stopped, retcode = %ld\n", retcode);

cleanup_8:
	close(fd);
cleanup_7:
	if (ioctl(devfd, PLOOP_IOC_TRACK_STOP, 0))
		perror("ioctl(PLOOP_IOC_TRACK_STOP)");
//	tracker_on = 0;
cleanup_6:
	close(devfd);
cleanup_5:
	pthread_cond_destroy(&data.write_cond);
cleanup_4:
	pthread_mutex_destroy(&data.write_mutex);
cleanup_3:
	pthread_cond_destroy(&data.read_cond);
cleanup_2:
	pthread_mutex_destroy(&data.read_mutex);
cleanup_1:
	free(data.write_buffer);
cleanup_0:
	free(data.read_buffer);
	return rc;
}

int main(int argc, char **argv, char **envp)
{
	int rc = 0;
	int c;
	char *hostname;
	unsigned veid;

	size_t blksize = CLUSTER;
	char *p;

	unsigned long addr;
	struct sockaddr_in saddr;
	unsigned short port = SENDFILE_TEST_PORT;

	int sock;

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
	veid = strtoul(argv[optind+1], &p, 10);
	if (*p != '\0') {
		fprintf(stderr, "Invalid VEID : %s\n", argv[optind+1]);
		exit(1);
	}

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

	rc = copy_image(veid, sock, blksize);

	close(sock);

	return rc;
}


