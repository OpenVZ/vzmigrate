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
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/syslog.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <linux/types.h>
#include <stdarg.h>
#include <dirent.h>
#include <libgen.h>

//#include <vz/lzrw4.h>  // comment prlcompress usage

#include <ploop/ploop_if.h>
#include <ploop/ploop1_image.h>

#include "common.h"
#include "util.h"
#include "ploop.h"

static int verbose = 0;

static ssize_t snd_size = 0;
static ssize_t rcv_size = 0;
static struct ploop_online_copy_data *_g_online_copy_data;

#pragma pack(0)
#define PLOOPCOPY_START_MARKER 0x4cc0ac3c
#define PLOOPCOPY_DATA_MARKER 0x4cc0ac3d
// comment prlcompress usage
//#define PLOOPCOPY_COMPRESSED_DATA_MARKER 0x4cc0ac3e
struct ploopcopy_start_packet
{
	__u32   marker;
	__u32   mode;
};
struct ploopcopy_data_packet
{
	__u32   marker;
	__u32   size;
	__u64   pos;
};
#pragma pack()

static void wakeup(pthread_mutex_t *m, pthread_cond_t *c)
{
	pthread_mutex_lock(m);
	pthread_cond_signal(c);
	pthread_mutex_unlock(m);
}

void ploop_delta_desc_close(struct ploop_delta_desc *d)
{
	if (d->tracker_on) {
		ioctl(d->devfd, PLOOP_IOC_TRACK_STOP, 0);
		d->tracker_on = 0;
	}

	if (d->devfd != -1) {
		close(d->devfd);
		d->devfd = -1;
	}
	if (d->deltafd != -1) {
		close(d->deltafd);
		d->deltafd = -1;
	}

	free(d->format);
	d->format = NULL;
	free(d->dev);
	d->dev = NULL;
	free(d->mnt);
	d->mnt = NULL;
	free(d->delta);
	d->delta = NULL;
}

int ploop_delta_desc_open(const char *basedir, const char *delta,
		struct ploop_delta_desc *d)
{
	char dd_xml[PATH_MAX];
	char fname[PATH_MAX];
	char dev[BUFSIZ];
	char mnt[PATH_MAX];
	struct ploop_spec spec;
	struct ploop_disk_images_data *di;
	char *dir;

	get_full_path(basedir, delta, fname, sizeof(fname));

	dir = strdupa(fname);
	dirname(dir);

	snprintf(dd_xml, sizeof(dd_xml), "%s/"DISKDESCRIPTOR_XML, dir);
	if (ploop_open_dd(&di, dd_xml)) {
		print_log(LOG_ERR, "ploop_open_dd %s: %s",
				dd_xml, ploop_get_last_error());
		return -1;
	}
	if (ploop_get_dev(di, dev, sizeof(dev))) {
		print_log(LOG_ERR, "ploop_get_dev %s: %s",
				dd_xml, ploop_get_last_error());
		return -1;
	}


	if (ploop_get_spec(di, &spec)) {
		print_log(LOG_ERR, "ploop_get_spec %s: %s",
				dd_xml, ploop_get_last_error());
		return -1;
	}

	d->devfd = open(dev, O_RDONLY);
	if (d->devfd == -1) {
		print_log(LOG_ERR, "open(%s) : %m", d->dev);
		return -1;
	}

	if (ploop_get_mnt_by_dev(dev, mnt, sizeof(mnt)) == 0)
		d->mnt = strdup(mnt);

	d->deltafd = open(fname, O_RDONLY|O_DIRECT);
	if (d->devfd == -1) {
		close(d->devfd);
		print_log(LOG_ERR, "open(%s) : %m", fname);
		return -1;
	}

	d->delta = strdup(delta);
	d->dev = strdup(dev);
	d->tracker_on = 0;
	d->blksize = spec.blocksize ? spec.blocksize * 512 : 1024 * 1024;
	d->size = spec.size * 512;
	d->format = strdup("ploop1");


	print_log(LOG_DEBUG, "Open %s dev=%s mnt=%s size=%llu fmt=%s blksie=%llu",
		fname, d->dev, d->mnt ? d->mnt : "",  d->size, d->format, d->blksize);
	ploop_close_dd(di);

	return 0;
}

static ssize_t nwrite(int fd, int tmo, void *data, ssize_t size)
{
	int rc;
	ssize_t n, sent = 0;
	fd_set readfds, writefds;

	if (size == 0)
		return 0;
	while (1) {
		while (1) {
			n = write(fd, data + sent, size - sent);
			if (n > 0) {
				sent += n;
				if (sent >= size)
					return 0;
				continue;
			}
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN)
				break;
			print_log(LOG_ERR, "write() : %m");
			return -1;
		}

		/* wait when socket will ready to write */
		FD_ZERO(&readfds);
		FD_SET(fd, &readfds);
		FD_ZERO(&writefds);
		FD_SET(fd, &writefds);
		if (tmo) {
			struct timeval tv;
			tv.tv_sec = tmo;
			tv.tv_usec = 0;
			rc = select(fd + 1, &readfds, &writefds, NULL, &tv);
		} else {
			rc = select(fd + 1, &readfds, &writefds, NULL, NULL);
		}
		if (rc == 0) {
			print_log(LOG_ERR, "timeout (%d sec)", tmo);
			return -1;
		} else if (rc < 0) {
			print_log(LOG_ERR, "select() : %m");
			return -1;
		}
		if (FD_ISSET(fd, &readfds)) {
			/* reader will write to socket on failure only */
			print_log(LOG_ERR, "error on destination side");
			return -1;
		}
	}

	/* but we never should be here */
	print_log(LOG_ERR, "I/O error, size=%lu\n", size);
	return -1;
}

static ssize_t send_block(struct ploop_online_copy_data *data)
{
	struct ploopcopy_data_packet pkt;
	ssize_t n;
	void *buffer;

	if (data->compress_buffer != NULL) {
		// comment prlcompress usage
		//// compress data
	        ///* 4K buffer place in stack */
		//lzrw4_dic_t dic[LZRW4_DIC_LEN];
		//lzrw4_size_t bsize = (lzrw4_size_t)(data->blksize + LZRW4_MAX_OVERHEAD(data->blksize));
		//
		//int rc = lzrw4_compress_plain(
		//	data->write_buffer,
		//	data->size,
		//	data->compress_buffer,
		//	&bsize,
		//	dic);
		//
		//if (rc)
		//	return -1;
		//
		//pkt.marker = PLOOPCOPY_COMPRESSED_DATA_MARKER;
		//pkt.size = bsize;
		//buffer = data->compress_buffer;
		return -1;
	} else {
		pkt.marker = PLOOPCOPY_DATA_MARKER;
		pkt.size = data->size;
		buffer = data->write_buffer;
	}

	pkt.pos = data->pos;
	n = nwrite(data->sock, data->tmo, &pkt, sizeof(pkt));
	if (n < 0)
		return -1;
	n = nwrite(data->sock, data->tmo, buffer, pkt.size);
	if (n < 0)
		return -1;

	snd_size += pkt.size;
	return n;
}

static void *write_to_socket_func(void* d)
{
	long rc = 0;
	struct ploop_online_copy_data *data = (struct ploop_online_copy_data *)d;

	pthread_mutex_lock(&data->write_mutex);
	/* report to the reader that task is started */
	wakeup(&data->read_mutex, &data->read_cond);

	while (rc >= 0) {
		/* Wait till write_buffer is ready */
		rc = pthread_cond_wait(&data->write_cond, &data->write_mutex);
		/* report to reader that request is processed */
		wakeup(&data->read_mutex, &data->read_cond);
		if (rc) {
			print_log(LOG_ERR, "pthread_cond_wait() : %m");
			rc = -1;
			break;
		}

		if (data->size == 0) {
			print_log(LOG_DEBUG, "write thread completed");
			break;
		}

		if (send_block(data) < 0)
			rc = -1;
	}
	data->rc = rc;
	pthread_mutex_unlock(&data->write_mutex);
	pthread_exit((void *)rc);
}

static ssize_t read_block_from_image(
		int devfd, int fd, void *buffer, __u64 pos, ssize_t size, __u64 *trackpos)
{
	ssize_t rc;

	/* *trackpos is max pos of read data */
	if (trackpos && (pos + size > *trackpos)) {
		*trackpos = pos + size;
		if (ioctl(devfd, PLOOP_IOC_TRACK_SETPOS, trackpos)) {
			print_log(LOG_ERR, "ioctl(PLOOP_IOC_TRACK_SETPOS, %llu) : %m", *trackpos);
			return -1;
		}
	}
	rc = pread(fd, buffer, size, pos);
	if (rc == -1) {
		print_log(LOG_ERR, "read_block_from_image pos=%llu size=%llu: %m",
				pos, size);
		return -1;
	}
	return rc;
}

/* Phaul handle ploop online copying starting from Vz7, have to remove this
logic from vzmigrate or adapt to Vz7 for legacy scenarios if needed */
#if 0
static int do_iter(
		struct ploop_online_copy_data *data,
		struct ploop_delta_desc *d,
		__u64 pstart,
		__u64 pend,
		__u64 *trackpos)
{
	int rc = 0;
	__u64 pos;
	ssize_t nbytes;

	pthread_mutex_lock(&data->read_mutex);
	data->rc = 0;
	for (pos = pstart; pos < pend; ) {
		nbytes = read_block_from_image(d->devfd, d->deltafd,
				data->read_buffer, pos, d->blksize, trackpos);
		if (nbytes < 0) {
			rc = -1;
			break;
		}

		if (nbytes == 0)
			break;

		/* protect write_buffer */
		pthread_mutex_lock(&data->write_mutex);
		/* check result from writer */
		if (data->rc) {
			rc = data->rc;
			pthread_mutex_unlock(&data->write_mutex);
			break;
		}
		data->size = nbytes;
		data->pos = pos;
		memcpy(data->write_buffer, data->read_buffer, data->size);
		/* and wake up write task */
		pthread_cond_signal(&data->write_cond);
		pthread_mutex_unlock(&data->write_mutex);

		/* wait till writer started process request */
		pthread_cond_wait(&data->read_cond, &data->read_mutex);

		pos += nbytes;
	}
	pthread_mutex_unlock(&data->read_mutex);

	/* wait while last request is processed */
	pthread_mutex_lock(&data->write_mutex);
	pthread_mutex_unlock(&data->write_mutex);

	return rc;
}
#endif

static int ploop_data_init(int sock, int tmo, int lcompress,
		struct ploop_online_copy_data *data)
{
	int rc = 0;

	data->sock = sock;
	data->tmo = tmo;
	data->tracker_on = 0;
	data->compress_buffer = NULL;

	if (posix_memalign(&data->read_buffer, 4096, data->blksize)) {
		print_log(LOG_ERR, "posix_memalign() : %m");
		return -1;
	}
	if (posix_memalign(&data->write_buffer, 4096, data->blksize)) {
		print_log(LOG_ERR, "posix_memalign() : %m");
		rc = -1;
		goto cleanup_0;
	}
	if (lcompress) {
		// comment prlcompress usage
		//data->compress_buffer = malloc(data->blksize + LZRW4_MAX_OVERHEAD(data->blksize));
		//if (data->compress_buffer == NULL) {
		//	print_log(LOG_ERR, "malloc() : %m");
		//	rc = -1;
		//	goto cleanup_1;
		//}
		rc = -1;
		goto cleanup_1;
	}

	if (pthread_mutex_init(&data->read_mutex, NULL)) {
		print_log(LOG_ERR, "pthread_mutex_init() : %m");
		rc = -1;
		goto cleanup_1;
	}
	if (pthread_cond_init(&data->read_cond, NULL)) {
		print_log(LOG_ERR, "pthread_cond_init() : %m");
		rc = -1;
		goto cleanup_2;
	}
	if (pthread_mutex_init(&data->write_mutex, NULL)) {
		print_log(LOG_ERR, "pthread_mutex_init() : %m");
		rc = -1;
		goto cleanup_3;
	}
	if (pthread_cond_init(&data->write_cond, NULL)) {
		print_log(LOG_ERR, "pthread_cond_init() : %m");
		rc = -1;
		goto cleanup_4;
	}
	return 0;
cleanup_4:
	pthread_mutex_destroy(&data->write_mutex);
cleanup_3:
	pthread_cond_destroy(&data->read_cond);
cleanup_2:
	pthread_mutex_destroy(&data->read_mutex);
cleanup_1:
	free(data->write_buffer);
	data->write_buffer = NULL;
cleanup_0:
	free(data->read_buffer);
	data->read_buffer = NULL;
	if (data->compress_buffer != NULL) {
		free(data->compress_buffer);
		data->compress_buffer = NULL;
	}
	return rc;
}

static struct ploop_online_copy_data *get_online_copy_data()
{
	if (_g_online_copy_data == NULL)
		_g_online_copy_data = calloc(1, sizeof(struct ploop_online_copy_data));

	return _g_online_copy_data;
}

void ploop_data_close()
{
	struct ploop_online_copy_data *data = _g_online_copy_data;

	if (data) {
		if (data->write_buffer != NULL) {
			pthread_cond_destroy(&data->write_cond);
			pthread_mutex_destroy(&data->write_mutex);
			free(data->write_buffer);
		}
		if (data->read_buffer != NULL) {
			pthread_cond_destroy(&data->read_cond);
			pthread_mutex_destroy(&data->read_mutex);
			free(data->read_buffer);
		}
		if (data->compress_buffer != NULL)
			free(data->compress_buffer);

		free(_g_online_copy_data);
		_g_online_copy_data = NULL;
	}
}

int ploop_src_online_copy_image_1(int sock, int tmo, int lcompress,
		struct ploop_delta_desc *d)
{
/* Phaul handle ploop online copying starting from Vz7, have to remove this
logic from vzmigrate or adapt to Vz7 for legacy scenarios if needed */
#if 0
	int rc = 0;
	long retcode;
	pthread_t write_th;
	__u64 iterpos;
	__u64 trackend;
	__u64 xferred;
	int iter;
	struct ploop_track_extent e;
	struct ploopcopy_start_packet pkt;
	struct ploop_online_copy_data *data = get_online_copy_data();

	data->blksize = d->blksize;

	print_log(LOG_DEBUG, "Stage 1 %s", d->delta);

	rc = ploop_complete_running_operation(d->dev);
	if (rc) {
		print_log(LOG_ERR, "ploop_complete_running_operation(%s) : %s [%d]",
				d->dev, ploop_get_last_error(), rc);
		return -1;
	}

	rc = ploop_data_init(sock, tmo, lcompress, data);
	if (rc)
		return -1;

	if (ioctl(d->devfd, PLOOP_IOC_TRACK_INIT, &e)) {
		print_log(LOG_ERR, "ioctl(PLOOP_IOC_TRACK_INIT) : %m");
		rc = -1;
		goto cleanup_0;
	}

	d->tracker_on = 1;
	trackend = e.end;

	/* send start command */
	pkt.marker = PLOOPCOPY_START_MARKER;
	/* TODO: */
	pkt.mode = 0644;

	if (nwrite(data->sock, data->tmo, &pkt, sizeof(pkt)) < 0) {
		print_log(LOG_ERR, "can not send start command");
		rc = -1;
		goto cleanup_0;
	}

	/* start send thread */
	pthread_mutex_lock(&data->read_mutex);
	if (pthread_create(&write_th, NULL, write_to_socket_func, (void*)data) < 0) {
		print_log(LOG_ERR, "phtread_create() : %m");
		rc = -1;
		goto cleanup_0;
	}

	/* wait for write_to_socket_func start */
	pthread_cond_wait(&data->read_cond, &data->read_mutex);
	pthread_mutex_unlock(&data->read_mutex);

	/* first iteration */
	d->trackpos = 0;
	rc = do_iter(data, d, 0, trackend, &d->trackpos);
	if (rc)
		goto cleanup_1;

	iter = 1;
	iterpos = 0;
	xferred = 0;

	for (;;) {
		if (ioctl(d->devfd, PLOOP_IOC_TRACK_READ, &e)) {
			if (errno == EAGAIN)
				/* success : no more dirty blocks */
				break;
			print_log(LOG_ERR, "ioctl(PLOOP_IOC_TRACK_READ) : %m");
			rc = -1;
			goto cleanup_1;
		}
		if (verbose)
			print_log(LOG_DEBUG, "TRACK %Lu-%Lu", e.start, e.end);

		if (e.end > trackend)
			trackend = e.end;

		if (e.start < iterpos) {
			iter++;
			print_log(LOG_DEBUG, "iteration %d started", iter);
		}
		iterpos = e.end;
		xferred += e.end - e.start;
		rc = do_iter(data, d, e.start, e.end, &d->trackpos);
		if (rc)
			goto cleanup_1;

		if (iter > 10 || (iter > 1 && xferred > trackend)) {
			print_log(LOG_DEBUG,
					"iteration %d cancelled: prev iter data:"
					" %llu, current: %llu",
					iter, xferred, trackend);
			break;
		}
	}

	if (verbose)
		print_log(LOG_DEBUG, "Tracked iterations=%lu transfered=%llu",
				iter, xferred);

	/* Live iterative transfers are done. Either we transferred
	 * everything or iterations did not converge. In any case
	 * now we must suspend VE disk activity.
	*/

	/* check that write thread already completed data transmition */
	pthread_mutex_lock(&data->write_mutex);
	pthread_mutex_unlock(&data->write_mutex);

	// send EOF to stop recieve thread on destination side
	data->size = 0;
	data->pos = 0;
	send_block(data);

	print_log(LOG_DEBUG, "Stage 1 done");
cleanup_1:
	// to stop write task
	pthread_mutex_lock(&data->write_mutex);
	data->size = 0;
	pthread_cond_signal(&data->write_cond);
	pthread_mutex_unlock(&data->write_mutex);
	pthread_join(write_th, (void **)&retcode);
	if (verbose)
		print_log(LOG_DEBUG, "write thread stopped, retcode = %ld", retcode);

cleanup_0:
	if (rc)
		ploop_data_close();

	return rc;
#endif
	return -1;
}

int ploop_src_online_copy_image_2(struct ploop_delta_desc *d)
{
/* Phaul handle ploop online copying starting from Vz7, have to remove this
logic from vzmigrate or adapt to Vz7 for legacy scenarios if needed */
#if 0
	int rc = 0;
	long retcode;
	ssize_t n;
	pthread_t write_th;
	int iter = 1;
	__u64 iterpos;
	struct ploop_track_extent e;
	struct ploop_online_copy_data *data = get_online_copy_data();

	data->blksize = d->blksize;

	print_log(LOG_INFO, "Stage 2 %s", d->delta);
	pthread_mutex_lock(&data->read_mutex);
	/* start send thread */
	if (pthread_create(&write_th, NULL, write_to_socket_func, (void*)data) < 0) {
		print_log(LOG_ERR, "phtread_create() : %m");
		rc = -1;
		goto cleanup_0;
	}
	/* wait for write_to_socket_func start */
	pthread_cond_wait(&data->read_cond, &data->read_mutex);
	pthread_mutex_unlock(&data->read_mutex);

	if (ioctl(d->devfd, PLOOP_IOC_SYNC, 0)) {
		print_log(LOG_ERR, "ioctl(PLOOP_IOC_SYNC) : %m");
		rc = -1;
		goto cleanup_1;
	}

	iterpos = 0;
	for (;;) {
		if (ioctl(d->devfd, PLOOP_IOC_TRACK_READ, &e)) {
			if (errno == EAGAIN)
				// no more dirty blocks
				break;
			print_log(LOG_ERR, "ioctl(PLOOP_IOC_TRACK_READ) : %m");
			rc = -1;
			goto cleanup_1;
		}
		if (verbose)
			print_log(LOG_INFO, "TRACK %Lu-%Lu", e.start, e.end);

		if (e.start < iterpos)
			iter++;
		iterpos = e.end;

		// to allow 2 ieration after suspend (https://jira.sw.ru/browse/PSBM-12225)
		if (iter > 2) {
			print_log(LOG_ERR, "Too many iterations on frozen FS, aborting");
			print_log(LOG_ERR, "e.start = %llu, e.end = %llu, iterpos = %llu",
					e.start, e.end, iterpos);
			rc = -1;
			goto cleanup_1;
		}

		rc = do_iter(data, d, e.start, e.end, &d->trackpos);
		if (rc)
			goto cleanup_1;
        }

	/* check that write thread already completed data transmition */
	pthread_mutex_lock(&data->write_mutex);
	pthread_mutex_unlock(&data->write_mutex);

	/* To send first block - must clear dirty flag on ploop1 image. */
	if (strcmp(d->format, "ploop1") == 0) {
		n = pread(d->deltafd, data->write_buffer, 4096, 0);
		if (n != 4096) {
			if (n < 0)
				print_log(LOG_ERR, "read header");
			else
				print_log(LOG_ERR, "short read header");
			rc = -1;
			goto cleanup_1;
		}
		struct ploop_pvd_header *vh = (struct ploop_pvd_header *)data->write_buffer;
		vh->m_DiskInUse = 0;
		data->size = n;
		data->pos = 0;
		if (send_block(data) < 0) {
			rc = -1;
			goto cleanup_1;
		}
	}

	// send EOF to stop recieve thread on destination side
	data->size = 0;
	data->pos = 0;
	send_block(data);

	print_log(LOG_DEBUG, "Stage 2 done");

	if (verbose)
		print_log(LOG_DEBUG, "total write %lu", snd_size);
cleanup_1:
	// to stop write task
	pthread_mutex_lock(&data->write_mutex);
	data->size = 0;
	pthread_cond_signal(&data->write_cond);
	pthread_mutex_unlock(&data->write_mutex);
	pthread_join(write_th, (void **)&retcode);
	if (verbose)
		print_log(LOG_DEBUG, "write thread stopped, retcode = %ld", retcode);

cleanup_0:
	if (rc)
		ploop_data_close(data);
	return rc;
#endif
	return -1;
}

/*
  Target-side part
*/
static ssize_t nread(int fd, int tmo, void *data, ssize_t size)
{
	ssize_t rc = 0;
	fd_set fds;
	ssize_t recv = 0;

	while (1) {
		while (1) {
			errno = 0;
			rc = read(fd, data, size);
			if (rc < 0) {
				if (errno == EINTR)
					continue;
				if (errno == EAGAIN)
					/* wait next data */
					break;
				print_log(LOG_ERR, "read() : %m");
				return -1;
			} else if (rc == 0) {
				/* end of file */
				print_log(LOG_ERR, "read() : EOF");
				return -1;
			}
			size -= rc;
			data += rc;
			recv += rc;
			if (size <= 0)
				return recv;
		}

		/* wait when socket will ready to read */
		FD_ZERO(&fds);
		FD_SET(fd, &fds);
		if (tmo) {
			struct timeval tv;
			tv.tv_sec = tmo;
			tv.tv_usec = 0;
			rc = select(fd + 1, &fds, NULL, NULL, &tv);
		} else {
			rc = select(fd + 1, &fds, NULL, NULL, NULL);
		}
		if (rc == 0) {
			print_log(LOG_ERR, "timeout (%d sec)", tmo);
			return -1;
		} else if (rc < 0) {
			print_log(LOG_ERR, "select() : %m");
			return -1;
		}
	}

	return -1;
}

static void *write_to_image_func(void* d)
{
	long rc = 0;
	ssize_t write_bytes;
	struct ploop_online_copy_data *data = (struct ploop_online_copy_data *)d;

	pthread_mutex_lock(&data->write_mutex);

	/* report to the read thread that task is started */
	wakeup(&data->read_mutex, &data->read_cond);

	while (1) {
		/* wait for data */
		rc = pthread_cond_wait(&data->write_cond, &data->write_mutex);
		wakeup(&data->read_mutex, &data->read_cond);
		if (rc) {
			print_log(LOG_ERR, "pthread_cond_wait() failed [%d]", rc);
			rc = -1;
			break;
		}

		if (data->size == 0) {
			if (verbose)
				print_log(LOG_DEBUG, "write thread completed");
			break;
		}

		write_bytes = pwrite(data->fd, data->write_buffer, data->size, data->pos);
		if (write_bytes != data->size) {
			print_log(LOG_ERR, "pwrite() : %m");
			rc = -1;
			break;
		}
		if (verbose)
			printf("write %ld data\n", write_bytes);

	}
	data->rc = rc;
	pthread_mutex_unlock(&data->write_mutex);
	pthread_exit((void *)rc);
}

static ssize_t read_block_from_sock(struct ploop_online_copy_data *data, off_t *pos)
{
	ssize_t bsize, size;
	struct ploopcopy_data_packet pkt;
	void *buffer;

	size = nread(data->sock, data->tmo, &pkt, sizeof(struct ploopcopy_data_packet));
	if (size < 0) {
		return size;
	} else if (size != sizeof(struct ploopcopy_data_packet)) {
		print_log(LOG_ERR, "stream corrupted, invalid control block size");
		return -1;
	}
	if (pkt.marker == PLOOPCOPY_DATA_MARKER) {
		buffer = data->read_buffer;
		bsize = data->blksize;
	// comment prlcompress usage
	//} else if (pkt.marker == PLOOPCOPY_COMPRESSED_DATA_MARKER) {
	//	buffer = data->compress_buffer;
	//	bsize = data->blksize + LZRW4_MAX_OVERHEAD(data->blksize);
	} else {
		print_log(LOG_ERR, "stream corrupted, bad marker");
		return -1;
	}
	if (pkt.size > bsize) {
		print_log(LOG_ERR,
			"stream corrupted, too long chunk. size = %d, maxsize = %d",
			pkt.size, bsize);
		return -1;
	}
	if (pkt.size == 0) {
		return 0;
	}
	*pos = pkt.pos;

	size = nread(data->sock, data->tmo, buffer, pkt.size);
	if (size < 0)
		return size;

	// comment prlcompress usage
	//if (pkt.marker == PLOOPCOPY_COMPRESSED_DATA_MARKER) {
	//	/* decompress data */
	//	int rc;
	//	lzrw4_size_t usize = (lzrw4_size_t)data->blksize;
	//
	//	rc = lzrw4_decompress_plain(data->compress_buffer, size, data->read_buffer, &usize);
	//	if (rc) {
	//		print_log(LOG_ERR, "lzrw4_decompress_plain() return %d", rc);
	//		return -1;
	//	}
	//	size = usize;
	//}
	rcv_size += size;

	return size;
}

static int ploop_dst_online_copy_image(struct ploop_online_copy_data *data)
{
	int rc = 0;
	long retcode;
	pthread_t write_th;
	int ret;
	ssize_t nbytes = 0;
	off_t pos = 0;

	pthread_mutex_lock(&data->read_mutex);

	if ((ret = pthread_create(&write_th, NULL, write_to_image_func, (void*)data))) {
		pthread_mutex_unlock(&data->read_mutex);
		print_log(LOG_ERR, "phtread_create() : [%d]", ret);
		return -1;
	}

	/* wait for write_to_image_func start */
	pthread_cond_wait(&data->read_cond, &data->read_mutex);
	do {
		nbytes = read_block_from_sock(data, &pos);
		if (nbytes < 0) {
			rc = -1;
			break;
		}

		/* protect write_buffer */
		pthread_mutex_lock(&data->write_mutex);
		if (data->rc) {
			rc = data->rc;
			pthread_mutex_unlock(&data->write_mutex);
			break;
		}
		data->size = nbytes;
		data->pos = pos;
		memcpy(data->write_buffer, data->read_buffer, data->size);
		pthread_cond_signal(&data->write_cond);
		pthread_mutex_unlock(&data->write_mutex);

		/* wait till writer started process the request */
		pthread_cond_wait(&data->read_cond, &data->read_mutex);
	} while (nbytes > 0);

	pthread_mutex_unlock(&data->read_mutex);

	if (verbose)
		print_log(LOG_DEBUG, "total read%lu", rcv_size);

	// to stop write task
	pthread_mutex_lock(&data->write_mutex);
	data->size = 0;
	pthread_cond_signal(&data->write_cond);
	pthread_mutex_unlock(&data->write_mutex);

	pthread_join(write_th, (void **)&retcode);
	if (verbose)
		print_log(LOG_DEBUG, "retcode = %ld", retcode);
	if (rc)
		// write anything to socket on failure as 'error signal' for source side
		nwrite(data->sock, data->tmo, "", 0);

	return rc;
}

int ploop_dst_online_copy_image_1(const char *image, int sock, int tmo, size_t blksize)
{
	int rc = 0;
	ssize_t n;
	struct ploopcopy_start_packet pkt;
	struct ploop_online_copy_data *data = get_online_copy_data();

	data->blksize = blksize;

	rc = ploop_data_init(sock, tmo, 1, data);
	if (rc)
		return rc;

	n = nread(data->sock, data->tmo, (void *)&pkt, sizeof(pkt));
	if (n < 0) {
		rc = -1;
		goto cleanup_0;
	} else if (n != sizeof(pkt)) {
		print_log(LOG_ERR, "stream corrupted, invalid start block size");
		rc = -1;
		goto cleanup_0;
	}
	if (pkt.marker != PLOOPCOPY_START_MARKER) {
		print_log(LOG_ERR, "stream corrupted, bad marker. PLOOPCOPY_START_MARKER waited");
		rc = -1;
		goto cleanup_0;
	}

	data->fd = open(image, O_WRONLY|O_CREAT|O_TRUNC, pkt.mode);
	if (data->fd == -1) {
		print_log(LOG_ERR, "open(%s) : %m", image);
		rc = -1;
		goto cleanup_0;
	}

	rc = ploop_dst_online_copy_image(data);
	if (rc) {
		rc = -1;
		goto cleanup_1;
	}

	// sync now when container is running to make sync on 2 stage fast
	// see #PSBM-26514
	fsync(data->fd);

	return 0;
cleanup_1:
	close(data->fd);
	data->fd = -1;
cleanup_0:

	return rc;
}

int ploop_dst_online_copy_image_2(const char *image, size_t blksize)
{
	int rc = 0;
	struct ploop_online_copy_data *data = get_online_copy_data();

	if (blksize != 0)
		data->blksize = blksize;

	if (image != NULL) {
		if (data->fd != -1)
			close(data->fd);
		data->fd = open(image, O_WRONLY);
		if (data->fd == -1) {
			print_log(LOG_ERR, "<dst_online_copy_image_2> failed to open %s: %m",
				image);
			return -1;
		}
	}

	rc = ploop_dst_online_copy_image(data);

	if (close(data->fd))
		print_log(LOG_ERR, "failde to close %s", image);
	data->fd = -1;

	return rc;
}
