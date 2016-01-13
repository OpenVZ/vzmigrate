/* $Id: migratesrc.h 708591 2011-11-02 10:41:03Z krasnov $
 *
 * Copyright (c) Parallels, 2011
 *
 */
#ifndef __PLOOP__H
#define __PLOOP__H

#include <ploop/libploop.h>

struct ploop_delta_desc {
	int devfd;
	int deltafd;
	size_t blksize;
	ssize_t size;
	int tracker_on;
	char *format;
	char *dev;
	char *mnt;
	char *delta;
	__u64 trackpos;
};

struct ploop_online_copy_data {
	int sock;
	int tracker_on;
	int fd;
	int tmo;
	void *read_buffer;
	void *write_buffer;
	void *compress_buffer;
	ssize_t size; // write_buffer size
	off_t pos; // write_buffer pos
	size_t blksize;
	int rc;
	pthread_mutex_t read_mutex;
	pthread_cond_t read_cond;
	pthread_mutex_t write_mutex;
	pthread_cond_t write_cond;
};

#ifdef __cplusplus
extern "C" {
#endif

int ploop_delta_desc_open(const char *basedir, const char *delta,
		struct ploop_delta_desc *d);
void ploop_delta_desc_close(struct ploop_delta_desc *d);
int ploop_src_online_copy_image_1(int sock, int tmo,int lcompress,
		struct ploop_delta_desc *desc);
int ploop_src_online_copy_image_2(struct ploop_delta_desc *desc);
int ploop_dst_online_copy_image_1(const char *image, int sock, int tmo, size_t blksize);
int ploop_dst_online_copy_image_2(const char *image, size_t blksize);
void ploop_data_close();


#ifdef __cplusplus
}
#endif

#endif
