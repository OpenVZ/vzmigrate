/* $Id: $
 *
 * Copyright (c) 2011-2016 Parallels IP Holdings GmbH
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
