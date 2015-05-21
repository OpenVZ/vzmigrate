/*
 *
 * Copyright (c) Parallels, 2008
 *
 */
#ifndef __VZACOMPAT_H_
#define __VZACOMPAT_H_

int vza_init_cli(struct vzsock_ctx *ctx, void **conn);
int vza_start_swap_cli(
		struct vzsock_ctx *ctx,
		void *conn,
		const char *dst_ctid,
		int *sock,
		void **swapch);
int vza_send_data(
		struct vzsock_ctx *ctx,
		void *conn,
		const char * cmd,
		char * const *argv);
int vza_init_srv(
		struct vzsock_ctx *ctx,
		void **conn);
/* for vzagent mode: chdir to dst, connect to src SVE/node via ssh,
   run tar as server and unpack all from ssh stdout */
int vza_recv_data(
		struct vzsock_ctx *ctx,
		void *conn,
		char * const argv[]);
int vza_start_swap_srv(
		struct vzsock_ctx *ctx,
		void *conn,
		char * const argv[],
		pid_t *ppid);

#endif
