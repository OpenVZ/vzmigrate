/* $Id$
 *
 * Copyright (c) Parallels, 2008
 *
 */

#ifndef __CHANNEL_H__
#define __CHANNEL_H__

#ifdef __cplusplus
extern "C" {
#endif

extern int (*vzm_send)(struct vzsock_ctx *ctx, void *conn, const char * data, size_t size);

/*
 Function to read reply from 'DESTINATION' side as |errcode|:replymessage
*/
int vzsock_logger(int level, const char *fmt, va_list pvar);

int recv_filter(char * buffer, int *code, char *reply, size_t *size);

int ch_read_reply(
		struct vzsock_ctx *ctx,
		void *conn,
		int *code,
		char *reply,
		size_t size);

/* read retcode from reply only */
int ch_read_retcode(
		struct vzsock_ctx *ctx,
		void *conn);

int ch_send_str(
		struct vzsock_ctx *ctx,
		void *conn,
		const char *str);

int ch_recv_str(
		struct vzsock_ctx *ctx,
		void *conn,
		char *buffer,
		size_t size);

int ch_recv(
		struct vzsock_ctx *ctx,
		void *conn,
		char separator,
		char *buffer,
		size_t size);

/* Send packet and receive reply, return 'errcode' from reply */
int ch_send_cmd(
		struct vzsock_ctx *ctx,
		void *conn,
		const char *cmd);

/* accept incoming connection on socket srvcosk during timeout "tmo" */
int sock_listen(int srvsock, long tmo);

/* accept incoming connection on socket srvcosk during timeout "tmo" */
int sock_accept(int srvsock, long tmo, int *sock);

/* connect to "host:service" during timeout "tmo" */
int sock_connect(const char *host, const char *service, long tmo, int *out_sock);

/*
  read from nonblocking descriptor <fd> string, separated by <separator>.
  will write '\0' on the end of string
*/
int sock_read(
		int fd,
		long tmo,
		char separator,
		char *data,
		size_t *size);

#ifdef __cplusplus
}
#endif

#endif
