/* $Id$
 *
 * Copyright (c) SWsoft, 2006-2007
 *
 */
#ifndef _MIGSSH_H_
#define _MIGSSH_H_

#include <sys/types.h>
#include <linux/limits.h>
#include <vz/libvzsock.h>

#include "migchannel.h"
#include "bincom.h"

#define SSH_PASS_SIZE 1024

int ssh_send_data(
		struct vzsock_ctx *ctx,
		void *conn,
		const char * cmd,
		char * const *tar_argv);
int ssh_recv_data(
		struct vzsock_ctx *ctx,
		void *conn,
		char * const *args,
		const char *dst,
		long timeout);
int ssh_start_swap_cli(
		struct vzsock_ctx *ctx,
		const char *dst_bin,
		unsigned dst_veid,
		void **wcn);
int ssh_start_swap_srv(struct vzsock_ctx *ctx, char * const *args);

// Ssh channel
class MigrateSshChannel : public MigrateChannel
{
public:
	int m_nFwdSrvSock;
	char *m_sFwdPort;
public:
	MigrateSshChannel();
	void killSshChannel();
	int fwdAddPort(CVZMOptions *options);
	int fwdBind();
	void fwdSrvClose();
	int fwdSendData(const char *cmd, char * const *argv);
	int fwdRecvData(char * const argv[]);
	int fwdStartSwapCli(const char *cmd, void **swapch);
	int fwdStartSwapSrv(char * const argv[]);
	void fwdCloseSwap(const void *swapch);
};

#if 0
struct ssh_conn {
	pid_t pid;
	int in;
	int out;
	char askfile[PATH_MAX + 1];
	char password[SSH_PASS_SIZE];
};

int generate_askpass(const char *pass, char *path, size_t size);

/* create test ssh connection */
int check_ssh(const char * addr, char *password, int psize);

/* start ssh connection */
int ssh_start_connection(
		char * const args[],
		const char *pass,
		struct ssh_conn *cn);

/*
  read from ssl connection string, separated by <separator>.
  will write '\0' on the end of string
*/
int ssh_recv_str(void *conn, char separator, char *data, size_t size);

/* send data via ssh connection */
int ssh_send(void *conn, const char * data, size_t size);

int ssh_close(void *conn);

void ssh_kill(void *conn);

int ssh_is_connected(void *conn);

int ssh_send_data(
		void *conn,
		unsigned long dst_addr,
		const char * cmd,
		char * const *args);

int ssh_recv_data(
		void *conn,
		char * const *args);

/* Filesystem objects coping via tar:
   - run ssh with tar on src
   - wait tar exiting on dst */
int ssh_send_data2(
		void *conn,
		unsigned long dst_addr,
		const char * cmd,
		char * const *tar_argv);
int ssh_recv_data2(
		void *conn,
		char * const *args,
		const char *dst,
		long timeout);

int ssh_start_swap_cli(
		void *conn,
		const char *addr,
		const char *src_bin,
		const char *dst_bin,
		unsigned src_veid,
		unsigned dst_veid,
		void **wcn);

int ssh_start_swap_srv(void *conn, char * const *args);

void ssh_swap_close(void *conn);
#endif
#endif

