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
		const char *dst_ctid,
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

#endif
