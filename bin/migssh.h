/* $Id$
 *
 * Copyright (c) 2006-2017, Parallels International GmbH
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
 * Our contact details: Parallels International GmbH, Vordergasse 59, 8200
 * Schaffhausen, Switzerland.
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
};

#endif
