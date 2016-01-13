/* $Id$
 *
 * Copyright (c) 2006-2016 Parallels IP Holdings GmbH
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
#ifndef __MIGCHANNEL_H_
#define __MIGCHANNEL_H_

#include <stdarg.h>
#include <stdio.h>
#include <vector>
#include <memory>
#include <string>
#include <vz/libvzsock.h>

#define PACKET_SEPARATOR '\0'

class MigrateChannel
{
public:
	struct vzsock_ctx ctx;
	void *conn;
public:
	int establish(const char * args[]);
	int createSockChannel(const char * args[]);
	int get_fds(int *fds);

	int createParallelsServerChannel();

	int createChannel();

	int getFd(int std); // 0 - input, 1 - output, return -1 on error

	int createSshChannel(const char * ssh_args[], const char * const args[]);
	int closeChannel();

	int isConnected();
	char * readPkt(char separator, int *rc);
	int sendPkt(const char * str, ...);
	int sendPkt(char separator, const char * str, ...);
	int sendPkt(char separator, const char * str, va_list ap);
	int sendBuf(const char * buf, size_t size);

	int sendReply(int code, const char * str, ...);
	int sendErrMsg(int code, const char * str, ...);
	const char * readReply(int * code);
	int readReply();
	int sendCommand(const char * str, ...);

	MigrateChannel();
	~MigrateChannel();
};

int init_sock_server(struct vzsock_ctx *ctx, int *sock);
int init_sock_server_client(struct vzsock_ctx *ctx);

/*
 * Phaul connection manage additional connections needed for p.haul and
 * p.haul-service on source and destination sides respectively. Three
 * additional sockets needed for p.haul - socket for rpc calls, socket for
 * memory transfer and socket for disk transfer.
 */
class PhaulConn {
public:
	PhaulConn(const std::vector<std::string>& activeDeltas);
	~PhaulConn();
	int initServer(vzsock_ctx* ctx, int serverSocket);
	int initClient(vzsock_ctx* ctx);
	std::string getFdrpcArg() const;
	std::string getFdmemArg() const;
	std::string getFdfsArg() const;
	int checkEstablished() const;

private:
	int getChannelFd(size_t index) const;
	std::string getChannelFdStr(size_t index) const;
	std::string getActiveDeltaFdStr(size_t nDelta) const;

private:
	// Forbidden class methods
	PhaulConn(const PhaulConn&);
	PhaulConn& operator =(const PhaulConn&);

private:
	enum {
		RPC_CHANNEL_INDEX = 0,
		MEM_CHANNEL_INDEX = 1,
		FS_CHANNELS_START_INDEX = 2,
	};

private:
	std::auto_ptr<vzsock_ctx> m_ctx;
	std::vector<void*> m_channelConns;
	std::vector<std::string> m_activeDeltas;
};

/*
 * Phaul socket server handle additional connections establishment needed for
 * phaul on destination side.
 */
class PhaulSockServer {
public:
	PhaulSockServer();
	~PhaulSockServer();
	int init();
	PhaulConn* acceptConn(const std::vector<std::string>& activeDeltas);
private:
	// Forbidden class methods
	PhaulSockServer(const PhaulSockServer&);
	PhaulSockServer& operator =(const PhaulSockServer&);
private:
	std::auto_ptr<vzsock_ctx> m_ctx;
	int m_serverSocket;
};

/*
 * Client of phaul socket server handle additional connections establishment
 * needed for phaul on source side.
 */
class PhaulSockClient {
public:
	PhaulSockClient();
	~PhaulSockClient();
	int init();
	PhaulConn* establishConn(const std::vector<std::string>& activeDeltas);
private:
	// Forbidden class methods
	PhaulSockClient(const PhaulSockClient&);
	PhaulSockClient& operator =(const PhaulSockClient&);
private:
	std::auto_ptr<vzsock_ctx> m_ctx;
};

#endif
