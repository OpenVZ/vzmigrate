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
#ifndef __MIGCHANNEL_H_
#define __MIGCHANNEL_H_

#include <stdarg.h>
#include <stdio.h>
#include <vector>
#include <memory>
#include <string>
#include <utility>
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

/*
 * Set of socket pairs needed to emulate multiple virtual connections using
 * single real connection. At least two channels needed for
 * p.haul/p.haul-service on source/destination sides respectively - channel
 * for rpc-calls, channel for memory transfer and zero or more channels for
 * disk transfer.
 */
class PhaulChannels {
public:
	PhaulChannels(const std::vector<std::string>& activeDeltas);
	~PhaulChannels();
	int init();

	std::vector<int> getVzmigrateChannelFds() const;
	std::string getPhaulFdrpcArg() const;
	std::string getPhaulFdmemArg() const;
	std::string getPhaulFdfsArg() const;
	void closePhaulChannelFds();

private:
	int getVzmigrateChannelFd(size_t index) const;
	int getPhaulChannelFd(size_t index) const;
	std::string getPhaulChannelFdStr(size_t index) const;

private:
	PhaulChannels(const PhaulChannels&);
	PhaulChannels& operator =(const PhaulChannels&);

private:
	enum {
		RPC_CHANNEL_INDEX = 0,
		MEM_CHANNEL_INDEX = 1,
		FS_CHANNELS_START_INDEX = 2,
	};

private:
	std::vector<std::pair<int, int> > m_channelsFds;
	std::vector<std::string> m_activeDeltas;
};

#endif
