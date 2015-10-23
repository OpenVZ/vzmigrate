/* $Id$
 *
 * Copyright (c) SWsoft, 2006-2007
 *
 */
#ifndef __MIGCHANNEL_H_
#define __MIGCHANNEL_H_

#include <stdarg.h>
#include <stdio.h>
#include <vector>
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

/*
 * Phaul connection manage additional connections needed for p.haul and
 * p.haul-service on source and destination sides respectively. Three
 * additional sockets needed for p.haul - socket for rpc calls, socket for
 * memory transfer and socket for disk transfer.
 */
class PhaulConnection {
public:
	PhaulConnection();
	~PhaulConnection();
	void setChannelFd(size_t index, int fd);
	int getChannelFd(size_t index) const;
	int isEstablished() const;
private:
	// Forbidden class methods
	PhaulConnection(const PhaulConnection&);
	PhaulConnection& operator =(const PhaulConnection&);
public:
	static const size_t RPC_CHANNEL_INDEX = 0;
	static const size_t MEM_CHANNEL_INDEX = 1;
	static const size_t FS_CHANNEL_INDEX = 2;
	static const size_t CHANNELS_COUNT = 3;
private:
	std::vector<int> m_channelFds;
};

#endif
