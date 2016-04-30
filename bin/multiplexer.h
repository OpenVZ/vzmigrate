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

#ifndef __MULTIPLEXER_H_
#define __MULTIPLEXER_H_

#include <stdint.h>
#include <vector>
#include <deque>
#include <string>
#include <memory>
#include <boost/asio.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/noncopyable.hpp>

class MigrateChannel;

extern "C" {

/*
 * Packet header data. Consists of two uint32 values - channel index and packet
 * body size. ATTENTION!, don't touch structure size and format to preserve
 * backward compatibility.
 */
#pragma pack(push, 1)
struct MultiplexerPacketHeaderData {
	uint32_t m_channelIndex;
	uint32_t m_bodySize;
};
#pragma pack(pop)

/*
 * Multiplexer command header data. Consists of command id (uint32) and command
 * specific data (arbitrary size). ATTENTION!, don't touch structure format to
 * preserve backward compatibility.
 */
#pragma pack(push, 1)
struct MultiplexerCommandHeaderData {
	uint32_t m_command;
	char m_data[];
};
#pragma pack(pop)

/*
 * MULTIPLEXER_CMD_LOG_MESSAGE command associated data structure. Consists of
 * logging level of message (int32) and zero-terminated message string
 * (arbitrary size). ATTENTION!, don't touch structure format to preserve
 * backward compatibility.
 */
#pragma pack(push, 1)
struct MultiplexerLogCommandData {
	int32_t m_level;
	char m_text[];
};
#pragma pack(pop)

/*
 * Avaliable control commands. ATTENTION!, don't touch numeric values of
 * existing commands to preserve backward compatibility.
 */
enum EMultiplexerControlCommands {
	MULTIPLEXER_CMD_FINISH = 0,       // Ask peer to finish
	MULTIPLEXER_CMD_ABORT = 1,        // Ask peer to abort
	MULTIPLEXER_CMD_ACK_FINISH = 2,   // Acknowledge peers finish
	MULTIPLEXER_CMD_ACK_ABORT = 3,    // Acknowledge peers abort
	MULTIPLEXER_CMD_LOG_MESSAGE = 4,  // Log peer message
};

} // extern "C"

namespace multiplexer {

class IoMultiplexer;

/*
 * Packet buffer needed to simplify packet buffers allocation.
 */
class PacketBuffer : private boost::noncopyable {
public:
	static PacketBuffer* create(size_t size);
	bool shrink(size_t size);
	~PacketBuffer();

	char* getBuf();
	size_t getBufSize() const;
	char* getHeaderBuf();
	char* getBodyBuf();
	size_t getBodyBufSize() const;

private:
	PacketBuffer(char* buffer, size_t bufferSize);

public:
	enum {
		DEFAULT_BODY_SIZE =
			(0x100000 - sizeof(MultiplexerPacketHeaderData))  // ~1Mb
	};

private:
	char* m_buffer;
	size_t m_bufferSize;
};

/*
 * Packed packet with header meant for master connection. Packet starts with
 * fixed-size header followed by variable-size body.
 */
class PackedPacket : private boost::noncopyable {
public:
	static PackedPacket* create(const MultiplexerPacketHeaderData& header);
	PackedPacket(PacketBuffer* buffer);
	PacketBuffer* releaseBuffer();

	char* getBuf();
	size_t getBufSize() const;
	char* getBodyBuf();
	size_t getBodyBufSize() const;

private:
	std::auto_ptr<PacketBuffer> m_buffer;
};

/*
 * Raw packet without header meant for channel connection.
 */
class RawPacket : private boost::noncopyable {
public:
	static RawPacket* create();
	static RawPacket* create(size_t size);
	RawPacket(PacketBuffer* buffer);
	bool shrinkBuffer(size_t size);
	PacketBuffer* releaseBuffer();

	char* getBodyBuf();
	size_t getBodyBufSize() const;

private:
	std::auto_ptr<PacketBuffer> m_buffer;
};

/*
 * So-called master connection which handle packed packets transfer through
 * physical master socket.
 */
class MasterConn : private boost::noncopyable {
public:
	MasterConn(IoMultiplexer& ioMultiplexer, int fdIn, int fdOut);
	void doRecvPacked();
	void doSendPacked(const boost::shared_ptr<PackedPacket>& packet);
	void doCloseInStream();
	void doCloseOutStream();
	bool isSendQueueEmpty() const;

private:
	void asyncRecvHeader();
	void asyncRecvBody();
	void asyncSendPacked();
	void handleRecvHeader(const boost::system::error_code& error);
	void handleRecvBody(const boost::system::error_code& error);
	void handleSendPacked(const boost::system::error_code& error);

private:
	IoMultiplexer& m_ioMultiplexer;
	boost::asio::posix::stream_descriptor m_inStream;
	boost::asio::posix::stream_descriptor m_outStream;
	MultiplexerPacketHeaderData m_tempHeader;
	std::auto_ptr<PackedPacket> m_recvPacket;
	std::deque<boost::shared_ptr<PackedPacket> > m_sendQueue;
};

/*
 * So-called channel connection which handle unpacked packets transfer through
 * virtual channel socket.
 */
class ChannelConn : private boost::noncopyable {
public:
	ChannelConn(IoMultiplexer& ioMultiplexer, int fd, size_t index);
	void doRecvRaw();
	void doSendRaw(const boost::shared_ptr<RawPacket>& packet);
	void doClose();
	bool isClosed() const;
	bool isSendQueueEmpty() const;

private:
	void asyncPutRecvRaw();
	void asyncRecvRaw();
	void asyncSendRaw();
	void handlePutRecvRaw();
	void handleRecvRaw(const boost::system::error_code& error, size_t nRecved);
	void handleSendRaw(const boost::system::error_code& error);
	bool allocateRecvPacket();

private:
	IoMultiplexer& m_ioMultiplexer;
	boost::asio::ip::tcp::socket m_socket;
	size_t m_index;
	std::auto_ptr<RawPacket> m_recvPacket;
	std::deque<boost::shared_ptr<RawPacket> > m_sendQueue;
};

/*
 * So-called control connection which dispatch/process control commands needed
 * for communication between multiplexers.
 */
class ControlChannelConn : private boost::noncopyable {
public:
	ControlChannelConn(IoMultiplexer& ioMultiplexer);
	void doDispatchControlCommand(int command);
	void doDispatchLogMessage(int level, const std::string& text);
	void doProcessCommand(const boost::shared_ptr<RawPacket>& packet);

public:
	enum { INDEX = 0xff };

private:
	IoMultiplexer& m_ioMultiplexer;
};

/*
 * Io multiplexer which allows multiple virtual connections to be employed over
 * a single real connection. It multiplex/demultiplex data from/to several
 * so-called channel connections via so-called master connection manually.
 * Multiplexer have two modes of work - master mode and slave mode. Master mode
 * handle source side logic and slave mode handle destination side logic.
 */
class IoMultiplexer : private boost::noncopyable {
public:
	IoMultiplexer(MigrateChannel& migrateChannel,
		const std::vector<int>& channelFds, pid_t childPid, bool isMasterMode);
	int runMultiplexing();
	void runMultiplexingAbort();
	void doMultiplex(RawPacket* packet, size_t index);
	void doDemultiplex(PackedPacket* packet);
	void doProcessControlCommand(int command);
	void doProcessLogMessage(int level, const std::string& text);
	void doProcessDisconnect();
	void doProcessOOM();
	boost::asio::io_service& getIoService();
	bool isChildTerminated() const;

private:
	void processSigchld();
	void processFinishCommand();
	void processAbortCommand();
	void processAckFinishCommand();
	void processAckAbortCommand();

	void cleanupFinishing();
	void cleanupAborting();
	void cleanupAckFinishing();
	void cleanupAckAborting();

	void logMessage(int level, const std::string& text);
	void recvAllChannelsRawRemainder();
	void sendAllChannelsRawRemainder();
	void sendMasterPackedReminder();
	void closeAllChannels();
	bool isAllChannelsClosed() const;
	bool isAllChannelsSendQueuesEmpty() const;

private:
	enum EStates {
		STATE_RUNNING,          // Running
		STATE_FINISHING,        // Handle successful finish
		STATE_ABORTING,         // Handle abnormal finish
		STATE_ACK_FINISHING,    // Handle peers successful finish
		STATE_ACK_ABORTING,     // Handle peers abnormal finish
		STATE_DISCONNECTED,     // Handle peers disconnect
		STATE_OOM,              // Handle out of memory
	};

private:
	MigrateChannel& m_migrateChannel;
	boost::asio::io_service m_ioService;
	boost::shared_ptr<MasterConn> m_masterConn;
	boost::shared_ptr<ControlChannelConn> m_controlConn;
	std::vector<boost::shared_ptr<ChannelConn> > m_channelConns;
	boost::shared_ptr<boost::asio::signal_set> m_sigchldSet;
	pid_t m_childPid;
	bool m_isMasterMode;
	EStates m_state;
};

} // namespace multiplexer

#endif
