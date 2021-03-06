/*
 * Copyright (c) 2006-2017, Parallels International GmbH
 * Copyright (c) 2017-2019 Virtuozzo International GmbH. All rights reserved.
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
 * Our contact details: Virtuozzo International GmbH, Vordergasse 59, 8200
 * Schaffhausen, Switzerland.
 *
 */

#include <sys/types.h>
#include <sys/wait.h>
#include <boost/bind.hpp>
#include <boost/make_shared.hpp>
#include "multiplexer.h"
#include "migchannel.h"
#include "common.h"
#include <zstd.h>

namespace multiplexer {

/*
 * Create packet buffer of specified size. For efficiency reasons allocate
 * additional space for header at the start of the buffer unconditionally. So
 * finally buffer always starts with a fixed-size header (which unused in raw
 * packets). Variable-size body starts after header. Such trick make it
 * possible to convert raw packets to packed packets and vice versa without
 * excess memory copying.
 */
PacketBuffer* PacketBuffer::create(size_t size)
{
	// Calculate buffer size
	size_t bufferSize = sizeof(MultiplexerPacketHeaderData) + size;

	// Allocate buffer
	char* buffer = (char*)malloc(bufferSize);
	if (buffer == NULL) {
		return NULL;
	}

	return new PacketBuffer(buffer, bufferSize);
}

/*
 * Shrink buffer to specified size.
 */
bool PacketBuffer::shrink(size_t size)
{
	assert((sizeof(MultiplexerPacketHeaderData) + size) <= m_bufferSize);

	// Calculate new buffer size
	size_t newBufferSize = sizeof(MultiplexerPacketHeaderData) + size;

	// Reallocate buffer
	char* newBuffer = (char*)realloc(m_buffer, newBufferSize);
	if (newBuffer == NULL) {
		free(m_buffer);
		m_buffer = NULL;
		m_bufferSize = 0;
		return false;
	}

	m_buffer = newBuffer;
	m_bufferSize = newBufferSize;
	return true;
}

PacketBuffer::~PacketBuffer()
{
	free(m_buffer);
}

char* PacketBuffer::getBuf()
{
	return m_buffer;
}

size_t PacketBuffer::getBufSize() const
{
	return m_bufferSize;
}

char* PacketBuffer::getHeaderBuf()
{
	return getBuf();
}

char* PacketBuffer::getBodyBuf()
{
	return (m_buffer + sizeof(MultiplexerPacketHeaderData));
}

size_t PacketBuffer::getBodyBufSize() const
{
	assert(m_bufferSize > sizeof(MultiplexerPacketHeaderData));
	return (m_bufferSize - sizeof(MultiplexerPacketHeaderData));
}

/*
 * Construct packet buffer using allocated memory buffer of specified size.
 */
PacketBuffer::PacketBuffer(char* buffer, size_t bufferSize)
	: m_buffer(buffer)
	, m_bufferSize(bufferSize)
{
}

/*
 * Create packed packet with initialized header and empty body.
 */
PackedPacket* PackedPacket::create(const MultiplexerPacketHeaderData& header)
{
	PacketBuffer* buffer = PacketBuffer::create(header.m_bodySize);
	if (buffer == NULL) {
		return NULL;
	}

	memcpy(buffer->getHeaderBuf(), &header,
		sizeof(MultiplexerPacketHeaderData));

	return new PackedPacket(buffer);
}

/*
 * Construct packed packet using existing buffer.
 */
PackedPacket::PackedPacket(PacketBuffer* buffer)
	: m_buffer(buffer)
{
}

/*
 * Release packet buffer without destructing buffer object and return it.
 * After buffer released packet object becomes useless and must be destroyed.
 */
PacketBuffer* PackedPacket::releaseBuffer()
{
	return m_buffer.release();
}

char* PackedPacket::getBuf()
{
	return m_buffer->getBuf();
}

size_t PackedPacket::getBufSize() const
{
	return m_buffer->getBufSize();
}

char* PackedPacket::getBodyBuf()
{
	return m_buffer->getBodyBuf();
}

size_t PackedPacket::getBodyBufSize() const
{
	return m_buffer->getBodyBufSize();
}

/*
 * Create raw packet with empty body of default size.
 */
RawPacket* RawPacket::create()
{
	PacketBuffer* buffer = PacketBuffer::create(
		PacketBuffer::DEFAULT_BODY_SIZE);
	if (buffer == NULL) {
		return NULL;
	}

	return new RawPacket(buffer);
}

/*
 * Create raw packet with empty body of specified size.
 */
RawPacket* RawPacket::create(size_t size)
{
	PacketBuffer* buffer = PacketBuffer::create(size);
	if (buffer == NULL) {
		return NULL;
	}

	return new RawPacket(buffer);
}

/*
 * Construct raw packet using existing buffer.
 */
RawPacket::RawPacket(PacketBuffer* buffer)
	: m_buffer(buffer)
{
}

bool RawPacket::shrinkBuffer(size_t size)
{
	return m_buffer->shrink(size);
}

/*
 * Release packet buffer without destructing buffer object and return it.
 * After buffer released packet object becomes useless and must be destroyed.
 */
PacketBuffer* RawPacket::releaseBuffer()
{
	return m_buffer.release();
}

char* RawPacket::getBodyBuf()
{
	return m_buffer->getBodyBuf();
}

size_t RawPacket::getBodyBufSize() const
{
	return m_buffer->getBodyBufSize();
}

MasterConn::MasterConn(IoMultiplexer& ioMultiplexer, int fdIn, int fdOut)
	: m_ioMultiplexer(ioMultiplexer)
	, m_inStream(ioMultiplexer.getIoService())
	, m_outStream(ioMultiplexer.getIoService())
{
	boost::system::error_code dummy;
	m_inStream.assign(dup(fdIn), dummy);
	m_outStream.assign(dup(fdOut), dummy);
}

/*
 * Start receiving packed packets.
 */
void MasterConn::doRecvPacked()
{
	asyncRecvHeader();
}

/*
 * Add packed packet to write queue.
 */
void MasterConn::doSendPacked(const boost::shared_ptr<PackedPacket>& packet)
{
	// Skip packet if output stream was closed
	if (!m_outStream.is_open()) {
		return;
	}

	// Add new packed packet to write queue
	bool writeQueued = !m_sendQueue.empty();
	m_sendQueue.push_back(packet);
	m_ioMultiplexer.throttler().account(packet->getBodyBufSize());

	// Start new send operation if not already started
	if (!writeQueued) {
		asyncSendPacked();
	}
}

void MasterConn::doCloseInStream()
{
	boost::system::error_code dummy;
	m_inStream.close(dummy);
}

void MasterConn::doCloseOutStream()
{
	boost::system::error_code dummy;
	m_outStream.close(dummy);
}

bool MasterConn::isSendQueueEmpty() const
{
	return m_sendQueue.empty();
}

void MasterConn::asyncRecvHeader()
{
	boost::asio::async_read(m_inStream,
		boost::asio::buffer(
			&m_tempHeader,
			sizeof(MultiplexerPacketHeaderData)),
		boost::bind(
			&MasterConn::handleRecvHeader, this,
			boost::asio::placeholders::error));
}

void MasterConn::asyncRecvBody()
{
	assert(m_recvPacket.get() != NULL);

	boost::asio::async_read(m_inStream,
		boost::asio::buffer(
			m_recvPacket->getBodyBuf(),
			m_recvPacket->getBodyBufSize()),
		boost::bind(
			&MasterConn::handleRecvBody, this,
			boost::asio::placeholders::error));
}


void MasterConn::syncSendPacked()
{		
	boost::system::error_code error;

	while (m_sendQueue.size() > 1) {
		boost::asio::write(m_outStream,
			boost::asio::buffer(
				m_sendQueue.front()->getBuf(),
				m_sendQueue.front()->getBufSize()),
			error);
		if (error) {
			m_sendQueue.clear();
			m_ioMultiplexer.throttler().clear();
			doCloseOutStream();
			m_ioMultiplexer.doProcessDisconnect();
			return;
		}

		m_ioMultiplexer.throttler().release(m_sendQueue.front()->getBodyBufSize());
		// Remove processed packet from send queue
		m_sendQueue.pop_front();
	}
}

void MasterConn::asyncSendPacked()
{
	assert(!m_sendQueue.empty());

	if (m_ioMultiplexer.throttler().active())
		syncSendPacked();

	if (!m_sendQueue.empty()) {
		boost::asio::async_write(m_outStream,
			boost::asio::buffer(
				m_sendQueue.front()->getBuf(),
				m_sendQueue.front()->getBufSize()),
			boost::bind(
				&MasterConn::handleSendPacked, this,
				boost::asio::placeholders::error));
	}
}

void MasterConn::handleRecvHeader(const boost::system::error_code& error)
{
	if (error) {
		doCloseInStream();
		m_ioMultiplexer.doProcessDisconnect();
		return;
	}

	// Allocate new packed packet using information from temporary header
	m_recvPacket.reset(PackedPacket::create(m_tempHeader));
	if (m_recvPacket.get() == NULL) {
		m_ioMultiplexer.doProcessOOM();
		return;
	}

	// Start async receiving of packet body
	asyncRecvBody();
}

void MasterConn::handleRecvBody(const boost::system::error_code& error)
{
	assert(m_recvPacket.get() != NULL);

	if (error) {
		doCloseInStream();
		m_ioMultiplexer.doProcessDisconnect();
		return;
	}

	// Release received packed packet and demultiplex it
	m_ioMultiplexer.doDemultiplex(m_recvPacket.release());

	// Start async receiving of new packed packet
	if (!m_ioMultiplexer.throttler().active())
		asyncRecvHeader();
}

void MasterConn::handleSendPacked(const boost::system::error_code& error)
{
	if (error) {
		m_sendQueue.clear();
		m_ioMultiplexer.throttler().clear();
		doCloseOutStream();
		m_ioMultiplexer.doProcessDisconnect();
		return;
	}

	m_ioMultiplexer.throttler().release(m_sendQueue.front()->getBodyBufSize());
	// Remove processed packet from send queue
	m_sendQueue.pop_front();

	// Start new send operation if queue contain unprocessed packets
	if (!m_sendQueue.empty()) {
		asyncSendPacked();
	}
}

ChannelConn::ChannelConn(IoMultiplexer& ioMultiplexer, int fd, size_t index)
	: m_ioMultiplexer(ioMultiplexer)
	, m_socket(ioMultiplexer.getIoService())
	, m_index(index)
{
	boost::system::error_code dummy;
	m_socket.assign(boost::asio::ip::tcp::v4(), dup(fd), dummy);
}

/*
 * Start receiving raw packets.
 */
void ChannelConn::doRecvRaw()
{
	asyncPutRecvRaw();
}

/*
 * Add raw packet to write queue.
 */
void ChannelConn::doSendRaw(const boost::shared_ptr<RawPacket>& packet)
{
	// Skip packet if socket was closed
	if (!m_socket.is_open()) {
		return;
	}

	// Add new raw packet to write queue
	bool writeQueued = !m_sendQueue.empty();
	m_sendQueue.push_back(packet);

	m_ioMultiplexer.throttler().account(packet->getBodyBufSize());

	// Start new send operation if not already started
	if (!writeQueued) {
		asyncSendRaw();
	}
}

void ChannelConn::doClose()
{
	boost::system::error_code dummy;
	m_socket.close(dummy);
}

bool ChannelConn::isClosed() const
{
	return !m_socket.is_open();
}

bool ChannelConn::isSendQueueEmpty() const
{
	return m_sendQueue.empty();
}

void ChannelConn::asyncPutRecvRaw()
{
	m_ioMultiplexer.getIoService().post(
		boost::bind(&ChannelConn::handlePutRecvRaw, this));
}

void ChannelConn::asyncRecvRaw()
{
	assert(m_recvPacket.get() != NULL);

	m_socket.async_read_some(
		boost::asio::buffer(
			m_recvPacket->getBodyBuf(),
			m_recvPacket->getBodyBufSize()),
		boost::bind(
			&ChannelConn::handleRecvRaw, this,
			boost::asio::placeholders::error,
			boost::asio::placeholders::bytes_transferred));
}

void ChannelConn::asyncSendRaw()
{
	assert(!m_sendQueue.empty());

	boost::asio::async_write(m_socket,
		boost::asio::buffer(
			m_sendQueue.front()->getBodyBuf(),
			m_sendQueue.front()->getBodyBufSize()),
		boost::bind(
			&ChannelConn::handleSendRaw, this,
			boost::asio::placeholders::error));
}

void ChannelConn::handlePutRecvRaw()
{
	// Allocate new raw packet and start async receiving
	if (allocateRecvPacket()) {
		asyncRecvRaw();
	}
}

void ChannelConn::handleRecvRaw(const boost::system::error_code& error,
	size_t nRecved)
{
	if (error) {
		doClose();
		return;
	}

	// Shrink buffer size to real value
	if (!m_recvPacket->shrinkBuffer(nRecved)) {
		m_ioMultiplexer.doProcessOOM();
		return;
	}

	// Release received raw packet and multiplex it
	m_ioMultiplexer.doMultiplex(m_recvPacket.release(), m_index);

	// Allocate new raw packet and start async receiving
	if (allocateRecvPacket()) {
		asyncRecvRaw();
	}
}

void ChannelConn::handleSendRaw(const boost::system::error_code& error)
{
	if (error) {
		m_sendQueue.clear();
		m_ioMultiplexer.throttler().clear();
		doClose();
		return;
	}

	if (m_ioMultiplexer.throttler().release(m_sendQueue.front()->getBodyBufSize())) {
		// Start async receiving of new packed packet
		m_ioMultiplexer.doRecvPacked();
	}

	// Remove processed packet from send queue
	m_sendQueue.pop_front();

	// Start new send operation if queue contain unprocessed packets
	if (!m_sendQueue.empty()) {
		asyncSendRaw();
	}
}

bool ChannelConn::allocateRecvPacket()
{
	m_recvPacket.reset(RawPacket::create());

	if (m_recvPacket.get() == NULL) {
		m_ioMultiplexer.doProcessOOM();
		return false;
	}

	return true;
}

ControlChannelConn::ControlChannelConn(IoMultiplexer& ioMultiplexer)
	: m_ioMultiplexer(ioMultiplexer)
{
}

/*
 * Send control command to peer (e.g. MULTIPLEXER_CMD_FINISH).
 */
void ControlChannelConn::doDispatchControlCommand(int command)
{
	std::auto_ptr<RawPacket> rawPacket(
		RawPacket::create(sizeof(MultiplexerCommandHeaderData)));
	if (rawPacket.get() == NULL) {
		m_ioMultiplexer.doProcessOOM();
		return;
	}

	// Pack control command manually
	MultiplexerCommandHeaderData* commandHeader =
		((MultiplexerCommandHeaderData*)rawPacket->getBodyBuf());
	commandHeader->m_command = (uint32_t)command;

	// Release raw packet with control command and multiplex it
	m_ioMultiplexer.doMultiplex(rawPacket.release(), INDEX);
}

/*
 * Send log message to peer (MULTIPLEXER_CMD_LOG_MESSAGE).
 */
void ControlChannelConn::doDispatchLogMessage(int level,
	const std::string& text)
{
	std::auto_ptr<RawPacket> rawPacket(
		RawPacket::create(sizeof(MultiplexerCommandHeaderData) +
			sizeof(MultiplexerLogCommandData) + text.size() + 1));
	if (rawPacket.get() == NULL) {
		m_ioMultiplexer.doProcessOOM();
		return;
	}

	// Pack log message command manually
	MultiplexerCommandHeaderData* commandHeader =
		((MultiplexerCommandHeaderData*)rawPacket->getBodyBuf());
	commandHeader->m_command = (uint32_t)MULTIPLEXER_CMD_LOG_MESSAGE;

	MultiplexerLogCommandData* logCommandData =
		((MultiplexerLogCommandData*)commandHeader->m_data);
	logCommandData->m_level = (int32_t)level;
	snprintf(logCommandData->m_text, text.size() + 1, "%s", text.c_str());

	// Release raw packet with log message command and multiplex it
	m_ioMultiplexer.doMultiplex(rawPacket.release(), INDEX);
}

void ControlChannelConn::doProcessCommand(
	const boost::shared_ptr<RawPacket>& packet)
{
	// Unpack control command manually
	const MultiplexerCommandHeaderData* commandHeader =
		((const MultiplexerCommandHeaderData*)packet->getBodyBuf());

	if (commandHeader->m_command == MULTIPLEXER_CMD_LOG_MESSAGE) {
		const MultiplexerLogCommandData* logCommandData =
			((const MultiplexerLogCommandData*)commandHeader->m_data);
		m_ioMultiplexer.doProcessLogMessage(logCommandData->m_level,
			std::string(logCommandData->m_text));

	} else {
		m_ioMultiplexer.doProcessControlCommand(commandHeader->m_command);
	}
}

/*
 * Init ZSTD contexts
 */
CompressedWrapPolicy::CompressedWrapPolicy()
{
	m_zstdCCtx = ZSTD_createCCtx();
	m_zstdDCtx = ZSTD_createDCtx();
	m_rawWrapper.reset(new RawWrapPolicy());
}

CompressedWrapPolicy::~CompressedWrapPolicy()
{
	ZSTD_freeCCtx(m_zstdCCtx);
	ZSTD_freeDCtx(m_zstdDCtx);
}

/*
 * Pack raw packet and send it using master connection.
 */

boost::shared_ptr<PackedPacket> RawWrapPolicy::wrap(RawPacket* packet, size_t index)
{
	std::auto_ptr<RawPacket> rawPacket(packet);
	size_t bodySize = rawPacket->getBodyBufSize();

	// Release raw packet buffer
	std::auto_ptr<PacketBuffer> buffer(rawPacket->releaseBuffer());

	// Pack header manually
	((MultiplexerPacketHeaderData*)buffer->getHeaderBuf())->m_channelIndex =
		static_cast<uint32_t>(index);
	((MultiplexerPacketHeaderData*)buffer->getHeaderBuf())->m_bodySize =
		 static_cast<uint32_t>(bodySize);

	// Build packed packet from raw packet
	boost::shared_ptr<PackedPacket> packedPacket(
		new PackedPacket(buffer.release()));
	return packedPacket;
}

/*
 * Construct compressed packed and send it through the raw packed routine
 */
boost::shared_ptr<PackedPacket> CompressedWrapPolicy::wrap(RawPacket* packet, size_t index)
{
	// Prepare packet with the size of a worst case compression size
	RawPacket* outPacket = RawPacket::create(ZSTD_compressBound(packet->getBodyBufSize()));

	// Compress body (without header)
	size_t packSize = ZSTD_compressCCtx(m_zstdCCtx, outPacket->getBodyBuf(),
		outPacket->getBodyBufSize(), packet->getBodyBuf(), packet->getBodyBufSize(), 3);

	if (ZSTD_isError(packSize))
	{
		char buf[256];
		snprintf(buf, sizeof(buf), MIG_mSG_ZSTD_COMP_ERR, ZSTD_getErrorName(packSize));
		logger(LOG_ERR, buf);
		abort();
	}

	// We do not need original packet anymore
	delete packet;

	// Resize packet to the actual data written by ZSTD
	outPacket->shrinkBuffer(packSize);

	// Reuse Raw wrapping
	return m_rawWrapper->wrap(outPacket, index);
}

/*
 * Unwrap raw packed packed and return it along with channel id
 */
std::pair<boost::shared_ptr<RawPacket>, size_t> RawWrapPolicy::unwrap(PackedPacket* packet)
{
	std::auto_ptr<PackedPacket> packedPacket(packet);

	// Release packed packet buffer
	std::auto_ptr<PacketBuffer> buffer(packedPacket->releaseBuffer());

	// Unpack header manually
	size_t channelIndex = ((MultiplexerPacketHeaderData*)
		buffer->getHeaderBuf())->m_channelIndex;

	// Build raw packet from packed packet
	boost::shared_ptr<RawPacket> rawPacket(new RawPacket(buffer.release()));

	return std::make_pair(rawPacket, channelIndex);
}

/*
 * Unwrap compressed packed and send it through raw unwrap routine
 */
std::pair<boost::shared_ptr<RawPacket>, size_t> CompressedWrapPolicy::unwrap(PackedPacket* packet)
{
	// Construct new raw packet for decompressed data
	size_t decompSize = ZSTD_getFrameContentSize(packet->getBodyBuf(), packet->getBodyBufSize());
	std::auto_ptr<RawPacket> dummyRawPacket(RawPacket::create(decompSize));

	size_t realZstdCompSize = ZSTD_decompressDCtx(m_zstdDCtx, dummyRawPacket->getBodyBuf(),
		decompSize, packet->getBodyBuf(), packet->getBodyBufSize());
	if (ZSTD_isError(realZstdCompSize))
	{
		char buf[BUFSIZ];
		snprintf(buf, sizeof(buf), MIG_mSG_ZSTD_DECOMP_ERR,
			ZSTD_getErrorName(realZstdCompSize));
		logger(LOG_ERR, buf);
		abort();
	}

	std::auto_ptr<PacketBuffer> buffer(dummyRawPacket->releaseBuffer());

	// Pack header manually
	((MultiplexerPacketHeaderData*)buffer->getHeaderBuf())->m_channelIndex =
		((MultiplexerPacketHeaderData*)packet->getBuf())->m_channelIndex;
	((MultiplexerPacketHeaderData*)buffer->getHeaderBuf())->m_bodySize =
		decompSize;

	// We don't need original packet anymore at this point
	delete packet;

	// Reuse Raw unwrap routine
	PackedPacket* packedPacket = new PackedPacket(buffer.release());
	return m_rawWrapper->unwrap(packedPacket);
}

/*
 * IO Multiplexer class
 */
IoMultiplexer::IoMultiplexer(MigrateChannel& migrateChannel,
	const std::vector<int>& channelFds, pid_t childPid, bool isMasterMode, bool isCompressionEnabled)
	: m_migrateChannel(migrateChannel)
	, m_childPid(childPid)
	, m_isMasterMode(isMasterMode)
	, m_state(STATE_RUNNING)
{
	assert(channelFds.size() <= ControlChannelConn::INDEX);

	// Create master connetion
	m_masterConn.reset(new MasterConn(*this, migrateChannel.getFd(0),
		migrateChannel.getFd(1)));

	// Create control channel connection
	m_controlConn.reset(new ControlChannelConn(*this));

	logger(LOG_INFO, "Compression is %s", isCompressionEnabled ? "enabled" : "disabled");
	if (isCompressionEnabled)
	{
		m_wrapPolicy = boost::make_shared<CompressedWrapPolicy>();
	} else {
		m_wrapPolicy = boost::make_shared<RawWrapPolicy>();
	}

	// Create channel connections
	for (size_t i = 0; i < channelFds.size(); ++i) {
		m_channelConns.push_back(boost::shared_ptr<ChannelConn>(
			new ChannelConn(*this, channelFds[i], i)));
	}

	// Create SIGCHLD signal set
	m_sigchldSet.reset(new boost::asio::signal_set(m_ioService, SIGCHLD));
}

/*
 * Run io multiplexing.
 */
int IoMultiplexer::runMultiplexing()
{
	// Start master connection packets receiving
	m_masterConn->doRecvPacked();

	// Start channel connections packets receiving
	for (size_t i = 0; i < m_channelConns.size(); ++i) {
		m_channelConns[i]->doRecvRaw();
	}

	// Setup SIGCHLD handler
	m_sigchldSet->async_wait(
		boost::bind(&IoMultiplexer::processSigchld, this));

	// Run packets processing loop
	boost::system::error_code dummy;
	m_ioService.run(dummy);

	// Reset io service after it was stopped
	m_ioService.reset();

	// Jump to cleanup routine
	switch (m_state) {
	case STATE_FINISHING:
		cleanupFinishing();
		return 0;
	case STATE_ABORTING:
		cleanupAborting();
		logMessage(LOG_DEBUG, MIG_MSG_MPX_ABORT);
		return -1;
	case STATE_ACK_FINISHING:
		cleanupAckFinishing();
		return 0;
	case STATE_ACK_ABORTING:
		cleanupAckAborting();
		logMessage(LOG_DEBUG, MIG_MSG_MPX_PEER_ABORT);
		return -1;
	case STATE_DISCONNECTED:
		logMessage(LOG_ERR, MIG_MSG_MPX_DISCONNECT);
		return -1;
	case STATE_OOM:
		logMessage(LOG_ERR, MIG_MSG_MPX_OOM);
		return -1;
	default:
		logMessage(LOG_ERR, MIG_MSG_MPX_UNKNOWN);
		return -1;
	}
}

/*
 * Run io multiplexing abnormal termination.
 */
void IoMultiplexer::runMultiplexingAbort()
{
	// Start master connection packets receiving
	m_masterConn->doRecvPacked();

	closeAllChannels();
	m_state = STATE_ABORTING;
	cleanupAborting();
}

/*
 * Pack raw packet and send it using master connection.
 */
void IoMultiplexer::doMultiplex(RawPacket* packet, size_t index)
{
	m_masterConn->doSendPacked(m_wrapPolicy->wrap(packet, index));
}

/*
 * Unpack packed packet and send it using channel connection.
 */
void IoMultiplexer::doDemultiplex(PackedPacket* packet)
{
	std::pair<boost::shared_ptr<RawPacket>, size_t> packet_pair = m_wrapPolicy->unwrap(packet);
	boost::shared_ptr<RawPacket> rawPacket = packet_pair.first;
	size_t channelIndex = packet_pair.second;

	if (channelIndex < m_channelConns.size()) {
		m_channelConns[channelIndex]->doSendRaw(rawPacket);

	} else if (channelIndex == ControlChannelConn::INDEX) {
		m_controlConn->doProcessCommand(rawPacket);

	} else {
		char buf[BUFSIZ];
		snprintf(buf, sizeof(buf), MIG_MSG_MPX_UNKNOWN_CHANNEL,
			(int)channelIndex);
		logMessage(LOG_ERR, buf);
	}
}

/*
 * Process control command from control channel.
 */
void IoMultiplexer::doProcessControlCommand(int command)
{
	switch (command) {
	case MULTIPLEXER_CMD_FINISH:
		return processFinishCommand();
	case MULTIPLEXER_CMD_ABORT:
		return processAbortCommand();
	case MULTIPLEXER_CMD_ACK_FINISH:
		return processAckFinishCommand();
	case MULTIPLEXER_CMD_ACK_ABORT:
		return processAckAbortCommand();
	default:
		{
		char buf[BUFSIZ];
		snprintf(buf, sizeof(buf), MIG_MSG_MPX_UNKNOWN_CMD, command);
		logMessage(LOG_ERR, buf);
		}
	}
}

/*
 * Process log message from control channel.
 */
void IoMultiplexer::doProcessLogMessage(int level, const std::string& text)
{
	if (m_isMasterMode) {
		std::string tmpText = std::string(MIG_INFO_MPX_SLAVE_PREFIX) + text;
		logMessage(level, tmpText);
	}
}

/*
 * Process master connection disconnect.
 */
void IoMultiplexer::doProcessDisconnect()
{
	// Skip processing if cleanup already in process
	if (m_state != STATE_RUNNING) {
		return;
	}

	m_state = STATE_DISCONNECTED;
	m_ioService.stop();
}

/*
 * Process out of memory state.
 */
void IoMultiplexer::doProcessOOM()
{
	m_masterConn->doCloseInStream();
	m_masterConn->doCloseOutStream();
	m_migrateChannel.closeChannel();

	// Skip further processing if cleanup already in process
	if (m_state != STATE_RUNNING) {
		return;
	}

	m_state = STATE_OOM;
	m_ioService.stop();
}

boost::asio::io_service& IoMultiplexer::getIoService()
{
	return m_ioService;
}

bool IoMultiplexer::isChildTerminated() const
{
	return (m_childPid == -1);
}

/*
 * Process SIGCHLD signal.
 */
void IoMultiplexer::processSigchld()
{
	assert(m_childPid != -1);

	// Chech exit status of desired child
	int status;
	pid_t child = waitpid(m_childPid, &status, WNOHANG);

	// Setup SIGCHLD handler and return if desired child still alive
	if (child != m_childPid) {
		m_sigchldSet->async_wait(
			boost::bind(&IoMultiplexer::processSigchld, this));
		return;
	}

	// Reset child pid
	m_childPid = -1;

	// Skip further processing if cleanup already in process
	if (m_state != STATE_RUNNING) {
		return;
	}

	// Determine cleanup state
	if (m_isMasterMode) {
		if ((WIFEXITED(status) && (WEXITSTATUS(status) == 0))) {
			m_state = STATE_FINISHING;
		} else {
			m_state = STATE_ABORTING;
		}
	} else {
		m_state = STATE_ABORTING;
	}

	m_ioService.stop();
}

/*
 * Process MULTIPLEXER_CMD_FINISH command (ask peer to finish).
 */
void IoMultiplexer::processFinishCommand()
{
	// Release master input stream
	m_masterConn->doCloseInStream();

	if (m_state == STATE_RUNNING) {
		m_state = STATE_ACK_FINISHING;
		m_ioService.stop();
	}
}

/*
 * Process MULTIPLEXER_CMD_ABORT command (ask peer to abort).
 */
void IoMultiplexer::processAbortCommand()
{
	// Release master input stream
	m_masterConn->doCloseInStream();

	if (m_state == STATE_RUNNING) {
		m_state = STATE_ACK_ABORTING;
		m_ioService.stop();
	}
}

/*
 * Process MULTIPLEXER_CMD_ACK_FINISH command (acknowledge peers finish).
 */
void IoMultiplexer::processAckFinishCommand()
{
	// Release master input stream
	m_masterConn->doCloseInStream();
}

/*
 * Process MULTIPLEXER_CMD_ACK_ABORT command (acknowledge peers abort).
 */
void IoMultiplexer::processAckAbortCommand()
{
	// Release master input stream
	m_masterConn->doCloseInStream();
}

/*
 * Handle cleanup in STATE_FINISHING state. Child process dead in this state.
 */
void IoMultiplexer::cleanupFinishing()
{
	// Receive raw packets while open channels present
	recvAllChannelsRawRemainder();

	// Receive remainder from closed channels
	m_ioService.poll();

	// Queue finish control command to peer
	m_controlConn->doDispatchControlCommand(MULTIPLEXER_CMD_FINISH);

	// Send master remainder and release master output stream
	sendMasterPackedReminder();
	m_masterConn->doCloseOutStream();

	// Run loop waiting for acknowledgement control command from peer
	boost::system::error_code dummy;
	m_ioService.run(dummy);
}

/*
 * Handle cleanup in STATE_ABORTING state. Child process dead in this state.
 */
void IoMultiplexer::cleanupAborting()
{
	// Receive raw packets while open channels present
	recvAllChannelsRawRemainder();

	// Receive remainder from closed channels
	m_ioService.poll();

	// Queue abort control command to peer
	m_controlConn->doDispatchControlCommand(MULTIPLEXER_CMD_ABORT);

	// Send master remainder and release master output stream
	sendMasterPackedReminder();
	m_masterConn->doCloseOutStream();

	// Run loop waiting for acknowledgement control command from peer
	boost::system::error_code dummy;
	m_ioService.run(dummy);
}

/*
 * Handle cleanup in STATE_ACK_FINISHING state.
 */
void IoMultiplexer::cleanupAckFinishing()
{
	// Send channel remainders and close all channels
	sendAllChannelsRawRemainder();
	closeAllChannels();

	// Receive remainder from closed channels
	m_ioService.poll();

	// Queue acknowledgement control command to peer
	m_controlConn->doDispatchControlCommand(MULTIPLEXER_CMD_ACK_FINISH);

	// Send master remainder and release master output stream
	sendMasterPackedReminder();
	m_masterConn->doCloseOutStream();
}

/*
 * Handle cleanup in STATE_ACK_ABORTING state.
 */
void IoMultiplexer::cleanupAckAborting()
{
	// Send channel remainders and close all channels
	sendAllChannelsRawRemainder();
	closeAllChannels();

	// Receive remainder from closed channels
	m_ioService.poll();

	// Queue acknowledgement control command to peer
	m_controlConn->doDispatchControlCommand(MULTIPLEXER_CMD_ACK_ABORT);

	// Send master remainder and release master output stream
	sendMasterPackedReminder();
	m_masterConn->doCloseOutStream();
}

void IoMultiplexer::logMessage(int level, const std::string& text)
{
	if (m_isMasterMode) {
		logger(level, text.c_str());
	} else {
		m_controlConn->doDispatchLogMessage(level, text);
	}
}

/*
 * Run packets processing loop while open channel connections present.
 */
void IoMultiplexer::recvAllChannelsRawRemainder()
{
	boost::system::error_code dummy;
	while (!isAllChannelsClosed()) {
		m_ioService.run_one(dummy);
	}
}

/*
 * Run packets processing loop while send queues of all channel connections
 * not empty.
 */
void IoMultiplexer::sendAllChannelsRawRemainder()
{
	boost::system::error_code dummy;
	while (!isAllChannelsSendQueuesEmpty()) {
		m_ioService.run_one(dummy);
	}
}

/*
 * Run packets processing loop while send queue of master connection not empty.
 */
void IoMultiplexer::sendMasterPackedReminder()
{
	boost::system::error_code dummy;
	while (!m_masterConn->isSendQueueEmpty()) {
		m_ioService.run_one(dummy);
	}
}

void IoMultiplexer::closeAllChannels()
{
	for (size_t i = 0; i < m_channelConns.size(); ++i) {
		m_channelConns[i]->doClose();
	}
}

/*
 * Check that all channel connections closed.
 */
bool IoMultiplexer::isAllChannelsClosed() const
{
	for (size_t i = 0; i < m_channelConns.size(); ++i) {
		if (!m_channelConns[i]->isClosed()) {
			return false;
		}
	}

	return true;
}

/*
 * Check that send queues of all channel connections empty.
 */
bool IoMultiplexer::isAllChannelsSendQueuesEmpty() const
{
	for (size_t i = 0; i < m_channelConns.size(); ++i) {
		if (!m_channelConns[i]->isSendQueueEmpty()) {
			return false;
		}
	}

	return true;
}

/////////////////////////////////////////////////////////
// Throttler
void Throttler::account(size_t size)
{
	m_total += size;
	if (!m_active && m_total > m_limit) {
		logger(LOG_DEBUG, "throttler: start throtling total: %lu", m_total);
		m_active = true;
	}
}

bool Throttler::release(size_t size)
{
	bool a = m_active;

	m_total -= size;
	if (m_total < m_limit)
		m_active = false;
	if (a && a != m_active) {
		logger(LOG_DEBUG, "throttler: stop throtling total: %lu", m_total);
		return true;
	}

	return false;
}

} // namespace multiplexer
