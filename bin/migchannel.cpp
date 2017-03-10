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
#include <unistd.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <sstream>

#include "migchannel.h"
#include "common.h"
#include "bincom.h"
#include "channel.h"
#include "migssh.h"
#include "ssl.h"
#include "remotecmd.h"
#include "util.h"

MigrateChannel::MigrateChannel()
{
	conn = NULL;
}

MigrateChannel::~MigrateChannel()
{
	// fixme: seems we need to close
}


int MigrateChannel::get_fds(int *fds)
{
	int rc;
	size_t size = 2 * sizeof(int);

	if ((rc = vzsock_get_conn(&ctx, conn, VZSOCK_DATA_FDPAIR, fds, &size)))
		return putErr(MIG_ERR_VZSOCK, "vzsock_get_conn() return %d", rc);
	return 0;
}

int MigrateChannel::getFd(int num)
{
	int rc;
	int fds[2];

	if ((rc = get_fds(fds)))
		return -1;
	return (num == 0 ? fds[0] : fds[1]);
}

int MigrateChannel::isConnected()
{
	if (conn == NULL)
		return 0;
	return vzsock_is_open_conn(&ctx, conn);
}

int MigrateChannel::createSockChannel(const char * args[])
{
	int rc = 0;
	int ret;
	int debug = (debug_level == LOG_DEBUG)?1:0;

	if ((ret = vzsock_init(VZSOCK_SOCK, &ctx)))
		return putErr(MIG_ERR_VZSOCK, "vzsock_init() return %d", ret);

	vzsock_set(&ctx, VZSOCK_DATA_DEBUG, (void *)&debug, sizeof(debug));
	vzsock_set(&ctx, VZSOCK_DATA_LOGGER, (void *)&vzsock_logger, 0);
	vzsock_set(&ctx, VZSOCK_DATA_FILTER, (void *)&recv_filter, 0);
	if ((ret = vzsock_set(&ctx, VZSOCK_DATA_TMO, (void *)&VZMoptions.tmo.val, sizeof(VZMoptions.tmo.val)))) {
		rc = putErr(MIG_ERR_CONN_BROKEN, "vzsock_set() return %d", ret);
		goto cleanup_0;
	}
	if ((ret = vzsock_set(&ctx, VZSOCK_DATA_HOSTNAME, (void *)VZMoptions.dst_addr, strlen(VZMoptions.dst_addr)))) {
		rc = putErr(MIG_ERR_VZSOCK, "vzsock_set() return %d", ret);
		goto cleanup_0;
	}
	if ((ret = vzsock_set(&ctx, VZSOCK_DATA_SERVICE, (void *)VZMD_DEF_PORT, strlen(VZMD_DEF_PORT)))) {
		rc = putErr(MIG_ERR_VZSOCK, "vzsock_set() return %d", ret);
		goto cleanup_0;
	}

	if ((ret = vzsock_open(&ctx))) {
		rc = putErr(MIG_ERR_VZSOCK, "vzsock_open() return %d", ret);
		goto cleanup_0;
	}

	if ((ret = vzsock_open_conn(&ctx, NULL, &conn))) {
		rc = putErr(MIG_ERR_VZSOCK, "vzsock_create_conn() return %d", ret);
		goto cleanup_0;
	}

	if ((rc = establish(args)))
		goto cleanup_0;

	return 0;

	vzsock_close_conn(&ctx, conn);

cleanup_0:
	vzsock_close(&ctx);

	return rc;
}

int MigrateChannel::establish(const char * args[])
{
	int rc;
	char buffer[BUFSIZ];
	const char *reply;
	int i;
	char *p;

	/* send binary name */
	snprintf(buffer, sizeof(buffer), CMD_BINARY " %s",
		(VZMoptions.bintype == BIN_TEMPL) ? "vzmtemplate" : "vzmigrate");
	if ((rc = sendBuf(buffer, strlen(buffer) + 1)))
		return rc;

	/* and wait reply with remote version */
	if ((reply = readReply(&rc)) == NULL)
		return putErr(rc, "can't read reply from server");

	if (sscanf(reply, CMD_VERSION " %d", &VZMoptions.remote_version) != 1)
		return putErr(MIG_ERR_CONN_BROKEN,
			"Bad version from server: '%s'", reply);

	/* Send own version and also :
	   debug_level and options(OPT_ONLINE, OPT_EZTEMPLATE). */
	snprintf(buffer, sizeof(buffer), CMD_START_PARAMS " %d %llu %d",
		VZMoptions.version, VZMoptions.options, debug_level);
	if ((rc = sendBuf(buffer, strlen(buffer) + 1)))
		return rc;
	/* wait any reply */
	if ((rc = readReply()))
		return putErr(rc, "can't read reply from server");

	/* send arguments list */
	strcpy(buffer, CMD_ARGUMENTS);
	for (i = 0; args[i]; i++) {
		if (sizeof(buffer)-strlen(buffer) <= strlen(args[i]))
			return putErr(MIG_ERR_CONN_TOOLONG,
					"can't send : too long arguments list");
		strncat(buffer, " ", sizeof(buffer)-strlen(buffer)-1);
		strncat(buffer, args[i], sizeof(buffer)-strlen(buffer)-1);
	}
	/* replace ' by space */
	for (p = strchr(buffer, '\''); p; p = strchr(p, '\''))
		*p = ' ';
	if ((rc = sendBuf(buffer, strlen(buffer) + 1)))
		return rc;
	/* wait any reply */
	if ((rc = readReply()))
		return putErr(rc, "can't read reply from server");

	return 0;
}

int MigrateChannel::createSshChannel(
		const char * ssh_args[],
		const char * const args[])
{
	int rc = 0;
	int ret;
	int debug = (debug_level == LOG_DEBUG)?1:0;
	char dst[BUFSIZ];

	if (VZMoptions.dst_user)
		snprintf(dst, sizeof(dst), "%s@%s",
			VZMoptions.dst_user, VZMoptions.dst_addr);
	else
		strncpy(dst, VZMoptions.dst_addr, sizeof(dst));

	if ((ret = vzsock_init(VZSOCK_SSH, &ctx)))
		return putErr(MIG_ERR_CONN_BROKEN,
			"vzsock_init() return %d", ret);

	vzsock_set(&ctx, VZSOCK_DATA_DEBUG, (void *)&debug, sizeof(debug));
	vzsock_set(&ctx, VZSOCK_DATA_LOGGER, (void *)&vzsock_logger, 0);
	vzsock_set(&ctx, VZSOCK_DATA_FILTER, (void *)&recv_filter, 0);
	if ((ret = vzsock_set(&ctx, VZSOCK_DATA_TMO, (void *)&VZMoptions.tmo.val, sizeof(VZMoptions.tmo.val)))) {
		rc = putErr(MIG_ERR_CONN_BROKEN, "vzsock_set() return %d", ret);
		goto cleanup_0;
	}

	if ((ret = vzsock_set(&ctx, VZSOCK_DATA_ARGS, (void *)ssh_args, sizeof(ssh_args)))) {
		rc = putErr(MIG_ERR_CONN_BROKEN, "vzsock_set() return %d", ret);
		goto cleanup_0;
	}

	if ((ret = vzsock_set(&ctx, VZSOCK_DATA_HOSTNAME,
		(void *)dst, strlen(dst)+1)))
	{
		rc = putErr(MIG_ERR_CONN_BROKEN,
			"vzsock_set() return %d", ret);
		goto cleanup_0;
	}
	if (VZMoptions.dst_pwd)
		vzsock_set(&ctx, VZSOCK_DATA_PASSWORD,
			(void *)VZMoptions.dst_pwd,
			strlen(VZMoptions.dst_pwd) + 1);

	if ((ret = vzsock_open(&ctx))) {
		rc = putErr(MIG_ERR_CONN_BROKEN,
			"vzsock_open() return %d\n", ret);
		goto cleanup_0;
	}

	if ((ret = vzsock_open_conn(&ctx, (void *)args, &conn))) {
		rc = putErr(MIG_ERR_CONN_BROKEN,
			"vzsock_create_conn() return %d\n", ret);
		goto cleanup_0;
	}
	return 0;

	vzsock_close_conn(&ctx, conn);

cleanup_0:
	vzsock_close(&ctx);

	return rc;
}

/* server */
int MigrateChannel::createChannel()
{
	int rc = 0;
	int fds[2];
	int ret;
	int debug = (debug_level == LOG_DEBUG)?1:0;

	if ((ret = vzsock_init(VZSOCK_FD, &ctx)))
		return putErr(MIG_ERR_CONN_BROKEN,
			"vzsock_init() return %d", ret);

	vzsock_set(&ctx, VZSOCK_DATA_DEBUG, (void *)&debug, sizeof(debug));
	vzsock_set(&ctx, VZSOCK_DATA_LOGGER, (void *)&vzsock_logger, 0);
	if ((ret = vzsock_set(&ctx, VZSOCK_DATA_TMO, (void *)&VZMoptions.tmo.val, sizeof(VZMoptions.tmo.val)))) {
		rc = putErr(MIG_ERR_CONN_BROKEN, "vzsock_set() return %d", ret);
		goto cleanup_0;
	}

	if ((ret = vzsock_open(&ctx))) {
		rc = putErr(MIG_ERR_CONN_BROKEN,
			"vzsock_open() return %d\n", ret);
		goto cleanup_0;
	}

	if ((ret = vzsock_open_conn(&ctx, NULL, &conn))) {
		rc = putErr(MIG_ERR_CONN_BROKEN,
			"vzsock_create_conn() return %d\n", ret);
		goto cleanup_0;
	}

	fds[0] = STDIN_FILENO;
	/*
	   Do not use STDOUT_FILENO on vzmdest in ssh mode -
	   this descriptor will redirected in /dev/null by command handler
	   (https://jira.sw.ru/browse/PSBM-11287)
	*/
	fds[1] = dup(STDOUT_FILENO);
	do_nonblock(fds[0]);
	do_nonblock(fds[1]);
	do_noclo(fds[0]);
	do_noclo(fds[1]);
	if ((ret = vzsock_set_conn(&ctx, conn, VZSOCK_DATA_FDPAIR, fds, sizeof(fds)))) {
		rc = putErr(MIG_ERR_VZSOCK, "vzsock_set_conn() return %d\n", ret);
		goto cleanup_1;
	}

	return 0;

cleanup_1:
	vzsock_close_conn(&ctx, conn);

cleanup_0:
	vzsock_close(&ctx);

	return rc;
}

int MigrateChannel::createParallelsServerChannel()
{
	int rc = 0;
	int ret;
	int debug = (debug_level == LOG_DEBUG)?1:0;
	int fds[2];

	do_nonblock(VZMoptions.cmd_sock);

	if ((ret = vzsock_init(VZSOCK_FD, &ctx)))
		return putErr(MIG_ERR_VZSOCK, "vzsock_init() return %d", ret);
	vzsock_set(&ctx, VZSOCK_DATA_DEBUG, (void *)&debug, sizeof(debug));
	vzsock_set(&ctx, VZSOCK_DATA_LOGGER, (void *)&vzsock_logger, 0);
	vzsock_set(&ctx, VZSOCK_DATA_FILTER, (void *)&recv_filter, 0);

	if ((ret = vzsock_open(&ctx))) {
		rc = putErr(MIG_ERR_VZSOCK, "vzsock_open() return %d\n", ret);
		goto cleanup_0;
	}

	if ((ret = vzsock_open_conn(&ctx, NULL, &conn))) {
		rc = putErr(MIG_ERR_VZSOCK,
			"vzsock_open_conn() return %d\n", ret);
		goto cleanup_0;
	}
	fds[0] = VZMoptions.cmd_sock;
	fds[1] = VZMoptions.cmd_sock;
	if ((ret = vzsock_set_conn(&ctx, conn,
			VZSOCK_DATA_FDPAIR, fds, sizeof(fds))))
	{
		rc = putErr(MIG_ERR_VZSOCK,
			"vzsock_set_conn() return %d\n", ret);
		goto cleanup_1;
	}

	return 0;

cleanup_1:
	vzsock_close_conn(&ctx, conn);
cleanup_0:
	vzsock_close(&ctx);

	return rc;
}

int MigrateChannel::closeChannel()
{
	int rc = 0;

	if ((vzsock_close_conn(&ctx, conn)))
		rc = MIG_ERR_VZSOCK;
	conn = NULL;
	return rc;
}

int MigrateChannel::sendPkt(const char * str, ...)
{
	va_list ap;
	va_start(ap, str);
	int rc = sendPkt(PACKET_SEPARATOR, str, ap);
	va_end(ap);
	return rc;
}

int MigrateChannel::sendPkt(char separator, const char * str, ...)
{
	va_list ap;
	va_start(ap, str);
	int rc = sendPkt(separator, str, ap);
	va_end(ap);
	return rc;
}

int MigrateChannel::sendPkt(char separator, const char * str, va_list ap)
{
	int rc;
	char buffer[BUFSIZ + 1];

	// send packet
	rc = vsnprintf(buffer, sizeof(buffer), str, ap);
	if (rc < 0)
		return putErr(MIG_ERR_CONN_BROKEN, MIG_MSG_SEND_PKT);
	else if (rc >= (int)sizeof(buffer) - 1)
		return putErr(MIG_ERR_CONN_TOOLONG,
			"can't send : too long message");
	buffer[rc] = separator;

	return sendBuf(buffer, rc + 1);
}

int MigrateChannel::sendBuf(const char * buf, size_t size)
{
	if (conn == NULL)
		return putErr(MIG_ERR_CONN_BROKEN, MIG_MSG_SEND_BUF);

	return (*vzm_send)(&ctx, conn, buf, size);
}

// add |code| prefix to the message
static int formatReply(int code, const char *str, va_list ap, char *buf, size_t buf_size)
{
	int sz1, sz2;

	sz1 = snprintf(buf, buf_size, "|%d|", code);
	if (sz1 < 0)
		return putErr(MIG_ERR_CONN_BROKEN, MIG_MSG_SEND_PKT);

	sz2 = vsnprintf(buf + sz1, buf_size - sz1, str, ap);
	if (sz2 < 0)
		return putErr(MIG_ERR_CONN_BROKEN, MIG_MSG_SEND_PKT);
	if (sz2 >= (int)(buf_size))
		return putErr(MIG_ERR_CONN_TOOLONG,
			"can't send : too long message");

	return 0;
}

// function to send reply by 'DESTINATION' side as |errcode|:replymessage
// NOTE: use only on destination side
int MigrateChannel::sendReply(int code, const char * str, ...)
{
	char buffer[BUFSIZ + 1];
	va_list ap;
	int ret;

	va_start(ap, str);
	ret = formatReply(code, str, ap, buffer, sizeof(buffer));
	va_end(ap);

	if (ret)
		return ret;

	return sendBuf(buffer, strlen(buffer) + 1);
}

/* for error message sending only: putErr() call removed
   to avoid infinite looping */
int MigrateChannel::sendErrMsg(int code, const char * str, ...)
{
	char buffer[BUFSIZ + 1];
	va_list ap;
	int ret;

	if (conn == NULL)
		return putErr(MIG_ERR_CONN_BROKEN, MIG_MSG_SEND_ERR);

	va_start(ap, str);
	ret = formatReply(code, str, ap, buffer, sizeof(buffer));
	va_end(ap);

	if (ret)
		return ret;

	ret = vzsock_send_err_msg(&ctx, conn, buffer, strlen(buffer) + 1);
	return ret ? MIG_ERR_VZSOCK : 0;
}

/* read data from connection descriptor */
char * MigrateChannel::readPkt(char separator, int *rc)
{
	static char buffer[BUFSIZ];

	*rc = 0;
	int ret;
	size_t size = sizeof(buffer);

	buffer[0] = '\0';
	if ((ret = vzsock_recv(&ctx, conn, separator, buffer, &size))) {
		*rc = putErr(MIG_ERR_VZSOCK, "vzsock_recv() return %d", ret);
		return NULL;
	}
	if (strlen(buffer) == 0)
		return NULL;
	return buffer;
}

// function to read reply from 'DESTINATION' side as |errcode|:replymessage
// NOTE: use only on source side
// NOTE: you also can send debug/info/warning messages from destination node
const char * MigrateChannel::readReply(int * code)
{
	int rc;
	static char buffer[BUFSIZ];

	if (conn == NULL) {
		if (code != NULL)
			(*code) = putErr(MIG_ERR_CONN_BROKEN, MIG_MSG_RECV_REPLY);
		return NULL;
	}

	if ((rc = ch_read_reply(&ctx, conn,
			code, buffer, sizeof(buffer))))
		return NULL;

	return buffer;
}

int MigrateChannel::readReply()
{
	if (conn == NULL)
		return putErr(MIG_ERR_CONN_BROKEN, MIG_MSG_RECV_REPLY);

	return ch_read_retcode(&ctx, conn);
}

// Send packet and receive reply, return 'errcode' from reply,
// or from 'send' function if it cant send or read reply
// error put in setErrorMessage
// NOTE:: use only on SRC side
int MigrateChannel::sendCommand(const char * str, ...)
{
	va_list ap;
	va_start(ap, str);
	logger(LOG_DEBUG, "Send command: %s", str);
	int rc = sendPkt(PACKET_SEPARATOR, str, ap);
	va_end(ap);
	if (rc != 0)
		return rc;
	return readReply();
}

/*
 * Initialize socket server needed to accept incoming connections on
 * destination.
 */
int init_sock_server(struct vzsock_ctx *ctx, int *sock)
{
	int rc = 0;
	int ret;
	int debug = (debug_level == LOG_DEBUG) ? 1 : 0;
	struct addrinfo hints, *res, *ressave;

	if ((ret = vzsock_init(VZSOCK_SOCK, ctx)))
		return putErr(MIG_ERR_VZSOCK, "vzsock_init() return %d", ret);

	vzsock_set(ctx, VZSOCK_DATA_DEBUG, (void *)&debug, sizeof(debug));

	if ((ret = vzsock_open(ctx))) {
		rc = putErr(MIG_ERR_VZSOCK, "vzsock_open() return %d", ret);
		goto cleanup_0;
	}

	if ((*sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		rc = putErr(MIG_ERR_SYSTEM, "socket() : %m");
		goto cleanup_0;
	}

	memset(&hints, 0, sizeof(struct addrinfo));
	/*
	   AI_PASSIVE flag: the resulting address is used to bind
	   to a socket for accepting incoming connections.
	   So, when the hostname==NULL, getaddrinfo function will
	   return one entry per allowed protocol family containing
	   the unspecified address for that family.
	*/
	hints.ai_flags    = AI_PASSIVE;
	hints.ai_family   = AF_INET6;
	hints.ai_socktype = SOCK_STREAM;

	if ((ret = getaddrinfo(NULL, VZMD_DEF_PORT, &hints, &ressave))) {
		rc = putErr(MIG_ERR_SYSTEM, "getaddrinfo error: [%s]\n", gai_strerror(ret));
		goto cleanup_0;
	}

	/*
	   Try open socket with each address getaddrinfo returned,
	   until getting a valid listening socket.
	*/
	*sock = -1;
	for (res = ressave; res; res = res->ai_next) {
		*sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (*sock < 0)
			continue;
		if (bind(*sock, res->ai_addr, res->ai_addrlen) == 0)
			break;
		close(*sock);
		*sock = -1;
	}
	if (*sock < 0) {
		rc = putErr(MIG_ERR_SYSTEM, "socket error:: could not open socket\n");
		goto cleanup_1;
	}
	if ((ret = vzsock_set(ctx, VZSOCK_DATA_SOCK_TYPE, (void *)&res->ai_socktype, sizeof(res->ai_socktype)))) {
		rc = putErr(MIG_ERR_VZSOCK, "vzsock_set() return %d", ret);
		goto cleanup_2;
	}
	if ((ret = vzsock_set(ctx, VZSOCK_DATA_SOCK_PROTO, (void *)&res->ai_protocol, sizeof(res->ai_protocol)))) {
		rc = putErr(MIG_ERR_VZSOCK, "vzsock_set() return %d", ret);
		goto cleanup_2;
	}

	if (listen(*sock, SOMAXCONN)) {
		rc = putErr(MIG_ERR_SYSTEM, "listen() : %m");
		goto cleanup_2;
	}

	logger(LOG_INFO, "server started");

	return 0;

cleanup_2:
	close(*sock);

cleanup_1:
	freeaddrinfo(ressave);

cleanup_0:
	vzsock_close(ctx);

	return rc;
}

/*
 * Suppose we have N phaul channels - one rpc channel, one memory channel and
 * zero or more fs channels (channel per active ploop delta). So we have
 * (2 + active deltas count) channels in total.
 */
PhaulChannels::PhaulChannels(const std::vector<std::string>& activeDeltas)
	: m_channelsFds(FS_CHANNELS_START_INDEX + activeDeltas.size(),
		std::make_pair(-1, -1))
	, m_activeDeltas(activeDeltas)
{
}

PhaulChannels::~PhaulChannels()
{
	for (size_t i = 0; i < m_channelsFds.size(); ++i) {
		close(m_channelsFds[i].first);
		close(m_channelsFds[i].second);
	}
}

int PhaulChannels::init()
{
	int fds[2];
	int flags;

	for (size_t i = 0; i < m_channelsFds.size(); ++i) {

		if (inet_socketpair(SOCK_STREAM, 0, fds) != 0) {
			return -1;
		}

		m_channelsFds[i] = std::make_pair(fds[0], fds[1]);

		flags = fcntl(getVzmigrateChannelFd(i), F_GETFD);
		if (flags == -1) {
			return -1;
		}

		flags |= FD_CLOEXEC;
		if (fcntl(getVzmigrateChannelFd(i), F_SETFD, flags) == -1) {
			return -1;
		}
	}

	return 0;
}

std::vector<int> PhaulChannels::getVzmigrateChannelFds() const
{
	std::vector<int> fds(m_channelsFds.size());

	for (size_t i = 0; i < m_channelsFds.size(); ++i) {
		fds[i] = getVzmigrateChannelFd(i);
	}

	return fds;
}

/*
 * Return value of --fdrpc phaul argument.
 */
std::string PhaulChannels::getPhaulFdrpcArg() const
{
	return getPhaulChannelFdStr(RPC_CHANNEL_INDEX);
}

/*
 * Return value of --fdmem phaul argument.
 */
std::string PhaulChannels::getPhaulFdmemArg() const
{
	return getPhaulChannelFdStr(MEM_CHANNEL_INDEX);
}

/*
 * Return value of --fdfs phaul argument. It contain list of active ploop
 * delta paths with corresponding socket file descriptors in format
 * %path1%:%socket1%[,%path2%:%socket2%[,...]]. Expect path can't contain ','
 * character.
 */
std::string PhaulChannels::getPhaulFdfsArg() const
{
	std::ostringstream fdfs;
	for (size_t nDelta = 0; nDelta < m_activeDeltas.size(); ++nDelta) {

		// Append deltas separator
		if (nDelta != 0)
			fdfs << ",";

		// Append %path%:%socket% pair
		fdfs << m_activeDeltas[nDelta] << ":"
			<< getPhaulChannelFdStr(FS_CHANNELS_START_INDEX + nDelta);
	}

	return fdfs.str();
}

void PhaulChannels::closePhaulChannelFds()
{
	for (size_t i = 0; i < m_channelsFds.size(); ++i) {
		close(m_channelsFds[i].second);
		m_channelsFds[i].second = -1;
	}
}

int PhaulChannels::getVzmigrateChannelFd(size_t index) const
{
	if (index >= m_channelsFds.size())
		return -1;

	return m_channelsFds[index].first;
}

int PhaulChannels::getPhaulChannelFd(size_t index) const
{
	if (index >= m_channelsFds.size())
		return -1;

	return m_channelsFds[index].second;
}

std::string PhaulChannels::getPhaulChannelFdStr(size_t index) const
{
	std::ostringstream fdStr;
	fdStr << getPhaulChannelFd(index);
	return fdStr.str();
}
