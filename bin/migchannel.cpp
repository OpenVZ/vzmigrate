/* $Id$
 *
 * Copyright (c) SWsoft, 2006-2007
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
	vzsock_set(&ctx, VZSOCK_DATA_LOGGER, (void *)vzsock_logger, sizeof(&vzsock_logger));
	vzsock_set(&ctx, VZSOCK_DATA_FILTER, (void *)recv_filter, sizeof(&recv_filter));
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
	snprintf(buffer, sizeof(buffer), CMD_BINARY " vzmigrate");
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
	vzsock_set(&ctx, VZSOCK_DATA_LOGGER, (void *)vzsock_logger, sizeof(&vzsock_logger));
	vzsock_set(&ctx, VZSOCK_DATA_FILTER, (void *)recv_filter, sizeof(&recv_filter));
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
	vzsock_set(&ctx, VZSOCK_DATA_LOGGER, (void *)vzsock_logger, sizeof(&vzsock_logger));
//	vzsock_set(&ctx, VZSOCK_DATA_FILTER, (void *)recv_filter, sizeof(&recv_filter));
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
	vzsock_set(&ctx, VZSOCK_DATA_LOGGER,
			(void *)vzsock_logger, sizeof(&vzsock_logger));
	vzsock_set(&ctx, VZSOCK_DATA_FILTER,
			(void *)recv_filter, sizeof(&recv_filter));

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
	assert(conn);
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

	if ((rc = ch_read_reply(&ctx, conn,
			code, buffer, sizeof(buffer))))
		return NULL;

	return buffer;
}

int MigrateChannel::readReply()
{
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
 * Initialize client of socket server needed to establish connections from
 * source to destination.
 */
int init_sock_server_client(struct vzsock_ctx *ctx)
{
	int rc = 0;
	int ret;
	int debug = (debug_level == LOG_DEBUG) ? 1 : 0;

	if ((ret = vzsock_init(VZSOCK_SOCK, ctx)))
		return putErr(MIG_ERR_VZSOCK, "vzsock_init() return %d", ret);

	vzsock_set(ctx, VZSOCK_DATA_DEBUG, (void *)&debug, sizeof(debug));

	if ((ret = vzsock_set(ctx, VZSOCK_DATA_TMO, (void *)&VZMoptions.tmo.val, sizeof(VZMoptions.tmo.val)))) {
		rc = putErr(MIG_ERR_CONN_BROKEN, "vzsock_set() return %d", ret);
		goto cleanup_0;
	}
	if ((ret = vzsock_set(ctx, VZSOCK_DATA_HOSTNAME, (void *)VZMoptions.dst_addr, strlen(VZMoptions.dst_addr)))) {
		rc = putErr(MIG_ERR_VZSOCK, "vzsock_set() return %d", ret);
		goto cleanup_0;
	}
	if ((ret = vzsock_set(ctx, VZSOCK_DATA_SERVICE, (void *)VZMD_DEF_PORT, strlen(VZMD_DEF_PORT)))) {
		rc = putErr(MIG_ERR_VZSOCK, "vzsock_set() return %d", ret);
		goto cleanup_0;
	}

	if ((ret = vzsock_open(ctx))) {
		rc = putErr(MIG_ERR_VZSOCK, "vzsock_open() return %d", ret);
		goto cleanup_0;
	}

	return 0;

cleanup_0:
	vzsock_close(ctx);
	return rc;
}

PhaulConn::PhaulConn()
	: m_channelConns(CHANNELS_COUNT, NULL)
{
}

PhaulConn::~PhaulConn()
{
	if (m_ctx.get() == NULL)
		return;

	for (size_t i = 0; i < m_channelConns.size(); ++i) {
		if (m_channelConns[i] != NULL) {
			vzsock_close_conn(m_ctx.get(), m_channelConns[i]);
		}
	}

	vzsock_close(m_ctx.get());
}

int PhaulConn::initServer(vzsock_ctx* ctx, int serverSocket)
{
	sockaddr_storage addr;
	socklen_t addrsize = sizeof(addr);
	int connSocket;
	void* conn = NULL;
	int isBlocking = 1;

	if ((ctx == NULL) || (m_ctx.get() != NULL))
		return -1;

	m_ctx.reset(ctx);

	for (size_t i = 0; i < PhaulConn::CHANNELS_COUNT; ++i) {

		connSocket = accept(serverSocket, (sockaddr*)&addr, &addrsize);
		if (connSocket == -1) {
			return -1;
		}

		if (vzsock_accept_conn(m_ctx.get(), (void*)&connSocket, &conn) != 0) {
			close(connSocket);
			return -1;
		}

		m_channelConns[i] = conn;

		if (vzsock_set_conn(m_ctx.get(), m_channelConns[i],
			VZSOCK_DATA_BLOCKING, &isBlocking, sizeof(int)) != 0) {
			return -1;
		}
	}

	return 0;
}

int PhaulConn::initClient(vzsock_ctx* ctx)
{
	void* conn = NULL;
	int isBlocking = 1;

	if ((ctx == NULL) || (m_ctx.get() != NULL))
		return -1;

	m_ctx.reset(ctx);

	for (size_t i = 0; i < PhaulConn::CHANNELS_COUNT; ++i) {

		if (vzsock_open_conn(m_ctx.get(), NULL, &conn) != 0) {
			return -1;
		}

		m_channelConns[i] = conn;

		if (vzsock_set_conn(m_ctx.get(), m_channelConns[i],
			VZSOCK_DATA_BLOCKING, &isBlocking, sizeof(int)) != 0) {
			return -1;
		}
	}

	return 0;
}

int PhaulConn::getChannelFd(size_t index) const
{
	int fd = -1;
	size_t fdSize = sizeof(int);

	if ((m_ctx.get() == NULL) || (m_channelConns[index] == NULL))
		return -1;

	if (vzsock_get_conn(m_ctx.get(), m_channelConns[index],
		VZSOCK_DATA_FDSOCK, &fd, &fdSize) != 0) {
		return -1;
	}

	return fd;
}

int PhaulConn::isEstablished() const
{
	for (size_t i = 0; i < m_channelConns.size(); ++i) {
		if (getChannelFd(i) == -1) {
			return -1;
		}
	}
	return 0;
}

PhaulSockServer::PhaulSockServer()
	: m_serverSocket(-1)
{
}

PhaulSockServer::~PhaulSockServer()
{
	if (m_serverSocket != -1)
		close(m_serverSocket);

	if (m_ctx.get() != NULL)
		vzsock_close(m_ctx.get());
}

/*
 * Initialize phaul socket server to make it possible to accept incoming
 * connections. Code from vzmd reused.
 */
int PhaulSockServer::init()
{
	assert(m_ctx.get() == NULL);
	m_ctx.reset(new vzsock_ctx());

	if (init_sock_server(m_ctx.get(), &m_serverSocket) != 0) {
		m_ctx.reset(NULL);
		return -1;
	}

	return 0;
}

/*
 * Accept required count of additional connections for phaul.
 */
PhaulConn* PhaulSockServer::acceptConn()
{
	if ((m_ctx.get() == NULL) || (m_serverSocket == -1))
		return NULL;

	std::auto_ptr<PhaulConn> conn(new PhaulConn());
	if (conn->initServer(m_ctx.release(), m_serverSocket) != 0)
		return NULL;

	return conn.release();
}

PhaulSockClient::PhaulSockClient()
{
}

PhaulSockClient::~PhaulSockClient()
{
	if (m_ctx.get() != NULL)
		vzsock_close(m_ctx.get());
}

int PhaulSockClient::init()
{
	assert(m_ctx.get() == NULL);
	m_ctx.reset(new vzsock_ctx());

	if (init_sock_server_client(m_ctx.get())) {
		m_ctx.reset(NULL);
		return -1;
	}

	return 0;
}

/*
 * Establish required count of additional connections for phaul.
 */
PhaulConn* PhaulSockClient::establishConn()
{
	if (m_ctx.get() == NULL)
		return NULL;

	std::auto_ptr<PhaulConn> phaulConn(new PhaulConn());
	if (phaulConn->initClient(m_ctx.release()) != 0)
		return NULL;

	return phaulConn.release();
}
