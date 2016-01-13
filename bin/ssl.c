/*
 * Copyright (c) 2016 Parallels IP Holdings GmbH
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
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <asm/param.h>
#include <getopt.h>
#include <libgen.h>
#include <limits.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/select.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#include "common.h"
#include "channel.h"
#include "ssl.h"
#include "util.h"

#define BUFFSIZE 16384

extern long io_timeout;

/*
SSL_CTX * ctx = NULL;
char crtfile[PATH_MAX + 1];
char keyfile[PATH_MAX + 1];
char *ciphers = NULL;
*/

/* recursive dump of the error stack */
static void ssl_error_stack()
{
	unsigned long err;
	char buffer[SSL_ERR_STRING_MAXLEN];

	err = ERR_get_error();
	if (err == 0)
		return;
	ssl_error_stack();
	ERR_error_string_n(err, buffer, sizeof(buffer));
	logger(LOG_ERR, "SSL error stack: %lu : %s", err, buffer);
}

int ssl_error(int rc, const char *title)
{
	char buffer[SSL_ERR_STRING_MAXLEN];
	ERR_error_string_n(ERR_get_error(), buffer, sizeof(buffer));
	ssl_error_stack();
	return putErr(MIG_ERR_SSL, "%s: %s", title, buffer);
}

int ssl_init(struct ssl_conn *cn)
{
	cn->ssl = NULL;
	cn->sock = -1;
//	cn->in = -1;
//	cn->out = -1;
//	cn->pid = 0;

	return 0;
}

int ssl_shutdown(SSL *ssl)
{
	int rc;

	rc = SSL_shutdown(ssl);
	if (rc == -1)
		return ssl_error(MIG_ERR_SSL, "SSL_shutdown()");
	if (rc == 0)
		return 0;

	if (SSL_shutdown(ssl) == -1)
		return ssl_error(MIG_ERR_SSL, "SSL_shutdown()");

	return 0;
}

int ssl_close(void *conn)
{
	struct ssl_conn *cn = (struct ssl_conn *)conn;

	SSL_shutdown(cn->ssl);
	ssl_clean(cn);
	return 0;
}

void ssl_clean(struct ssl_conn *cn)
{
	if (cn->ssl) {
		if (SSL_is_init_finished(cn->ssl))
/* TODO: repeat SSL_shutdown with select (nonblocking) */
			SSL_shutdown(cn->ssl);
		SSL_free(cn->ssl);
//SSL_set_shutdown(cn->ssl, SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
//SSL_free(cn->ssl);
//ERR_remove_state(0);
	}
	cn->ssl = NULL;

	if (cn->sock != -1)
		close(cn->sock);
	cn->sock = -1;

	free((void *)cn);
}

void ssl_srv_clean(struct ssl_conn *cn)
{
	if (cn->ctx)
		SSL_CTX_free(cn->ctx);
	cn->ctx = NULL;
}

int ssl_select(int sock, int err, long timeout)
{
	int rc;
	fd_set fds;
	struct timeval tv;

	do {
		FD_ZERO(&fds);
		FD_SET(sock, &fds);
		tv.tv_sec = timeout;
		tv.tv_usec = 0;
		if (err == SSL_ERROR_WANT_READ)
			rc = select(sock + 1, &fds, NULL, NULL, &tv);
		else
			rc = select(sock + 1, NULL, &fds, NULL, &tv);
		if (rc == 0) {
			return putErr(MIG_ERR_CONN_TIMEOUT,
				"timeout (%d sec)", timeout);
		} else if (rc <= 0) {
			return putErr(MIG_ERR_CONN_BROKEN, "select() : %m");
		}
	} while (!FD_ISSET(sock, &fds));

	return 0;
}


/* to establish client connection with server <dst_addr> */
int ssl_cli_conn_init(
		const char * dst_addr,
		const char * certificate,
		const char * privatekey,
		const char * ciphers,
		struct ssl_conn **conn)
{
	int rc = 0;
	int retcode, err;
	struct ssl_conn *cn;
	struct sockaddr_in addr;
	long result;
	int mode;

	if ((addr.sin_addr.s_addr = inet_addr(dst_addr)) == INADDR_NONE) {
		/* need to resolve address */
		struct hostent *host;
		if ((host = gethostbyname(dst_addr)) == NULL) {
			return putErr(MIG_ERR_SYSTEM,
				"gethostbyname(%s) err : %m\n", dst_addr);
		}
		memcpy(&addr.sin_addr.s_addr, host->h_addr,
			sizeof(addr.sin_addr.s_addr));
	}
	addr.sin_family = AF_INET;
	addr.sin_port = htons(VZMD_DEF_PORT);

	if ((cn = (struct ssl_conn *)malloc(sizeof(struct ssl_conn))) == NULL)
		return putErr(MIG_ERR_SYSTEM, "malloc() : %m");
	ssl_init(cn);

	if (strlen(certificate))
		strncpy(cn->crtfile, certificate, sizeof(cn->crtfile));
	else
		strncpy(cn->crtfile, DEF_CRTFILE, sizeof(cn->crtfile));
	if (strlen(privatekey))
		strncpy(cn->keyfile, privatekey, sizeof(cn->keyfile));
	else
		strncpy(cn->keyfile, DEF_KEYFILE, sizeof(cn->keyfile));

	/* Set up the library */
	SSL_library_init();
	SSL_load_error_strings();

	/* Create SSL context (framework) */
	if ((cn->ctx = SSL_CTX_new(SSLv23_client_method())) == NULL) {
		rc = ssl_error(MIG_ERR_SSL, "SSL_CTX_new()");
		goto cleanup_0;
	}
	/* load certificat from file */
	if(SSL_CTX_use_certificate_file(cn->ctx,
			cn->crtfile, SSL_FILETYPE_PEM) != 1) {
		rc = ssl_error(MIG_ERR_SSL, "SSL_CTX_use_certificate_file()");
		goto cleanup_1;
	}
	if(SSL_CTX_use_PrivateKey_file(cn->ctx,
			cn->keyfile, SSL_FILETYPE_PEM) != 1) {
		rc = ssl_error(MIG_ERR_SSL, "SSL_CTX_use_PrivateKey_file()");
		goto cleanup_1;
	}
	if (strlen(ciphers)) {
		strncpy(cn->ciphers, ciphers, sizeof(cn->ciphers));
		/* load available cipher list */
		if (SSL_CTX_set_cipher_list(cn->ctx, cn->ciphers) == 0) {
			rc = ssl_error(MIG_ERR_SSL, "SSL_CTX_set_cipher_list()");
			goto cleanup_1;
		}
	}
	if (SSL_CTX_check_private_key(cn->ctx) != 1) {
		rc = ssl_error(MIG_ERR_SSL, "SSL_CTX_check_private_key()");
		goto cleanup_1;
	}
//	mode = SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT|SSL_VERIFY_CLIENT_ONCE;
	mode = SSL_VERIFY_NONE;
	SSL_CTX_set_verify(cn->ctx, mode, NULL);

	/* Create a socket and connect to server using normal socket calls. */
	if ((cn->sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		rc = putErr(MIG_ERR_SYSTEM, "socket() : %m");
		goto cleanup_1;
	}

	/* Default connection timeount is 3 min, will use this value */
/* TODO : custom connection timeout */
	if (connect(cn->sock, (struct sockaddr *)&addr, sizeof(addr))) {
		if (errno == ECONNREFUSED)
			rc = MIG_ERR_CONN_REFUSED;
		else
			rc = putErr(MIG_ERR_SYSTEM, "connect() : %m");
		goto cleanup_2;
	}

	/* Create SSL obj */
	if ((cn->ssl = SSL_new(cn->ctx)) == NULL) {
		rc = ssl_error(MIG_ERR_SSL, "SSL_new()");
		goto cleanup_2;
	}
	SSL_set_fd(cn->ssl, cn->sock);
	SSL_set_mode(cn->ssl, SSL_MODE_AUTO_RETRY);

	if ((rc = do_nonblock(cn->sock)))
		goto cleanup_3;

	while (1) {
		if ((retcode = SSL_connect(cn->ssl)) > 0)
			break;
		err = SSL_get_error(cn->ssl, retcode);
		if (err == SSL_ERROR_SYSCALL) {
			if (retcode == 0)
				rc = putErr(MIG_ERR_CONN_BROKEN,
					"SSL_connect() : unexpected EOF");
			else if (errno == EINTR)
				continue;
			else
				rc = putErr(MIG_ERR_CONN_BROKEN,
					"SSL_connect() : %m");
			goto cleanup_3;
		} else if ((err != SSL_ERROR_WANT_WRITE) && \
			(err != SSL_ERROR_WANT_READ) && \
			(err != SSL_ERROR_WANT_CONNECT))
		{
			/*
			http://www.openssl.org/docs/ssl/SSL_get_error.html#,
			man SSL_get_error
			SSL_ERROR_WANT_ACCEPT
			SSL_ERROR_WANT_X509_LOOKUP
			SSL_ERROR_ZERO_RETURN
			SSL_ERROR_SSL
			*/
			rc = ssl_error(MIG_ERR_SSL, "SSL_connect()");
			goto cleanup_3;
		}
		if ((rc = ssl_select(cn->sock, err, io_timeout)))
			goto cleanup_3;
	}

	/* check client sertificate */
	result = SSL_get_verify_result(cn->ssl);
	if ((result != X509_V_OK) &&
			(result != X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT)) {
		rc = putErr(MIG_ERR_SSL, "Certificate verification error: "\
			"%ld. See verify man page for more info", result);
		goto cleanup_4;
	}

	*conn = cn;
	logger(LOG_DEBUG, "Connection established");
	return 0;

cleanup_4:
	SSL_shutdown(cn->ssl);
cleanup_3:
	SSL_free(cn->ssl);
cleanup_2:
	close(cn->sock);
cleanup_1:
	SSL_CTX_free(cn->ctx);
cleanup_0:
	free((void *)cn);

	return rc;
}

/* init ssl server */
int ssl_srv_init(
		const char * certificate,
		const char * privatekey,
		const char * ciphers,
		struct ssl_conn **conn)
{
	int rc;
	struct ssl_conn *cn;
	struct sockaddr_in srv;
	int mode;

	if ((cn = (struct ssl_conn *)malloc(sizeof(struct ssl_conn))) == NULL)
		return putErr(MIG_ERR_SYSTEM, "malloc() : %m");
	ssl_init(cn);
	if (strlen(certificate))
		strncpy(cn->crtfile, certificate, sizeof(cn->crtfile));
	else
		strncpy(cn->crtfile, DEF_CRTFILE, sizeof(cn->crtfile));
	if (strlen(privatekey))
		strncpy(cn->keyfile, privatekey, sizeof(cn->keyfile));
	else
		strncpy(cn->keyfile, DEF_KEYFILE, sizeof(cn->keyfile));

	/* Set up the library */
	SSL_library_init();
	SSL_load_error_strings();

	/* Create SSL context (framework) */
	if ((cn->ctx = SSL_CTX_new(SSLv23_server_method())) == NULL) {
		rc = ssl_error(MIG_ERR_SSL, "SSL_CTX_new()");
		goto cleanup_0;
	}

	/* load certificat from file */
	if(SSL_CTX_use_certificate_file(cn->ctx, cn->crtfile, SSL_FILETYPE_PEM) != 1) {
		rc = ssl_error(MIG_ERR_SSL, "SSL_CTX_use_certificate_file()");
		goto cleanup_1;
	}
	if(SSL_CTX_use_PrivateKey_file(cn->ctx, cn->keyfile, SSL_FILETYPE_PEM) != 1) {
		rc = ssl_error(MIG_ERR_SSL, "SSL_CTX_use_PrivateKey_file()");
		goto cleanup_1;
	}
	if (strlen(ciphers)) {
		/* load available cipher list */
		strncpy(cn->ciphers, ciphers, sizeof(cn->ciphers));
		if (SSL_CTX_set_cipher_list(cn->ctx, cn->ciphers) == 0) {
			rc = ssl_error(MIG_ERR_SSL, "SSL_CTX_set_cipher_list()");
			goto cleanup_1;
		}
	}
	if (SSL_CTX_check_private_key(cn->ctx) != 1) {
		rc = ssl_error(MIG_ERR_SSL, "SSL_CTX_check_private_key()");
		goto cleanup_0;
	}
//	mode = SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT|SSL_VERIFY_CLIENT_ONCE;
	mode = SSL_VERIFY_NONE;
	SSL_CTX_set_verify(cn->ctx, mode, NULL);

	/* Prepare TCP socket for receiving connections */
	if ((cn->sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		rc = putErr(MIG_ERR_SYSTEM, "socket() : %m");
		goto cleanup_1;
	}

	srv.sin_family = AF_INET;
	srv.sin_addr.s_addr = INADDR_ANY;
	srv.sin_port = htons(VZMD_DEF_PORT);

	if (bind(cn->sock, (struct sockaddr *)&srv, sizeof(srv))) {
		rc = putErr(MIG_ERR_SYSTEM, "bind() : %m");
		goto cleanup_2;
	}

	if (listen(cn->sock, SOMAXCONN)) {
		rc = putErr(MIG_ERR_SYSTEM, "listen() : %m");
		goto cleanup_2;
	}

	*conn = cn;
	return 0;

cleanup_2:
	close(cn->sock);
cleanup_1:
	SSL_CTX_free(cn->ctx);
cleanup_0:
	free((void *)cn);

	return rc;
}

/* init ssl server connection */
int ssl_srv_conn_init(struct ssl_conn *srv, int sock, struct ssl_conn **conn)
{
	int rc;
	long result;
	struct ssl_conn *cn;
	int retcode, err;

	if ((cn = (struct ssl_conn *)malloc(sizeof(struct ssl_conn))) == NULL) {
		rc = putErr(MIG_ERR_SYSTEM, "malloc() : %m");
		goto cleanup_0;
	}

	cn->sock = sock;
	cn->ctx = srv->ctx;
	/* Create SSL obj */
	if ((cn->ssl = SSL_new(srv->ctx)) == NULL) {
		rc = ssl_error(MIG_ERR_SSL, "SSL_new()");
		goto cleanup_1;
	}
	SSL_set_fd(cn->ssl, cn->sock);
	SSL_set_mode(cn->ssl, SSL_MODE_AUTO_RETRY);

	if ((rc = do_nonblock(cn->sock)))
		goto cleanup_2;

	while (1) {
		if ((retcode = SSL_accept(cn->ssl)) > 0)
			break;
		err = SSL_get_error(cn->ssl, retcode);
		if (err == SSL_ERROR_SYSCALL) {
			if (retcode == 0)
				rc = putErr(MIG_ERR_CONN_BROKEN,
					"SSL_accept() : unexpected EOF");
			else if (errno == EINTR)
				continue;
			else
				rc = putErr(MIG_ERR_CONN_BROKEN,
					"SSL_accept() : %m");
			goto cleanup_2;
		} else if ((err != SSL_ERROR_WANT_WRITE) && \
			(err != SSL_ERROR_WANT_READ) && \
			(err != SSL_ERROR_WANT_ACCEPT))
		{
			rc = ssl_error(MIG_ERR_SSL, "SSL_accept()");
			goto cleanup_2;
		}
		if ((rc = ssl_select(cn->sock, err, io_timeout)))
			goto cleanup_2;
	}

/* at really server does not check client certificate */
	/* check client sertificate */
	result = SSL_get_verify_result(cn->ssl);
	if ((result != X509_V_OK) &&
			(result != X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT)) {
		rc = putErr(MIG_ERR_SSL, "Certificate verification error: "\
			"%ld. See verify man page for more info", result);
		goto cleanup_3;
	}
	logger(LOG_DEBUG, "Connection established");
	logger(LOG_DEBUG, "SSL connection using %s", SSL_get_cipher(cn->ssl));

	*conn = cn;
	return 0;

cleanup_3:
	SSL_shutdown(cn->ssl);
cleanup_2:
	SSL_free(cn->ssl);
cleanup_1:
	free((void *)cn);
cleanup_0:
	close(sock);

	return rc;
}

/* is connected */
int ssl_is_connected(void *conn)
{
	struct ssl_conn *cn = (struct ssl_conn *)conn;
	return SSL_is_init_finished(cn->ssl);
}

/* Write <size> bytes of <data> in non-blocking <ssl> connection.
   We can't use putErr in this function because on server putErr will call
   ssl_write() to send error message to client side,
   also we can't use ssl_select */
static int ssl_write(SSL *ssl, long timeout, const char * data, size_t size)
{
	int rc;
	size_t sent;
	fd_set fds;
	struct timeval tv;
	int err;
	int sock;

	sock = SSL_get_fd(ssl);
	if (size == 0)
		return 0;
	sent = 0;
	while (1) {
		while (1) {
			rc = SSL_write(ssl, data + sent,
				(unsigned int)(size - sent));
			if (rc > 0) {
				sent += rc;
				if (sent >= size)
					return 0;
				continue;
			}
			err = SSL_get_error(ssl, rc);
			if (err == SSL_ERROR_SYSCALL) {
				if (rc == 0) {
					logger(LOG_ERR,
						"SSL_write() : unexpected EOF");
					return MIG_ERR_CONN_BROKEN;
				} else if (errno == EINTR) {
					continue;
				} else {
					logger(LOG_ERR,
						"SSL_write() : %m");
					return MIG_ERR_CONN_BROKEN;
				}
			} else if (	(err == SSL_ERROR_WANT_WRITE) || \
					(err == SSL_ERROR_WANT_READ)) {
				break;
			}
			return ssl_error(MIG_ERR_CONN_BROKEN, "SSL_write()");
		}
		do {
			FD_ZERO(&fds);
			FD_SET(sock, &fds);
			tv.tv_sec = timeout;
			tv.tv_usec = 0;
			if (err == SSL_ERROR_WANT_READ)
				rc = select(sock + 1, &fds, NULL, NULL, &tv);
			else
				rc = select(sock + 1, NULL, &fds, NULL, &tv);
			if (rc == 0) {
				logger(LOG_ERR,
					"timeout (%d sec)", timeout);
				return MIG_ERR_CONN_TIMEOUT;
			} else if (rc <= 0) {
				logger(LOG_ERR, "select() : %m");
				return MIG_ERR_CONN_BROKEN;
			}
		} while (!FD_ISSET(sock, &fds));
	}

	/* but we never should be here */
	return MIG_ERR_CONN_BROKEN;
}

/* send data via ssl connection */
int ssl_send(void *conn, const char * data, size_t size)
{
	struct ssl_conn *cn = (struct ssl_conn *)conn;

	return ssl_write(cn->ssl, io_timeout, data, size);
}

/*
  read from ssl connection string, separated by <separator>.
  will write '\0' on the end of string
*/
int ssl_recv_str(void *conn, char separator, char *data, size_t size)
{
	int rc;
	char * p;
	fd_set fds;
	struct timeval tv;
	int err;
	struct ssl_conn *cn = (struct ssl_conn *)conn;

	p = data;
	while (1) {
		/* read data */
		while (1) {
			rc = SSL_read(cn->ssl, p, 1);
			if (rc > 0) {
				if (*p == separator) {
					*p = '\0';
					return 0;
				}
				p++;
				if (p >= data + size)
					return putErr(MIG_ERR_CONN_TOOLONG,
						"%s : too long message",
						__FUNCTION__);
				continue;
			}
			err = SSL_get_error(cn->ssl, rc);
			if (err == SSL_ERROR_SYSCALL) {
				if (rc == 0)
					return putErr(MIG_ERR_CONN_BROKEN,
						"SSL_read() : unexpected EOF");
				else if (errno == EINTR)
					continue;
				else
					return putErr(MIG_ERR_CONN_BROKEN,
						"SSL_read() : %m");
			} else if ((err == SSL_ERROR_WANT_WRITE) || \
				(err == SSL_ERROR_WANT_READ))
			{
				/* to select */
				break;
			}
			return ssl_error(MIG_ERR_CONN_BROKEN, "SSL_read()");
		}
		if ((rc = ssl_select(cn->sock, err, io_timeout)))
			return rc;
	}

	/* but we never should be here */
	return MIG_ERR_CONN_BROKEN;
}

/* redirect stdout to ssl, ssl to stdin */
static int ssl_redirect(
		SSL *ssl,
		int in,
		int out,
		int err,
		long timeout)
{
	int rc;
	struct timeval tv;
	char buffer[BUFSIZ + 1];
	int sock;
	fd_set rd_set, wr_set;
	int fdmax;
	int num, errcode;
	char *str, *token;

	char pipe_buff[BUFFSIZE]; /* Pipe read buffer */
	char ssl_buff[BUFFSIZE]; /* SSL read buffer */
	int pipe_ptr, ssl_ptr; /* Index of first unused byte in buffer */
	int pipe_bytes, ssl_bytes; /* Bytes written to pipe and ssl */
	int pipe_rd, pipe_wr, ssl_rd, ssl_wr;
	int check_SSL_pending;

	sock = SSL_get_fd(ssl);

	do_nonblock(out);
	do_nonblock(err);
	do_nonblock(sock);
	do_nonblock(in);
	fdmax = (out > err) ? out : err;
	fdmax = (fdmax > sock) ? fdmax : sock;
	fdmax = (fdmax > in) ? fdmax : in;

	pipe_ptr = ssl_ptr = 0;
	pipe_rd = pipe_wr = ssl_rd = ssl_wr = 1;
	pipe_bytes = ssl_bytes = 0;

	while (((pipe_rd || pipe_ptr) && ssl_wr) || ((ssl_rd || ssl_ptr) && pipe_wr)) {

		FD_ZERO(&rd_set); /* Setup rd_set */
		if (pipe_rd && (pipe_ptr < BUFFSIZE)) /* pipe input buffer not full*/
			FD_SET(out, &rd_set);
		if (ssl_rd && ((ssl_ptr < BUFFSIZE) || /* SSL input buffer not full */
			(pipe_ptr && SSL_want_read(ssl))
			/* I want to SSL_write but read from the underlying */
			/* socket needed for the SSL protocol */
			)) {
			FD_SET(sock, &rd_set);
		}
		if (err != -1)
			FD_SET(err, &rd_set);

		FD_ZERO(&wr_set); /* Setup wr_set */
		if (pipe_wr && ssl_ptr) /* SSL input buffer not empty */
			FD_SET(in, &wr_set);
		if (ssl_wr && (pipe_ptr || /* pipe input buffer not empty */
			((ssl_ptr < BUFFSIZE) && SSL_want_write(ssl))
			/* I want to SSL_read but write to the underlying */
			/* socket needed for the SSL protocol */
			)) {
			FD_SET(sock, &wr_set);
		}

		tv.tv_sec = timeout;
		tv.tv_usec = 0;
		while ((rc = select(fdmax + 1, &rd_set, &wr_set, NULL, &tv)) == -1)
			if (errno != EINTR)
				break;
		if (rc == 0) {
			return putErr(MIG_ERR_CONN_TIMEOUT,
				"timeout exceeded (%d sec)", io_timeout);
		} else if (rc <= 0) {
			return putErr(MIG_ERR_CONN_BROKEN, "select() : %m");
		}

		/* Set flag to try and read any buffered SSL data if we made */
		/* room in the buffer by writing to the pipe */
		check_SSL_pending = 0;

		if (pipe_wr && FD_ISSET(in, &wr_set)) {
			switch(num = write(in, ssl_buff, ssl_ptr)) {
			case -1: /* error */
				switch(errno) {
				case EINTR:
				case EAGAIN:
					break;
				default:
					return putErr(MIG_ERR_CONN_BROKEN,
						"write() : %m");
				}
				break;
			case 0:
				/* No data written to the socket: retrying */
				break;
			default:
				memmove(ssl_buff, ssl_buff+num, ssl_ptr-num);
				if(ssl_ptr==BUFFSIZE)
					check_SSL_pending=1;
				ssl_ptr -= num;
				pipe_bytes += num;
				if ((ssl_rd == 0) && (ssl_ptr == 0)) {
					close(in);
					logger(LOG_DEBUG,
						"Pipe write shutdown "
						"(no more data to send)");
					pipe_wr = 0;
				}
			}
		}

		if (ssl_wr && ( /* SSL sockets are still open */
			(pipe_ptr && FD_ISSET(sock, &wr_set)) ||
			/* See if application data can be written */
			(SSL_want_read(ssl) && FD_ISSET(sock, &rd_set))
			/* I want to SSL_write but read from the underlying */
			/* socket needed for the SSL protocol */
			)) {
			num = SSL_write(ssl, pipe_buff, pipe_ptr);

			errcode = SSL_get_error(ssl, num);
			switch(errcode) {
			case SSL_ERROR_NONE:
				memmove(pipe_buff, pipe_buff+num, pipe_ptr-num);
				pipe_ptr -= num;
				ssl_bytes += num;
				/* if pipe reading already closed and pipe
				   buffer is empty, close ssl writing */
				if ((pipe_rd == 0) && (pipe_ptr == 0) && ssl_wr){
					SSL_shutdown(ssl); /* Send close_notify */
					logger(LOG_DEBUG,
						"SSL write shutdown "
						"(no more data to send)");
					ssl_wr = 0;
				}
				break;
			case SSL_ERROR_WANT_WRITE:
			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_X509_LOOKUP:
				break;
			case SSL_ERROR_SYSCALL:
				if (num < 0) { /* really an error */
					if (errno == EINTR)
						break;
					return putErr(MIG_ERR_CONN_BROKEN,
						"SSL_write() : %m");
				}
				break;
			case SSL_ERROR_ZERO_RETURN: /* close_notify received */
				logger(LOG_DEBUG,
					"connection closed on SSL_write()");
				ssl_rd = ssl_wr = 0;
				break;
			case SSL_ERROR_SSL:
			default:
				return ssl_error(MIG_ERR_SSL, "SSL_write()");
			}
		}

		if (pipe_rd && FD_ISSET(out, &rd_set)) {
			num = read(out, pipe_buff+pipe_ptr,
				sizeof(pipe_buff)-pipe_ptr);
			switch (num) {
			case -1:
				switch(errno) {
				case EINTR:
				case EAGAIN:
					break;
				default:
					return putErr(MIG_ERR_CONN_BROKEN,
						"read() : %m");
				}
				break;
			case 0: /* close */
				logger(LOG_DEBUG, "Pipe closed on read");
				pipe_rd = 0;
				/* if pipe buffer is empty, close ssl writing */
				if ((pipe_ptr == 0) && ssl_wr) {
					SSL_shutdown(ssl); /* Send close_notify */
					logger(LOG_DEBUG,
						"SSL write shutdown "
						"(output buffer empty)");
					ssl_wr = 0;
				}
				break;
			default:
				pipe_ptr += num;
			}
		}

		if (ssl_rd && ( /* SSL sockets are still open */
			((ssl_ptr < BUFFSIZE) && FD_ISSET(sock, &rd_set)) ||
			/* See if there's any application data coming in */
			(SSL_want_write(ssl) && FD_ISSET(sock, &wr_set)) ||
			/* I want to SSL_read but write to the underlying */
			/* socket needed for the SSL protocol */
			(check_SSL_pending && SSL_pending(ssl))
			/* Write made space from full buffer */
			)) {
			num = SSL_read(ssl, ssl_buff+ssl_ptr,
				sizeof(ssl_buff)-ssl_ptr);

			errcode = SSL_get_error(ssl, num);
			switch(errcode) {
			case SSL_ERROR_NONE:
				ssl_ptr += num;
				break;
			case SSL_ERROR_WANT_WRITE:
			case SSL_ERROR_WANT_READ:
			case SSL_ERROR_WANT_X509_LOOKUP:
				break;
			case SSL_ERROR_SYSCALL:
				if (num < 0) { /* not EOF */
					if (errno == EINTR)
						break;
					return putErr(MIG_ERR_CONN_BROKEN,
						"SSL_read() : %m");
				}
				logger(LOG_DEBUG, "SSL_read() : EOF");
				ssl_rd = ssl_wr = 0;
				break;
			case SSL_ERROR_ZERO_RETURN: /* close_notify received */
				logger(LOG_DEBUG,
					"connection closed on SSL_read()");
				ssl_rd = 0;
				if ((pipe_ptr == 0) && ssl_wr) {
					SSL_shutdown(ssl); /* Send close_notify back */
					logger(LOG_DEBUG,
						"SSL write shutdown "
						"(output buffer empty)");
					ssl_wr = 0;
				}
				if((ssl_ptr == 0) && pipe_wr) {
					close(in);
					logger(LOG_DEBUG,
						"Pipe write shutdown "
						"(output buffer empty)");
					pipe_wr = 0;
				}
				break;
			case SSL_ERROR_SSL:
			default:
				return ssl_error(MIG_ERR_SSL, "SSL_read()");
			}
		}

		if (FD_ISSET(err, &rd_set)) {
			/* logger */
			num = read(err, buffer, sizeof(buffer));
			switch (num) {
			case -1:
				switch(errno) {
				case EINTR:
				case EAGAIN:
					break;
				default:
					logger(LOG_ERR, "read(stderr) : %m");
				}
				break;
			case 0:
				break;
			default:
				buffer[num] = '\0';
				for (str = buffer; ;str = NULL) {
					if ((token = strtok(str, "\n")) == NULL)
						break;
					if (strlen(token) == 0)
						continue;
					logger(LOG_ERR, token);
				}
				break;
			}
		}
	}
	logger(LOG_DEBUG, "pipe_bytes = %d, ssl_bytes = %d", pipe_bytes, ssl_bytes);
	return 0;
}

/* run args[], and transmit data from args[0] to ssl connection and vice versa */
int ssl_send_data(
		void *conn,
		unsigned long dst_addr,
		const char * cmd,
		char * const *args)
{
	int rc, retcode;
	int i;
	char *p;
	int in[2], out[2], err[2];
	char buffer[BUFSIZ+1];
	size_t size;
	struct sockaddr_in addr;
	int sock;
	SSL *ssl;
	pid_t pid, chpid;
	int status;
	struct ssl_conn *cn = (struct ssl_conn *)conn;

	if (debug_level >= LOG_DEBUG) {
		buffer[0] = '\0';
		for (i = 0; args[i]; i++) {
			strncat(buffer, args[i],
					sizeof(buffer)-strlen(buffer)-1);
			strncat(buffer, " ", sizeof(buffer)-strlen(buffer)-1);
		}
		logger(LOG_DEBUG, buffer);
	}

	addr.sin_addr.s_addr = dst_addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(VZMD_ADD_PORT);

	/* send command to dst */
	if ((rc = ssl_send(conn, cmd, strlen(cmd) + 1)))
		return rc;

	if ((rc = ch_read_retcode(ssl_recv_str, conn)))
		return rc;

	/* Create a socket and connect to server using normal socket calls. */
	if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
		return putErr(MIG_ERR_SYSTEM, "socket() : %m");

	/* Default connection timeount is 3 min, will use this value */
/* TODO : custom connection timeout */
	if (connect(sock, (struct sockaddr *)&addr, sizeof(addr))) {
		rc = putErr(MIG_ERR_SYSTEM, "connect() : %m");
		goto cleanup_0;
	}

	/* Create SSL obj */
	if ((ssl = SSL_new(cn->ctx)) == NULL) {
		rc = ssl_error(MIG_ERR_SSL, "SSL_new()");
		goto cleanup_0;
	}
	SSL_set_fd(ssl, sock);
	SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

	if ((rc = do_nonblock(sock)))
		goto cleanup_1;

	while (1) {
		if ((retcode = SSL_connect(ssl)) > 0)
			break;
		rc = SSL_get_error(ssl, retcode);
		if (rc == SSL_ERROR_SYSCALL) {
			if (retcode == 0)
				rc = putErr(MIG_ERR_CONN_BROKEN,
					"SSL_connect() : unexpected EOF");
			else if (errno == EINTR)
				continue;
			else
				rc = putErr(MIG_ERR_CONN_BROKEN,
					"SSL_connect() : %m");
			goto cleanup_1;
		} else if ((rc != SSL_ERROR_WANT_WRITE) && \
			(rc != SSL_ERROR_WANT_READ) && \
			(rc != SSL_ERROR_WANT_CONNECT))
		{
			rc = ssl_error(MIG_ERR_SSL, "SSL_connect()");
			goto cleanup_1;
		}
		if ((rc = ssl_select(sock, rc, io_timeout)))
			goto cleanup_1;
	}

	if ((pipe(in) < 0) || (pipe(out) < 0) || (pipe(err) < 0)) {
		rc = putErr(MIG_ERR_SYSTEM, "%s : pipe() : %m", __FUNCTION__);
		goto cleanup_2;
	}

	/* and wait reply */
	if ((rc = ch_read_retcode(ssl_recv_str, conn)))
		goto cleanup_4;

	/* run target task */
	if ((chpid = fork()) < 0) {
		rc = putErr(MIG_ERR_SYSTEM, "fork() : %m");
		goto cleanup_4;
	} else if (chpid == 0) {
		signal(SIGTERM, SIG_DFL);
		close(in[1]); close(out[0]); close(err[0]);
		dup2(in[0], STDIN_FILENO);
		dup2(out[1], STDOUT_FILENO);
		dup2(err[1], STDERR_FILENO);
		close(in[0]); close(out[1]); close(err[1]);
		execvp(args[0], args);
		exit(-MIG_ERR_SYSTEM);
	}
	close(in[0]); close(out[1]); close(err[1]);

	while ((pid = waitpid(chpid, &status, WNOHANG)) == -1)
		if (errno != EINTR)
			break;

	if (pid < 0) {
		rc = putErr(MIG_ERR_SYSTEM, "waitpid() error: %m");
		goto cleanup_3;
	} else if (pid == chpid) {
		rc = check_exit_status(args[0], status);
		goto cleanup_3;
	}

	if ((rc = ssl_redirect(ssl, in[1], out[0], err[0], io_timeout)))
		goto cleanup_3;

	while ((pid = waitpid(chpid, &status, 0)) == -1)
		if (errno != EINTR)
			break;

	close(in[1]); close(out[0]); close(err[0]);

	if (pid < 0) {
		rc = putErr(MIG_ERR_SYSTEM, "waitpid() error: %m");
		goto cleanup_2;
	}

	if ((rc = check_exit_status(args[0], status)))
		goto cleanup_2;

	/* send reply to server */
/*
DO NOT USE cmd
	if ((rc = ssl_send(conn, cmd, strlen(cmd) + 1)))
		goto cleanup_2;

	if ((rc = ch_read_retcode(ssl_recv_str, conn)))
		goto cleanup_2;
*/
	goto cleanup_2;
cleanup_4:
	close(in[0]); close(out[1]); close(err[1]);
cleanup_3:
	close(in[1]); close(out[0]); close(err[0]);
cleanup_2:
//	SSL_shutdown(ssl);
	rc = ssl_shutdown(ssl);
cleanup_1:
	SSL_free(ssl);
cleanup_0:
	close(sock);

	return rc;
}

/* to establish ssl server connection for existing ctx */
int ssl_recv_data(
		void *conn,
		char * const *args)
{
	int rc, retcode;
	struct sockaddr_in srv;
	struct sockaddr_in addr;
	int mode;
	fd_set fds;
	struct timeval tv;
	socklen_t addrsize;
	int srvsock, sock;
	SSL *ssl;
	time_t start;
	int in[2], out[2], err[2];
	char *reply = "|0|";
	char buffer[MAX_CMD_SIZE + 1];
	int i;
	pid_t pid, chpid;
	int status;
	int val;
	struct ssl_conn *cn = (struct ssl_conn *)conn;

	if (debug_level >= LOG_DEBUG) {
		buffer[0] = '\0';
		for (i = 0; args[i]; i++) {
			strncat(buffer, args[i],
					sizeof(buffer)-strlen(buffer)-1);
			strncat(buffer, " ", sizeof(buffer)-strlen(buffer)-1);
		}
		logger(LOG_DEBUG, buffer);
	}

	/* Create a socket and connect to server using normal socket calls. */
	if ((srvsock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
		return putErr(MIG_ERR_SYSTEM, "socket() : %m");

	srv.sin_family = AF_INET;
	srv.sin_addr.s_addr = INADDR_ANY;
	srv.sin_port = htons(VZMD_ADD_PORT);

 	val = 1;
 	setsockopt(srvsock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
	if (bind(srvsock, (struct sockaddr *)&srv, sizeof(srv))) {
		rc = putErr(MIG_ERR_SYSTEM, "bind() : %m");
		goto cleanup_0;
	}

	/* since vzmd use one port for all additional connection,
	   we can get EADDRINUSE for this port. Will try to listen
	   during timeout */
	start = time(NULL);
	while (1) {
		if (listen(srvsock, SOMAXCONN) == 0)
			break;

		if (errno != EADDRINUSE) {
			rc = putErr(MIG_ERR_SYSTEM, "listen() : %m");
			goto cleanup_0;
		}
		if (time(NULL) - start >= io_timeout) {
			rc = putErr(MIG_ERR_CONN_TIMEOUT,
				"timeout (%d sec)", io_timeout);
			goto cleanup_0;
		}
		sleep(1);
	}

	if ((rc = do_nonblock(srvsock)))
		goto cleanup_0;

	/* first syncronization */
	if ((rc = ssl_send(conn, reply, strlen(reply) + 1)))
		goto cleanup_0;

	while(1) {
		addrsize = sizeof(addr);
		if ((sock = accept(srvsock,
				(struct sockaddr *)&addr, &addrsize)) >= 0)
			break;
		if (errno == EINTR) {
			continue;
		} else if ((errno != EAGAIN) && (errno != EWOULDBLOCK)) {
			rc = putErr(MIG_ERR_SYSTEM, "accept() : %m");
			goto cleanup_0;
		}

		do {
			FD_ZERO(&fds);
			FD_SET(srvsock, &fds);
			tv.tv_sec = io_timeout;
			tv.tv_usec = 0;
			rc = select(srvsock + 1, &fds, NULL, NULL, &tv);
			if (rc == 0) {
				rc = putErr(MIG_ERR_CONN_TIMEOUT,
					"timeout (%d sec)", io_timeout);
				goto cleanup_0;
			} else if (rc <= 0) {
				rc = putErr(MIG_ERR_CONN_BROKEN,
					"select() : %m");
				goto cleanup_0;
			}
		} while (!FD_ISSET(srvsock, &fds));
	}

	/* Create SSL obj */
	if ((ssl = SSL_new(cn->ctx)) == NULL) {
		rc = ssl_error(MIG_ERR_SSL, "SSL_new()");
		goto cleanup_1;
	}
	SSL_set_fd(ssl, sock);
	SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

	if ((rc = do_nonblock(sock)))
		goto cleanup_2;

	while (1) {
		if ((retcode = SSL_accept(ssl)) > 0)
			break;
		rc = SSL_get_error(ssl, retcode);
		if (rc == SSL_ERROR_SYSCALL) {
			if (retcode == 0)
				rc = putErr(MIG_ERR_CONN_BROKEN,
					"SSL_accept() : unexpected EOF");
			else if (errno == EINTR)
				continue;
			else
				rc = putErr(MIG_ERR_CONN_BROKEN,
					"SSL_accept() : %m");
			goto cleanup_2;
		} else if ((rc != SSL_ERROR_WANT_WRITE) && \
			(rc != SSL_ERROR_WANT_READ) && \
			(rc != SSL_ERROR_WANT_ACCEPT))
		{
			rc = ssl_error(MIG_ERR_SSL, "SSL_accept()");
			goto cleanup_2;
		}
		if ((rc = ssl_select(sock, rc, io_timeout)))
			goto cleanup_2;
	}

	if ((pipe(in) < 0) || (pipe(out) < 0) || (pipe(err) < 0)) {
		rc = putErr(MIG_ERR_SYSTEM, "pipe() error, %m");
		goto cleanup_3;
	}

	/* send readiness reply */
	if ((rc = ssl_send(conn, reply, strlen(reply) + 1)))
		goto cleanup_5;

	/* run target task */
	if ((chpid = fork()) < 0) {
		rc = putErr(MIG_ERR_SYSTEM, "fork() : %m");
		goto cleanup_5;
	} else if (chpid == 0) {
		signal(SIGTERM, SIG_DFL);
		close(in[1]); close(out[0]); close(err[0]);
		dup2(in[0], STDIN_FILENO);
		dup2(out[1], STDOUT_FILENO);
		dup2(err[1], STDERR_FILENO);
		close(in[0]); close(out[1]); close(err[1]);
		execvp(args[0], args);
		exit(-MIG_ERR_SYSTEM);
	}
	close(in[0]); close(out[1]); close(err[1]);

	while ((pid = waitpid(chpid, &status, WNOHANG)) == -1)
		if (errno != EINTR)
			break;

	if (pid < 0) {
		rc = putErr(MIG_ERR_SYSTEM, "waitpid() error: %m");
		goto cleanup_4;
	} else if (pid == chpid) {
		rc = check_exit_status(args[0], status);
		goto cleanup_4;
	}

	if ((rc = ssl_redirect(ssl, in[1], out[0], err[0], io_timeout)))
		goto cleanup_4;

	while ((pid = waitpid(chpid, &status, 0)) == -1)
		if (errno != EINTR)
			break;
	close(in[1]); close(out[0]); close(err[0]);

	if (pid < 0) {
		rc = putErr(MIG_ERR_SYSTEM, "waitpid() error: %m");
		goto cleanup_3;
	}

	if ((rc = check_exit_status(args[0], status)))
		goto cleanup_3;
/*
	if ((rc = ssl_recv_str(conn, '\0', buffer, sizeof(buffer))))
		goto cleanup_3;

	if ((rc = ssl_send(conn, reply, strlen(reply) + 1)))
		goto cleanup_3;
*/
	goto cleanup_3;
cleanup_5:
	close(in[0]); close(out[1]); close(err[1]);
cleanup_4:
	close(in[1]); close(out[0]); close(err[0]);
cleanup_3:
	SSL_shutdown(ssl);
cleanup_2:
	SSL_free(ssl);
cleanup_1:
	close(sock);
cleanup_0:
	close(srvsock);

	return rc;
}

int ssl_recv_data2(
		void *conn,
		char * const *args,
		const char *dst,
		long timeout)
{
	return ssl_recv_data(conn, args);
}


/* create swap channel in background */
int ssl_start_swap_cli(
		void *conn,
		const char *addr,
		const char *src_bin,
		const char *dst_bin,
		unsigned src_veid,
		unsigned dst_veid,
		void **wcn)
{
	int rc, retcode;
	int i;
	char *p;
	int in[2], out[2], err[2];
	char buffer[BUFSIZ+1];
	size_t size;
	struct sockaddr_in saddr;
	int sock;
	pid_t pid, vpid, tpid;
	int status;
	SSL *ssl;
	struct ssl_swap_conn *cn;
	unsigned long dst_addr;
	char veid_str[ITOA_BUF_SIZE];
	char in_str[ITOA_BUF_SIZE];
	char out_str[ITOA_BUF_SIZE];
	char * const args[] =
		{(char *)src_bin, veid_str, in_str, out_str, NULL};
	struct ssl_conn *srv = (struct ssl_conn *)conn;

	if ((dst_addr = inet_addr(addr)) == INADDR_NONE) {
		/* need to resolve address */
		struct hostent *host;
		if ((host = gethostbyname(addr)) == NULL) {
			return putErr(MIG_ERR_SYSTEM,
				"gethostbyname(%s) err : %m", addr);
		}
		memcpy(&addr, host->h_addr, sizeof(addr));
	}
	saddr.sin_addr.s_addr = dst_addr;
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(VZMD_ADD_PORT);

	snprintf(buffer, sizeof(buffer), "%s %d", dst_bin, dst_veid);
	logger(LOG_DEBUG, "establish ssl swap channel: %s", buffer);
	/* send command to dst */
	if ((rc = ssl_send(conn, buffer, strlen(buffer) + 1)))
		return rc;

	if ((rc = ch_read_retcode(ssl_recv_str, conn)))
		return rc;

	if ((cn = (struct ssl_swap_conn *)malloc(sizeof(struct ssl_conn))) == NULL)
		return putErr(MIG_ERR_SYSTEM, "malloc() : %m");

	/* Create a socket and connect to server using normal socket calls. */
	if ((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		rc = putErr(MIG_ERR_SYSTEM, "socket() : %m");
		goto cleanup_0;
	}

	/* Default connection timeount is 3 min, will use this value */
/* TODO : custom connection timeout */
	if (connect(sock, (struct sockaddr *)&saddr, sizeof(saddr))) {
		rc = putErr(MIG_ERR_SYSTEM, "connect() : %m");
		goto cleanup_1;
	}

	if ((rc = do_nonblock(sock)))
		goto cleanup_1;

	/* Create SSL obj */
	if ((ssl = SSL_new(srv->ctx)) == NULL) {
		rc = ssl_error(MIG_ERR_SSL, "SSL_new()");
		goto cleanup_1;
	}
	SSL_set_fd(ssl, sock);
	SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

	while (1) {
		if ((retcode = SSL_connect(ssl)) > 0)
			break;
		rc = SSL_get_error(ssl, retcode);
		if (rc == SSL_ERROR_SYSCALL) {
			if (retcode == 0)
				rc = putErr(MIG_ERR_CONN_BROKEN,
					"SSL_connect() : unexpected EOF");
			else if (errno == EINTR)
				continue;
			else
				rc = putErr(MIG_ERR_CONN_BROKEN,
					"SSL_connect() : %m");
			goto cleanup_2;
		} else if ((rc != SSL_ERROR_WANT_WRITE) && \
			(rc != SSL_ERROR_WANT_READ) && \
			(rc != SSL_ERROR_WANT_CONNECT))
		{
			rc = ssl_error(MIG_ERR_SSL, "SSL_connect()");
			goto cleanup_2;
		}
		if ((rc = ssl_select(sock, rc, io_timeout)))
			goto cleanup_2;
	}

	if ((pipe(in) < 0) || (pipe(out) < 0) || (pipe(err) < 0)) {
		rc = putErr(MIG_ERR_SYSTEM, "pipe() : %m");
		goto cleanup_3;
	}

	/* and wait reply */
	if ((rc = ch_read_retcode(ssl_recv_str, conn)))
		goto cleanup_5;

	if ((tpid = fork()) < 0) {
		rc = putErr(MIG_ERR_SYSTEM, "fork() : %m");
		goto cleanup_5;
	} else if (tpid == 0) {
		char buffer[BUFSIZ];

		close(in[0]); close(out[1]); close(err[1]);

		/* read reply from channel */
		if ((rc = ssl_recv_str(cn, '\n', buffer, sizeof(buffer))))
			exit(-rc);
		if (strcmp(buffer, "OK")) {
			logger(LOG_ERR, "%s", buffer);
			rc = putErr(MIG_ERR_CANT_CONNECT, MIG_MSG_CANT_CONNECT);
			exit(-rc);
		}

		rc = ssl_redirect(ssl, in[1], out[0], err[0], io_timeout);
		exit(-rc);
	}
	close(in[1]); close(out[0]); close(err[0]);

	while ((pid = waitpid(tpid, &status, WNOHANG)) == -1)
		if (errno != EINTR)
			break;

	if (pid < 0) {
		rc = putErr(MIG_ERR_SYSTEM, "waitpid() error: %m");
		goto cleanup_5;
	}

	if (fcntl(in[0], F_SETFD, ~FD_CLOEXEC)) {
		rc = putErr(MIG_ERR_SYSTEM, "fcntl() : %m");
		goto cleanup_6;
	}
	if (fcntl(out[1], F_SETFD, ~FD_CLOEXEC)) {
		rc = putErr(MIG_ERR_SYSTEM, "fcntl() : %m");
		goto cleanup_6;
	}

 	snprintf(veid_str, sizeof(veid_str), "%u", src_veid);
 	snprintf(in_str, sizeof(in), "%u", in[0]);
 	snprintf(out_str, sizeof(out), "%u", out[1]);

	if ((rc = vzm_execve(args, NULL, -1, -1, NULL)))
		goto cleanup_6;

	cn->sock = sock;
	cn->ssl = ssl;
	cn->in = in[0];
	cn->out = out[1];
	cn->pid = tpid;
	*wcn = cn;

	return 0;

cleanup_6:
	write(cn->out, "Closed", strlen("Closed")+1);
//	close(cn->in);
	close(cn->out);
	/* TODO: wait tmo in waitpid and kill(SIGTERM, tpid); in failure */
cleanup_5:
	close(in[1]); close(out[0]); close(err[0]);
cleanup_4:
	close(in[0]); close(out[1]); close(err[1]);
cleanup_3:
	SSL_shutdown(ssl);
cleanup_2:
	SSL_free(ssl);
cleanup_1:
	close(sock);
cleanup_0:
	free((void *)cn);

	return rc;
}

/* close swap channel */
void ssl_swap_close(void *conn)
{
	struct ssl_swap_conn *cn = (struct ssl_swap_conn *)conn;

	if (kill(cn->pid, 0))
		if (errno == ESRCH)
			return;
	if (cn->out != -1) {
		write(cn->out, "Closed", strlen("Closed")+1);
		close(cn->out);
		cn->out = -1;
	}
//	close(cn->in);
	/* TODO: wait tmo in waitpid and kill(SIGTERM, cn->pid); in failure */
}

/* start swap server in background */
int ssl_start_swap_srv(void *conn, char * const *args)
{
	int rc, retcode;
	struct sockaddr_in srv;
	struct sockaddr_in addr;
	int mode;
	fd_set fds;
	struct timeval tv;
	socklen_t addrsize;
	int srvsock, sock;
	SSL *ssl;
	time_t start;
	int in[2], out[2], err[2];
	char *reply = "|0|";
	char buffer[MAX_CMD_SIZE + 1];
	int i;
	pid_t pid, vpid, tpid;
	int status;
	int val;
	struct ssl_conn *cn = (struct ssl_conn *)conn;

	/* Create a socket and connect to server using normal socket calls. */
	if ((srvsock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1)
		return putErr(MIG_ERR_SYSTEM, "socket() : %m");

	srv.sin_family = AF_INET;
	srv.sin_addr.s_addr = INADDR_ANY;
	srv.sin_port = htons(VZMD_ADD_PORT);

 	val = 1;
 	setsockopt(srvsock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
	if (bind(srvsock, (struct sockaddr *)&srv, sizeof(srv))) {
		rc = putErr(MIG_ERR_SYSTEM, "bind() : %m");
		goto cleanup_0;
	}

	/* since vzmd use one port for all additional connection,
	   we can get EADDRINUSE for this port. Will try to listen
	   during timeout */
	start = time(NULL);
	while (1) {
		if (listen(srvsock, SOMAXCONN) == 0)
			break;

		if (errno != EADDRINUSE) {
			rc = putErr(MIG_ERR_SYSTEM, "listen() : %m");
			goto cleanup_0;
		}
		if (time(NULL) - start >= io_timeout) {
			rc = putErr(MIG_ERR_CONN_TIMEOUT,
				"timeout (%d sec)", io_timeout);
			goto cleanup_0;
		}
/* TODO : use select()? */
		sleep(1);
	}

	if ((rc = do_nonblock(srvsock)))
		goto cleanup_0;

	/* first syncronization */
	if ((rc = ssl_send(conn, reply, strlen(reply) + 1)))
		goto cleanup_0;

	while(1) {
		addrsize = sizeof(addr);
		if ((sock = accept(srvsock,
				(struct sockaddr *)&addr, &addrsize)) >= 0)
			break;
		if (errno == EINTR) {
			continue;
		} else if ((errno != EAGAIN) && (errno != EWOULDBLOCK)) {
			rc = putErr(MIG_ERR_SYSTEM, "accept() : %m");
			goto cleanup_0;
		}

		do {
			FD_ZERO(&fds);
			FD_SET(srvsock, &fds);
			tv.tv_sec = io_timeout;
			tv.tv_usec = 0;
			rc = select(srvsock + 1, &fds, NULL, NULL, &tv);
			if (rc == 0) {
				rc = putErr(MIG_ERR_CONN_TIMEOUT,
					"timeout (%d sec)", io_timeout);
				goto cleanup_0;
			} else if (rc <= 0) {
				rc = putErr(MIG_ERR_CONN_BROKEN,
					"select() : %m");
				goto cleanup_0;
			}
		} while (!FD_ISSET(srvsock, &fds));
	}
	close(srvsock);

	if ((rc = do_nonblock(sock)))
		goto cleanup_1;

	if ((pipe(in) < 0) || (pipe(out) < 0) || (pipe(err) < 0)) {
		rc = putErr(MIG_ERR_SYSTEM, "pipe() error, %m");
		goto cleanup_1;
	}

	if ((vpid = fork()) < 0) {
		rc = putErr(MIG_ERR_SYSTEM, "fork() : %m");
		goto cleanup_3;
	} else if (vpid == 0) {
		close(in[1]); close(out[0]); close(err[0]);
		dup2(in[0], STDIN_FILENO);
		dup2(out[1], STDOUT_FILENO);
		dup2(err[1], STDERR_FILENO);
		close(in[0]); close(out[1]); close(err[1]);
		do_nonblock(STDOUT_FILENO);
		do_block(STDIN_FILENO);
		do_nonblock(STDERR_FILENO);
		execvp(args[0], args);
		exit(-MIG_ERR_SYSTEM);
	}
	close(in[0]); close(out[1]); close(err[1]);

	while ((pid = waitpid(vpid, &status, WNOHANG)) == -1)
		if (errno != EINTR)
			break;
	if (pid < 0) {
		rc = putErr(MIG_ERR_SYSTEM, "waitpid() error: %m");
		goto cleanup_3;
	}
	if (pid == vpid) {
		rc = check_exit_status(args[0], status);
		goto cleanup_3;
	}

	if ((tpid = fork()) < 0) {
		rc = putErr(MIG_ERR_SYSTEM, "fork() : %m");
		goto cleanup_4;
	} else if (tpid == 0) {
		SSL *ssl;

		close(in[0]); close(out[1]); close(err[1]);

		/* Create SSL obj */
		if ((ssl = SSL_new(cn->ctx)) == NULL) {
			rc = ssl_error(MIG_ERR_SSL, "SSL_new()");
			exit(-rc);
		}
		SSL_set_fd(ssl, sock);
		SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

		while (1) {
			if ((retcode = SSL_accept(ssl)) > 0)
				break;
			rc = SSL_get_error(ssl, retcode);
			if (rc == SSL_ERROR_SYSCALL) {
				if (retcode == 0)
					rc = putErr(MIG_ERR_CONN_BROKEN,
						"SSL_accept() : unexpected EOF");
				else if (errno == EINTR)
					continue;
				else
					rc = putErr(MIG_ERR_CONN_BROKEN,
						"SSL_accept() : %m");
				goto ch_cleanup_0;
			} else if ((rc != SSL_ERROR_WANT_WRITE) && \
				(rc != SSL_ERROR_WANT_READ) && \
				(rc != SSL_ERROR_WANT_ACCEPT))
			{
				rc = ssl_error(MIG_ERR_SSL, "SSL_accept()");
				goto ch_cleanup_0;
			}
			if ((rc = ssl_select(sock, rc, io_timeout)))
				goto ch_cleanup_0;
		}

		rc = ssl_redirect(ssl, in[1], out[0], err[0], io_timeout);
		SSL_shutdown(ssl);
ch_cleanup_0:
		SSL_free(ssl);
		exit(-rc);
	}
	close(in[1]); close(out[0]); close(err[0]);
	close(sock);

	while ((pid = waitpid(tpid, &status, WNOHANG)) == -1)
		if (errno != EINTR)
			break;

	if (pid < 0) {
		rc = putErr(MIG_ERR_SYSTEM, "waitpid() error: %m");
		goto cleanup_4;
	}
/* TODO : use signal pipe */
	/* send readiness reply */
	if ((rc = ssl_send(conn, reply, strlen(reply) + 1)))
		goto cleanup_4;

	return 0;

cleanup_4:
	kill(SIGTERM, vpid);
cleanup_3:
	close(in[0]); close(out[1]); close(err[1]);
cleanup_2:
	close(in[1]); close(out[0]); close(err[0]);
cleanup_1:
	close(sock);
cleanup_0:
	close(srvsock);

	return rc;
}
