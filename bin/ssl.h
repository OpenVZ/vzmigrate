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
 * Double-linked lists functions declarations
 */

#ifndef __SSL_H__
#define __SSL_H__

#include <openssl/ssl.h>
#include <openssl/err.h>

/*
 AFAIK there are free ports, according
 http://www.iana.org/assignments/port-numbers
*/
//#define VZMD_DEF_PORT "4422"
//#define VZMD_ADD_PORT "4423"

#define DEF_CRTFILE "/root/vzmigrate/cert.pem"
#define DEF_KEYFILE "/root/vzmigrate/key.pem"

/* see ERR_error_string man page */
#define SSL_ERR_STRING_MAXLEN 121

struct ssl_conn {
	SSL_CTX * ctx;
	char crtfile[PATH_MAX + 1];
	char keyfile[PATH_MAX + 1];
	char ciphers[BUFSIZ+1];
	int sock;
	SSL * ssl;
//	X509 *cert;
};

struct ssl_swap_conn {
	SSL * ssl;
	pid_t pid;
	int sock;
	int in;
	int out;
};

#ifdef __cplusplus
extern "C" {
#endif

int ssl_error(int code, const char *title);
void ssl_clean(struct ssl_conn *cn);
void ssl_srv_clean(struct ssl_conn *cn);

/* init ssl client */
int ssl_cli_conn_init(
		const char * dst_addr,
		const char * certificate,
		const char * privatekey,
		const char * ciphers,
		struct ssl_conn **conn);

/* init ssl server */
int ssl_srv_init(
		const char * certificate,
		const char * privatekey,
		const char * ciphers,
		struct ssl_conn **conn);

/* init ssl server connection */
int ssl_srv_conn_init(struct ssl_conn *srv, int sock, struct ssl_conn **conn);

/* send data via ssl connection */
int ssl_send(void *conn, const char * data, size_t size);

/*
  read from ssl connection string, separated by <separator>.
  will write '\0' on the end of string
*/
int ssl_recv_str(void *conn, char separator, char *data, size_t size);

int ssl_close(void *conn);

int ssl_is_connected(void *conn);

/* run args[], and transmit data from args[0] to ssl connection and vice versa */
int ssl_send_data(
		void *conn,
		unsigned long dst_addr,
		const char * cmd,
		char * const *args);

/* to establish ssl server connection for existing ctx */
int ssl_recv_data(
		void *conn,
		char * const *args);

int ssl_recv_data2(
		void *conn,
		char * const *args,
		const char *dst,
		long timeout);

/* create swap channel in background */
int ssl_start_swap_cli(
		void *conn,
		const char *addr,
		const char *src_bin,
		const char *dst_bin,
		unsigned src_veid,
		unsigned dst_veid,
		void **wcn);

void ssl_swap_close(void *conn);

int ssl_start_swap_srv(
		void *conn,
		char * const *args);

#ifdef __cplusplus
}
#endif

#endif
