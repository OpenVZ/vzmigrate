/*
 * Copyright (c) 2016-2017, Parallels International GmbH
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
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <asm/param.h>
#include <getopt.h>
#include <libgen.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "openssl/ssl.h"
#include "openssl/err.h"

char *ciphers = NULL;
size_t bufsize = 4096;
char *crtfile = NULL;
char *keyfile = NULL;

static void usage(const char * progname, int rc)
{
	fprintf(stderr,"Usage:\n");
	fprintf(stderr,"%s [-c cipher list] [-b bufsize] [-C certificate] [-K private key] host\n",
		progname);
	fprintf(stderr,"\tFor cipher list see man ciphers\n");
	exit(rc);
}

/* command line parsing */
int parse_cmd_line(int argc, char *argv[])
{
	int c;
	char *p;
	struct option options[] =
	{
		{"ciphers", required_argument, NULL, 'c'},
		{"bufsize", required_argument, NULL, 'b'},
		{"crtfile", required_argument, NULL, 'C'},
		{"keyfile", required_argument, NULL, 'K'},
		{ NULL, 0, NULL, 0 }
	};

	while (1)
	{
		c = getopt_long(argc, argv, "c:b:C:K:", options, NULL);
		if (c == -1)
			break;
		switch (c)
		{
		case 'c':
			if (optarg == NULL) {
				fprintf(stderr, "Bad cipher list");
				return 1;
			}
			if (strlen(optarg) == 0) {
				fprintf(stderr, "Bad cipher list");
				return 1;
			}
			if ((ciphers = strdup(optarg)) == NULL) {
				fprintf(stderr, "strdup() : %m");
				return 1;
			}
			break;
		case 'b':
			if (optarg == NULL) {
				fprintf(stderr, "Bad bufsize value");
				return 1;
			}
			if (strlen(optarg) == 0) {
				fprintf(stderr, "Bad bufsize value");
				return 1;
			}
			for(p=optarg; *p; p++) {
				if (!isdigit(*p)) {
					fprintf(stderr, "Bad bufsize: %s", optarg);
					return 1;
				}
			}
			bufsize = strtol(optarg, NULL, 10);
			break;
		case 'C':
			if (optarg == NULL) {
				fprintf(stderr, "Bad certificate");
				return 1;
			}
			if (strlen(optarg) == 0) {
				fprintf(stderr, "Bad certificate");
				return 1;
			}
			if ((crtfile = strdup(optarg)) == NULL) {
				fprintf(stderr, "strdup() : %m");
				return 1;
			}
			break;
		case 'K':
			if (optarg == NULL) {
				fprintf(stderr, "Bad private key");
				return 1;
			}
			if (strlen(optarg) == 0) {
				fprintf(stderr, "Bad private key");
				return 1;
			}
			if ((keyfile = strdup(optarg)) == NULL) {
				fprintf(stderr, "strdup() : %m");
				return 1;
			}
			break;
		default :
			return 1;
		}
	}

	return 0;
}

int main(int argc, char **argv)
{
	int rc = 0;
	SSL_METHOD *meth = NULL;
	SSL_CTX *ctx = NULL;
	SSL *ssl = NULL;
	X509 *client_cert = NULL;
	char *buf = NULL;
	int i, s;
	long res;
	int listen_sd, sd;
	struct sockaddr_in ca_serv;
	struct sockaddr_in ca_cli;
	int ca_cli_len;
	unsigned short port = 4422;
	int lcipher = 1;

	if (parse_cmd_line(argc, argv)) {
		usage(basename(argv[0]), 1);
	}

	if ((buf = malloc(bufsize)) == NULL) {
		fprintf(stderr, "malloc() : %m");
		return -1;
	}

	if (crtfile == NULL)
		crtfile = strdup("certificate.pem");
	if (keyfile == NULL)
		keyfile = strdup("private.key");
	if (ciphers)
		if (strcasecmp(ciphers, "none") == 0)
			lcipher = 0;

	SSL_library_init();
	SSL_load_error_strings();

	/* to create SSL context */
	meth = SSLv23_server_method();
	if ((ctx = SSL_CTX_new(meth)) == NULL) {
		fprintf(stderr, "SSL_CTX_new() : %m\n");
		ERR_print_errors_fp(stdout);
		rc = 1;
		goto cleanup_0;
	}

	/* load certificat from file */
	if(SSL_CTX_use_certificate_file(ctx, crtfile, SSL_FILETYPE_PEM) < 1) {
		ERR_print_errors_fp(stdout);
		rc = 1;
		goto cleanup_1;
	}
	if(SSL_CTX_use_PrivateKey_file(ctx, keyfile, SSL_FILETYPE_PEM) < 1) {
		ERR_print_errors_fp(stdout);
		rc = 1;
		goto cleanup_1;
	}
	if (ciphers) {
		if (strcasecmp(ciphers, "none")) {
			/* load available cipher list */
			if (SSL_CTX_set_cipher_list(ctx, ciphers) == 0) {
				fprintf(stderr, "Error loading cipher list\n");
				ERR_print_errors_fp(stderr);
				rc = 1;
				goto cleanup_1;
			}
		}
	}
	/* TODO: SSL_CTX_check_private_key(ctx) */
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
//		SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT|
//			SSL_VERIFY_CLIENT_ONCE, NULL);

	/* ----------------------------------------------- */
	/* Prepare TCP socket for receiving connections */
	if ((listen_sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		fprintf(stderr, "socket() : %m\n");
		rc = 1;
		goto cleanup_1;
	}

	ca_serv.sin_family = AF_INET;
	ca_serv.sin_addr.s_addr = INADDR_ANY;
	ca_serv.sin_port = htons(port);

	if (bind(listen_sd, (struct sockaddr *)&ca_serv, sizeof(ca_serv))) {
		fprintf(stderr, "bind() : %m\n");
		rc = 1;
		goto cleanup_2;
	}

	if (listen(listen_sd, SOMAXCONN)) {
		fprintf(stderr, "listen() : %m\n");
		rc = 1;
		goto cleanup_2;
	}

//	fcntl(sock, F_SETFL, fcntl(sock, F_GETFL)|O_NONBLOCK);
	ca_cli_len = sizeof(ca_cli);
	if ((sd = accept(listen_sd, (struct sockaddr *)&ca_cli, &ca_cli_len)) < 0) {
		fprintf(stderr, "accept() : %m\n");
		rc = 1;
		goto cleanup_2;
	}
	close(listen_sd);

	/* ----------------------------------------------- */
	/* Now we have TCP connection. Start SSL negotiation. */

	/* Create SSL obj */
	if ((ssl = SSL_new(ctx)) == NULL) {
		fprintf(stderr, "Error creating SSL object\n");
		ERR_print_errors_fp(stderr);
		rc = 1;
		goto cleanup_3;
	}

	SSL_set_fd(ssl, sd);
	SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

	/* try to connect */
	if(SSL_accept(ssl) <= 0) {
		fprintf(stderr, "SSL_accept() : %m\n");
		ERR_print_errors_fp(stderr);
		rc = 1;
		goto cleanup_4;
	}
	printf ("SSL connection using  %s\n", SSL_get_cipher(ssl));

	/* Get server's certificate. Note: dynamic allocation */
	if ((client_cert = SSL_get_peer_certificate(ssl)) == NULL) {
		fprintf(stderr, "Can't get peer certificate\n");
		ERR_print_errors_fp(stderr);
		rc = 1;
		goto cleanup_4;
	}
	X509_free(client_cert);

	res = SSL_get_verify_result(ssl);
	/* will use expired certificate for test */
	if (	(res != X509_V_OK) &&
		(res != X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) &&
		(res != X509_V_ERR_CERT_HAS_EXPIRED)) {
		fprintf(stderr, "Certificate verification error: %ld\n", res);
		fprintf(stderr, "See verify man page for more info\n");
		ERR_print_errors_fp(stderr);
		rc = 1;
		goto cleanup_2;
	}
	printf("Client certificate verified\n");

	s = 0;
	while (1) {
		if (lcipher)
			i = SSL_read(ssl, buf, bufsize);
		else
			i = read(sd, buf, bufsize);
		if (i <= 0)
			break;
		s += i;
	}
	if (i < 0) {
		fprintf(stderr, "read() : %m\n");
		rc = 1;
	}
	printf("%d bytes received\n", s);


cleanup_4:
	if (ssl)
		SSL_free(ssl);

cleanup_3:
	close(sd);

cleanup_2:
	close(listen_sd);

cleanup_1:
	if (ctx)
		SSL_CTX_free(ctx);

cleanup_0:
	if (buf)
		free(buf);

	return rc;
}

