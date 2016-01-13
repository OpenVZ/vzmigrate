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

/* TODO: O_NONBLOCK + timeout */

int main(int argc, char **argv)
{
	int rc = 0;
	SSL_METHOD *meth = NULL;
	SSL * ssl = NULL;
	SSL_CTX * ctx = NULL;
	X509 *server_cert = NULL;
	long res;
	int max_size = 813*1024*1024;
	int i, j;
	char *buf = NULL;
	char *srv;
	int sd;
	unsigned long addr;
	struct sockaddr_in saddr;
	unsigned short port = 4422;
	int lcipher = 1;

	if ( argc < 2 )
		usage(basename(argv[0]), 1);
	if (parse_cmd_line(argc, argv))
		usage(basename(argv[0]), 1);

	srv = argv[optind];
	if ((addr = inet_addr(srv)) == INADDR_NONE) {
		/* need to resolve address */
		struct hostent *host;
		if ((host = gethostbyname(srv)) == NULL) {
			fprintf(stderr, "gethostbyname(%s) err : %m\n", srv);
			return 1;
		}
		memcpy(&addr, host->h_addr, sizeof(addr));
	}

	if (crtfile == NULL)
		crtfile = strdup("certificate.pem");
	if (keyfile == NULL)
		keyfile = strdup("private.key");
	if (ciphers)
		if (strcasecmp(ciphers, "none") == 0)
			lcipher = 0;

	srand(time(NULL));

	/* Set up the library */
	SSL_library_init();
	SSL_load_error_strings();

	if ((buf = malloc(bufsize)) == NULL) {
		fprintf(stderr, "malloc() : %m");
		return 1;
	}

	/* Create SSL context (framework) */
	meth = SSLv23_client_method();
	if ((ctx = SSL_CTX_new(meth)) == NULL) {
		fprintf(stderr, "SSL_CTX_new() : %m\n");
		ERR_print_errors_fp(stderr);
		rc = 1;
		goto cleanup_0;
	}

	/* load certificat from file */
	if(SSL_CTX_use_certificate_file(ctx, crtfile, SSL_FILETYPE_PEM) < 1) {
		ERR_print_errors_fp(stderr);
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
	SSL_CTX_set_verify(ctx,
		SSL_VERIFY_NONE, NULL);
//		SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

	/* ----------------------------------------------- */
	/* Create a socket and connect to server using normal socket calls. */
	if ((sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		fprintf(stderr, "socket() err : %m\n");
		rc = 1;
		goto cleanup_1;
	}

	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = addr;
	saddr.sin_port = htons(port);

	if (connect(sd, (struct sockaddr *)&saddr, sizeof(saddr))) {
		// if (errno != EINPROGRESS) - for NONBLOCK
		fprintf(stderr, "connect() : %m\n");
		rc = 1;
		goto cleanup_1;
	}
	/* ----------------------------------------------- */
	/* Now we have TCP connection. Start SSL negotiation. */

	/* Create SSL obj */
	if ((ssl = SSL_new(ctx)) == NULL) {
		fprintf(stderr, "Error creating SSL object\n");
		ERR_print_errors_fp(stderr);
		rc = 1;
		goto cleanup_1;
	}

	SSL_set_fd(ssl, sd);
	SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

	/* try to connect */
	if(SSL_connect(ssl) <= 0) {
		fprintf(stderr, "Error attempting to connect\n");
		/* TODO SSL_get_error() */
		ERR_print_errors_fp(stderr);
		rc = 1;
		goto cleanup_2;
	}

	/* Get server's certificate. Note: dynamic allocation */
	if ((server_cert = SSL_get_peer_certificate(ssl)) == NULL) {
		fprintf(stderr, "Can't get peer certificate\n");
		ERR_print_errors_fp(stderr);
		rc = 1;
		goto cleanup_2;
	}

	X509_free(server_cert);

	/* verify the certificate
	From SSL_get_verify_result() man page:
	If no peer certificate was presented, the returned result code is
	X509_V_OK. This is because no verification error occurred, it does how-
	ever not indicate success. SSL_get_verify_result() is only useful in
	connection with SSL_get_peer_certificate(3).
	*/
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
	printf("Server certificate verified\n");

	i = 0;
	while (i < max_size) {
		for (j = 0; (j < bufsize) && (i < max_size); j++, i++) {
			buf[j] = (char) (255.0*rand()/(RAND_MAX+1.0));
		}
		if (lcipher)
			j = SSL_write(ssl, buf, j);
		else
			j = write(sd, buf, j);
		/* TODO: use SSL_get_fd */
		if (j <= 0) {
			fprintf(stderr, "write() error\n");
			ERR_print_errors_fp(stderr);
			rc = 1;
			break;
		}
	}
	printf("%d bytes wrote\n", i);
	SSL_shutdown(ssl);

	/* Close the connection and free the context */
cleanup_2:
	if (ssl)
		SSL_free(ssl);

cleanup_1:
	if (ctx)
		SSL_CTX_free(ctx);

cleanup_0:
	if (buf)
		free(buf);

	return rc;
}
