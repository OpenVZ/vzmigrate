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

#include "openssl/ssl.h"
#include "openssl/bio.h"
#include "openssl/err.h"


char *ciphers = NULL;
size_t bufsize = 4096;
char *crtfile = NULL;

static void usage(const char * progname, int rc)
{
	fprintf(stderr,"Usage:\n");
	fprintf(stderr,"%s [-c cipher list] [-b bufsize] [-C CAfile] host\n",
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
		{"CAfile", required_argument, NULL, 'C'},
		{ NULL, 0, NULL, 0 }
	};

	while (1)
	{
		c = getopt_long(argc, argv, "c:b:C:", options, NULL);
		if (c == -1)
			break;
		switch (c)
		{
		case 'p':
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
		default :
			return 1;
		}
	}

	return 0;
}


int main(int argc, char **argv, char **envp)
{
	int rc = 0;
	BIO * bio;
	SSL * ssl;
	SSL_CTX * ctx;
	long res;
	int max_size = 813*1024*1024;
	int i, j;
	char *buf = NULL;
	char srv[MAXHOSTNAMELEN+1];
	char *port = "4422";

	if ( argc < 2 ) {
		fprintf(stderr, "Usage: %s addr\n", argv[0]);
		exit(1);
	}
	if (parse_cmd_line(argc, argv)) {
		usage(basename(argv[0]), 1);
	}
	strncpy(srv, argv[optind], sizeof(srv));

	if (crtfile == NULL)
		crtfile = strdup("certificate.pem");

	srand(time(NULL));

	/* Set up the library */
	SSL_library_init();

	ERR_load_BIO_strings();
	SSL_load_error_strings();

	if ((buf = malloc(bufsize)) == NULL) {
		fprintf(stderr, "malloc() : %m");
		return 1;
	}

	/* Create SSL context (framework) */
	if ((ctx = SSL_CTX_new(SSLv23_client_method())) == NULL) {
		ERR_print_errors_fp(stderr);
		rc = 1;
		goto cleanup_0;
	}

	/* load certificat from file */
	if(SSL_CTX_use_certificate_file(ctx, crtfile,
			SSL_FILETYPE_PEM) < 1) {
		fprintf(stderr, "Error loading certificate %s\n", crtfile);
		ERR_print_errors_fp(stderr);
		rc = 1;
		goto cleanup_1;
	}
	if (ciphers) {
		/* load available cipher list */
		if (SSL_CTX_set_cipher_list(ctx, ciphers) == 0) {
			fprintf(stderr, "Error loading cipher list\n");
			ERR_print_errors_fp(stderr);
			rc = 1;
			goto cleanup_1;
		}
	}

	/* Create BIO wrapper for ssl */
	if ((bio = BIO_new_ssl_connect(ctx)) == NULL) {
		fprintf(stderr, "Error creating BIO object\n");
		ERR_print_errors_fp(stderr);
		rc = 1;
		goto cleanup_1;
	}

	/* get pointer to SSL obj, provides by bio */
	BIO_get_ssl(bio, &ssl);
	if(!ssl) {
		fprintf(stderr, "Can't locate SSL pointer\n");
		ERR_print_errors_fp(stderr);
		rc = 1;
		goto cleanup_2;
	}
	/* Set the SSL_MODE_AUTO_RETRY flag */
	SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

//	BIO_set_buffer_size(bio, 32000);
	/* Create and setup the connection */
	BIO_set_conn_hostname(bio, srv);
	BIO_set_conn_port(bio, port);

	/* try to connect */
	if(BIO_do_handshake(bio) <= 0) {
		fprintf(stderr, "Error attempting to connect\n");
		ERR_print_errors_fp(stderr);
		rc = 1;
		goto cleanup_2;
	}

	/* Check the certificate */
	res = SSL_get_verify_result(ssl);
	/* will use expired certificate for test */
	if ((res != X509_V_OK) && (res != X509_V_ERR_CERT_HAS_EXPIRED)) {
		fprintf(stderr, "Certificate verification error: %ld\n", res);
		fprintf(stderr, "See verify man page for more info\n");
		ERR_print_errors_fp(stderr);
		rc = 1;
		goto cleanup_2;
	}

	i = 0;
	while (i < max_size) {
		for (j = 0; (j < bufsize) && (i < max_size); j++, i++) {
			buf[j] = (char) (255.0*rand()/(RAND_MAX+1.0));
		}
		if (BIO_write(bio, buf, j) <= 0) {
			fprintf(stderr, "BIO_write() error\n");
			ERR_print_errors_fp(stderr);
			rc = 1;
			break;
		}
	}
	BIO_flush(bio);
	printf("%d bytes wrote\n", i);

	/* Close the connection and free the context */
cleanup_2:
	BIO_free_all(bio);

cleanup_1:
	SSL_CTX_free(ctx);
cleanup_0:
	if (buf)
		free(buf);

	return rc;
}
