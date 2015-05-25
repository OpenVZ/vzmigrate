#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <asm/param.h>
#include <getopt.h>
#include <libgen.h>
#include <limits.h>

#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"

char *ciphers = NULL;
size_t bufsize = 4096;
char *CAfile = NULL;

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
				fprintf(stderr, "Bad CAfile");
				return 1;
			}
			if (strlen(optarg) == 0) {
				fprintf(stderr, "Bad CAfile");
				return 1;
			}
			if ((CAfile = strdup(optarg)) == NULL) {
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


int main()
{
	int rc = 0;
	SSL_CTX *ctx;
	SSL *ssl;
	BIO *bio, *abio, *out;
	char *port = "4422";
	char *buf;
	int i, s;

//	int (*callback)(char *, int, int, void *) = &password_callback;

	SSL_load_error_strings();
	ERR_load_BIO_strings();
	ERR_load_SSL_strings();
	OpenSSL_add_all_algorithms();

	if ((buf = malloc(bufsize)) == NULL) {
		fprintf(stderr, "malloc() : %m");
		return -1;
	}

	/* to create SSL context */
	if ((ctx = SSL_CTX_new(SSLv23_server_method())) == NULL) {
		ERR_print_errors_fp(stderr);
		return 1;
	}

	/* Load certificate and private key */
//	SSL_CTX_set_default_passwd_cb(ctx, callback);
	/* load certificat from file */
	if(SSL_CTX_use_certificate_file(ctx, "certificate.pem",
			SSL_FILETYPE_PEM) < 1) {
		ERR_print_errors_fp(stdout);
		rc = 1;
		goto cleanup_0;
	}
	if(SSL_CTX_use_PrivateKey_file(ctx, "private.key",
			SSL_FILETYPE_PEM) < 1) {
		ERR_print_errors_fp(stdout);
		rc = 1;
		goto cleanup_0;
	}

	if ((bio = BIO_new_ssl(ctx, 0)) == NULL) {
		fprintf(stderr, "Can't create BIO object\n");
		ERR_print_errors_fp(stdout);
		rc = 1;
		goto cleanup_0;
	}

	/* to set up BIO for SSL */
	BIO_get_ssl(bio, &ssl);
	if(!ssl) {
		fprintf(stderr, "Can't locate SSL pointer\n");
		ERR_print_errors_fp(stderr);
		rc = 1;
		goto cleanup_0;
	}
	SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

	if ((abio = BIO_new_accept(port)) == NULL) {
		fprintf(stderr, "Can't create BIO object\n");
		ERR_print_errors_fp(stdout);
		rc = 1;
		goto cleanup_1;
	}
	/* By doing this when a new connection is established
	* we automatically have sbio inserted into it. The
	* BIO chain is now 'swallowed' by the accept BIO and
	* will be freed when the accept BIO is freed.
	*/
	BIO_set_accept_bios(abio, bio);

	/* First call to set up for accepting incoming connections... */
	if(BIO_do_accept(abio) <= 0) {
		ERR_print_errors_fp(stdout);
		rc = 1;
		goto cleanup_2;
	}

	/* Second call to actually wait */
	if(BIO_do_accept(abio) <= 0)
	{
		ERR_print_errors_fp(stdout);
		rc = 1;
		goto cleanup_2;
	}

	out = BIO_pop(abio);

	BIO_set_buffer_size(out, 32000);
	if(BIO_do_handshake(out) <= 0) {
		printf("Handshake failed.\n");
		ERR_print_errors_fp(stdout);
		rc = 1;
		goto cleanup_2;
	}
	s = 0;
	while (1) {
		i = BIO_read(out, buf, bufsize);
//		printf("%d bytes received\n", i);
		if (i <= 0)
			break;
		s += i;
	}
	if (i < 0) {
		fprintf(stderr, "read() : %m\n");
		rc = 1;
	}
	printf("%d bytes received\n", s);

	BIO_free_all(out);

cleanup_2:
	BIO_free_all(abio);

cleanup_1:
//	BIO_free_all(bio);

cleanup_0:
	SSL_CTX_free(ctx);
	free(buf);

	return rc;
}

