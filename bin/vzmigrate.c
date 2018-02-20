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
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>

#define RUNAS_OPTS		3
#define SSH_OPTS		4
#define KEEPER_OPTS		5
#define KEEPDST_OPTS		6
#define ONLINE_OPTS		7
#define LAZY_OPTS		8
#define NOITER_OPTS		9
#define REAL_TIME_OPTS		10
#define SKIP_LOCKVE_OPTS	11
#define DRY_RUN_OPTS 		12
#define NEW_NAME_OPTS		13
#define NEW_ID_OPTS		14
#define NEW_PRIVATE_OPTS	15
#define NEW_ROOT_OPTS		16
#define NONSHAREDFS_OPTS	17
#define WHOLE_FILE_OPTS		'W'
#define TIMEOUT_OPTS		't'
#define NO_SSL_OPTS		18
#define KEEP_IMAGES_OPTS	19
#define CERTIFICATE_OPTS	20
#define PRIVATEKEY_OPTS		21
#define CIPHERS_OPTS		22
#define DST_OPTS		23
#define NOCOMPRESS_OPTS		24
#define CONVERT_VZFS_OPTS	25
#define IGNORE_BACKUP_DISK_OPTS	26
#define NOEVENT_OPTS		27
#define LIMIT_SPEED_OPTS	28
#define COMPRESS_OPTS		29

#define MAX_VE_AVAILABLE	512

#define put_arg(arg)	do {				\
		new_args[new_argc++] = arg;		\
	} while (0)

#define CHECK_NOOPT_ARG(arg_id, arg)			\
		case arg_id:				\
			put_arg(arg);			\
			break

#define CHECK_OOPT_ARG(arg_id, arg)								\
		case arg_id:									\
			strncpy(buffer, arg, sizeof(buffer));					\
			if (optarg) {								\
				strncat(buffer, "=", sizeof(buffer)-strlen(buffer)-1);		\
				strncat(buffer, optarg, sizeof(buffer)-strlen(buffer)-1);	\
			}									\
			put_arg(buffer);							\
			break

#define SET_MOPT_ARG(arg)				\
			if (optarg == NULL)		\
				usage();		\
			put_arg(arg);			\
			put_arg(optarg);		\
			break

#define CHECK_MOPT_ARG(arg_id, arg)			\
		case arg_id:				\
			SET_MOPT_ARG(arg)

#define CHECK_MOPT_NEW_ARG(arg_id, arg)			\
		case arg_id:				\
			new_syntax = 1;			\
			SET_MOPT_ARG(arg)

static int call_pmigrate_once(char *src_ct, char *dst_hn,
		char *dst_ct, char **narg)
{
	char *dst;

	narg[1] = src_ct;
	dst = malloc(strlen(dst_hn) + strlen(dst_ct) + 2);
	if (dst == NULL) {
		perror("Not enough memory");
		return 1;
	}

	sprintf(dst, "%s/%s", dst_hn, dst_ct);
	narg[2] = dst;

	execv("/usr/share/pmigrate/pmigrate.c2c", narg);
	perror("Can't execute pmigrate");
	return 1;
}

static int call_pmigrate(char *src_ct, char *dst_hn, char *dst_ct, char **narg)
{
	int pid, status;

	pid = fork();
	if (pid == -1) {
		perror("Can't fork");
		return -1;
	}

	if (pid == 0) {
		int err;

		err = call_pmigrate_once(src_ct, dst_hn, dst_ct, narg);
		exit(err);
	}

	if (waitpid(pid, &status, 0) != pid) {
		perror("Can't wait pmigrate");
		return -1;
	}

	return (WIFEXITED(status) && (WEXITSTATUS(status) == 0)) ? 0 : -1;
}

#define VZMIGRATE_USAGE									\
"Usage: %s [OPTIONS] <[user@]destination_HN_address> {CT List}\n"			\
"Utility for migration virtual environments between hardware nodes.\n\n"		\
"Mandatory arguments to long options are mandatory for short options too.\n"		\
"  -r, --remove-area yes|no   Remove/Don't Remove  private area on source node for\n"\
"                             successfully migrated CT. Command-line option\n"\
"                             overrides configuration parameter REMOVEMIGRATED\n"\
"                             in @PRODUCT_NAME_LONG@ config file (see vz(5)).\n"			\
"  -h, --help                 Get usage info.\n"					\
"  -s, --nostart              Do not attempt to restore CT state (start/mount\n" \
"                             CT) after successful migration on destination node,\n" \
"                             when it was running/mounted on source node. It means\n" \
"                             that CT should be started/mounted manually on the\n" \
"                             destination node. Option doesn't affect CT that was\n" \
"                             stopped at the migration time.\n"			\
"  -f, --nodeps[=selector]    Ignore failed to check on destination node.\n"	\
"                             About selector see vzmigrate(8).\n"\
"      --ssh=<options>        Additional options that will be passed ssh during\n"\
"                             establishing connection with destination node. Please\n"\
"                             be carefully with passed options, DON'T pass\n"\
"                             destination hostname.\n"				\
"      --keeper[=<veid>]      Keeper CT identification, Service CT ID used if\n"\
"                             not specified. Keeper CT is needed to keep CT IP\n"\
"                             addresses during migration (it used for\n"\
"                             example to show web page that CT in stage of\n"\
"                             migration).\n" \
"      --keep-dst             Don't clean synced destination CT private area in\n"\
"                             case of some error. It is usefull to use this\n"\
"                             option on big CT migration to protect of syncing\n"\
"                             CT private area again in case of some error (on\n"\
"                             CT stop for example) occured during first\n"\
"                             migration attempt.\n"\
"      --keep-images          Don't remove c/r images after a successful migration.\n"\
"      --readonly             Do not locking and use write functions on source\n"       \
"                             CT.\n"			\
"      --dry-run              Option that will perform only checks and will not\n"       \
"                             perform actual data transfer.\n"			\
"      --new-id=<CT ID>       Set destination CT ID.\n"			\
"      --new-name=<CT name>   Set destination CT name.\n"			\
"      --dst=<CT private>     Set destination CT private.\n"			\
"      --new-root=<CT root>   Set destination CT root.\n"			\
"      --nonsharedfs          Force migrate of CT private from shared partition\n" \
"                             to non-shared.\n"  \
"      --whole-file           Use rsync --whole-file option.\n" \
"      --no-ssl               Do not use ssl transport.\n" \
"  -l, --limit-speed          Limit maximum writing speed, in bytes per second.\n" \
"  -t, --timeout              Connection timeout in seconds.\n" \
"      --compress             Enable SSH channel compression.\n" \
"  -v, --verbose              Print verbose information.\n\n" \
"Online option: \n" 									\
"      --online               Perform online (zero-downtime) migration.\n"		\
"      --require-realtime     Force to use only realtime scheme for online migration.\n" \
"                             Migration fails if this method is not available for\n"     \
"                             some reason. It is useful to be sure that delay in\n"      \
"                             service will be the smallest.\n"                           \
"      --noiter               Do not use iterative scheme during online\n"\
"                             migration.\n\n"\
"{CT List} = <source CT ID>[:[<dst CT ID>][:[<dstCT private>][:<dstCT root>]]] [...]\n"\
"without --new-id, --new-name, --new-private, --new-root option(s), and\n"	\
"{CT List} = <source CT ID>\n"	\
"otherwise.\n\n"

static void usage(void)
{
	fprintf(stderr, VZMIGRATE_USAGE, "vzmigrate");
	fprintf(stderr, "The vzmigrate utility is deprecated.\n");
	fprintf(stderr, "Please, consider switching to the prlctl utility.\n");
	exit(1);
}

int main(int argc, char **argv)
{
	static char short_options[] = "hCvr:fszbWtl";
	static struct option long_options[] =
	{
		{"remove-area", required_argument, NULL, 'r'},
		{"nodeps", optional_argument, NULL, 'f'},
		{"nostart", no_argument, NULL, 's'},
		{"run-as", required_argument, NULL, RUNAS_OPTS},
		{"ssh", required_argument, NULL, SSH_OPTS},
		{"help", no_argument, NULL, 'h'},
		{"keeper", optional_argument, NULL, KEEPER_OPTS},
		{"keep-dst", no_argument, NULL, KEEPDST_OPTS},
		{"online", no_argument, NULL, ONLINE_OPTS},
		{"lazy", no_argument, NULL, LAZY_OPTS},
		{"eztempl", no_argument, NULL, 'z'},
		{"readonly", no_argument, NULL, SKIP_LOCKVE_OPTS},
		{"dry-run", no_argument, NULL, DRY_RUN_OPTS},
		{"noiter", no_argument, NULL, NOITER_OPTS},
		{"require-realtime", no_argument, NULL, REAL_TIME_OPTS},
		{"new-name", required_argument, NULL, NEW_NAME_OPTS},
		{"new-id", required_argument, NULL, NEW_ID_OPTS},
		{"new-private", required_argument, NULL, NEW_PRIVATE_OPTS},
			{"dst", required_argument, NULL, DST_OPTS},
		{"new-root", required_argument, NULL, NEW_ROOT_OPTS},
		{"batch", no_argument, NULL, 'b'},
		{"nonsharedfs", no_argument, NULL, NONSHAREDFS_OPTS},
		{"whole-file", no_argument, NULL, WHOLE_FILE_OPTS},
		{"verbose", no_argument, NULL, 'v'},
		{"timeout", required_argument, NULL, TIMEOUT_OPTS},
		{"no-ssl", no_argument, NULL, NO_SSL_OPTS},
		{"limit-speed", required_argument, NULL, LIMIT_SPEED_OPTS},
		{"certificate", required_argument, NULL, CERTIFICATE_OPTS},
		{"privatekey", required_argument, NULL, PRIVATEKEY_OPTS},
		{"ciphers", required_argument, NULL, CIPHERS_OPTS},
		{"keep-images", no_argument, NULL, KEEP_IMAGES_OPTS},
		{"nocompress", no_argument, NULL, NOCOMPRESS_OPTS},
		{"compress", no_argument, NULL, COMPRESS_OPTS},
		{"ignore-backup-disk", no_argument, NULL, IGNORE_BACKUP_DISK_OPTS},
		{"noevent", no_argument, NULL, NOEVENT_OPTS},
		{0, 0, 0, 0}
	};
	char **new_args, *dst_host, *dst_ct = NULL, c;
	int new_argc, new_syntax = 0, i;
	char buffer[BUFSIZ];

	/*
	 * in the worst case we'll need approx argc * 2 arguments
	 * (one for arg and the other one for opt) plus 2 for types
	 * and 1 for terminating NULL
	 * and +2 for dst private & dst root in old syntax:
	 * 101:101:/vz/private/101:/vz/root/101
	 */

	new_args = malloc((argc * 2 + 3 + 2) * sizeof(char *));
	if (new_args == NULL) {
		perror("Not enough memory");
		exit(1);
	}

	memset(new_args, 0, (argc * 2 + 3) * sizeof(char *));

	new_args[0] = "pmigrate.c2c";
	new_args[1] = NULL; /* will be set later */
	new_args[2] = NULL; /* will be set later */
	new_argc = 3;

	/* according to mesk@ vzmigrate is never called by agent directly */

	while ((c = getopt_long(argc, argv, short_options,
					long_options, NULL)) != -1) {
		switch (c) {
			CHECK_OOPT_ARG(KEEPER_OPTS, "--keeper");
			CHECK_OOPT_ARG('f', "--nodeps");

			CHECK_NOOPT_ARG(KEEPDST_OPTS, "--keep-dst");
			CHECK_NOOPT_ARG(DRY_RUN_OPTS, "--dry-run");
			CHECK_NOOPT_ARG(ONLINE_OPTS, "--online");
			CHECK_NOOPT_ARG(LAZY_OPTS, "--lazy");
			CHECK_NOOPT_ARG(SKIP_LOCKVE_OPTS, "--readonly");
			CHECK_NOOPT_ARG(NOITER_OPTS, "--noiter");
			CHECK_NOOPT_ARG(REAL_TIME_OPTS, "--require-realtime");
			CHECK_NOOPT_ARG('s', "--nostart");
			CHECK_NOOPT_ARG('z', "--eztempl");
			CHECK_NOOPT_ARG('v', "--verbose");
			CHECK_NOOPT_ARG(NONSHAREDFS_OPTS, "--nonsharedfs");
			CHECK_NOOPT_ARG(WHOLE_FILE_OPTS, "--whole-file");
			CHECK_NOOPT_ARG(NO_SSL_OPTS, "--no-ssl");
			CHECK_NOOPT_ARG(KEEP_IMAGES_OPTS, "--keep-images");
			CHECK_NOOPT_ARG('b', "--batch");
			CHECK_NOOPT_ARG(NOCOMPRESS_OPTS, "--nocompress");
			CHECK_NOOPT_ARG(COMPRESS_OPTS, "--compress");
			CHECK_NOOPT_ARG(NOEVENT_OPTS, "--noevent");

			CHECK_MOPT_ARG(TIMEOUT_OPTS, "--timeout");
			CHECK_MOPT_ARG(CERTIFICATE_OPTS, "--certificate");
			CHECK_MOPT_ARG(SSH_OPTS, "--ssh");
			CHECK_MOPT_ARG(RUNAS_OPTS, "--run-as");
			CHECK_MOPT_ARG(PRIVATEKEY_OPTS, "--privatekey");
			CHECK_MOPT_ARG(CIPHERS_OPTS, "--ciphers");
			CHECK_MOPT_ARG('r', "--remove-area");
			CHECK_MOPT_ARG(LIMIT_SPEED_OPTS, "--limit-speed");

			CHECK_MOPT_NEW_ARG(NEW_PRIVATE_OPTS, "--new-private");
			CHECK_MOPT_NEW_ARG(DST_OPTS, "--dst");
			CHECK_MOPT_NEW_ARG(NEW_ROOT_OPTS, "--new-root");
			CHECK_MOPT_NEW_ARG(NEW_NAME_OPTS, "--new-name");
			CHECK_NOOPT_ARG(IGNORE_BACKUP_DISK_OPTS, "--ignore-backup-disk");

		case NEW_ID_OPTS:
			if (optarg == NULL)
				usage();

			new_syntax = 1;
			dst_ct = optarg;
			break;

		case 'h':
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc < 2)
		usage();

	dst_host = *argv;
	argv++;
	argc--;

	if (argc > MAX_VE_AVAILABLE) {
		fprintf(stderr, "Maximum number of VEs is limited by %d",
				MAX_VE_AVAILABLE);
		usage();
	}

	if (new_syntax) {
		if (argc != 1) {
			fprintf(stderr, "Only one veid/vename should be used "
					"with --new-* options");
			usage();
		}
		if (strchr(argv[0], ':')) {
			fprintf(stderr, "Old ve list syntax can not be used "
					"with --new-* options: %s", argv[0]);
			usage();
		}
		if (dst_ct == NULL)
			dst_ct = argv[0];

		return call_pmigrate_once(argv[0], dst_host, dst_ct, new_args);
	}

	for (i = 0; i < argc; i++) {
		char *arg;
		char *src_ct;
		char *dst_ct;
		char *p;
		int err;

		arg = strdup(argv[i]);
		if (arg == NULL) {
			perror("Not enough memory");
			exit(1);
		}

		p = arg;
		src_ct = p;
		dst_ct = p;
		// Read 'source' veid
		if ((p = strchr(p, ':'))) {
			*p = '\0';
			// Read 'dst' veid
			dst_ct = ++p;
			if ((p = strchr(p, ':'))) {
				*p = '\0';
				// Read 'dst' priv_path
				put_arg("--dst");
				put_arg(++p);
				if ((p = strchr(p, ':'))) {
					*p = '\0';
					// Read 'dst' root_path
					put_arg("--new-root");
					put_arg(++p);
				}
			}
		}

		if (argc == 1)
			return call_pmigrate_once(src_ct, dst_host, dst_ct,
					new_args);

		err = call_pmigrate(src_ct, dst_host, dst_ct, new_args);
		free(arg);
		if (err)
			return err;
	}

	return 0;
}
