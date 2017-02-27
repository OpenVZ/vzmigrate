/* $Id$
 *
 * Copyright (c) 2006-2016 Parallels IP Holdings GmbH
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
 *
 */
#include <getopt.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <boost/uuid/string_generator.hpp>
#include <boost/uuid/uuid_io.hpp>

#include <vzctl/libvzctl.h>

#include "remotecmd.h"
#include "common.h"
#include "util.h"
#include "bincom.h"

#include "migratecom.h"
#include "migssh.h"
#include "vzacompat.h"

//#include <memory>

extern struct vz_data *vzcnf;

int terminated = 0;
static volatile int sig_handler_disabled;

static void sighandler(int signum)
{
	if (!sig_handler_disabled) {
		sigignore(signum);
		// send sigterm to all processes in group
		kill(0, signum);
		terminated = 1;
	}
}

int init_sig_handlers(__sighandler_t handler)
{
	struct sigaction sigact;

	sigact.sa_flags = 0;
	sigemptyset(&sigact.sa_mask);

	sigact.sa_handler = handler ?: sighandler;
	sigaction(SIGTERM, &sigact, NULL);
	sigaction(SIGINT, &sigact, NULL);

	sigact.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &sigact, NULL);
	return 0;
}

int disable_sig_handler()
{
	sig_handler_disabled = 1;
}

CVZMOptions VZMoptions;
CVZMOptions::CVZMOptions()
{
	options = 0ULL;
	src_addr = dst_addr = NULL;
	dst_user = NULL;
	dst_pwd = NULL;
	bintype = BIN_LOCAL;
	version = MIGRATE_VERSION;
	remote_version = MIGRATE_VERSION;
	invert_lazy_flag = 1;
	tmo.val = IO_TIMEOUT;
	tmo.customized = 0;
	string_list_init(&ssh_options);
	cmd_sock = -1;
	data_sock = -1;
	tmpl_data_sock = -1;
	swap_sock = -1;
	progress_fd = -1;
};

CVZMOptions::~CVZMOptions()
{
	if (src_addr)
		free(src_addr);
	if (dst_addr)
		free(dst_addr);
	if (dst_user)
		free(dst_user);
	if (dst_pwd)
		free(dst_pwd);
	string_list_clean(&ssh_options);
};

static const char * prog_name = NULL;

ctid_t g_keeperCTID = "\0";


#define AGENT_PREFIX	"-agent"
#define AGENT40_PREFIX	"-agent40"

#define USAGE_ONLINE	"[--online]"

#define USAGE_KEEPER	"[--keeper[=<veid>]]"

#define VZMLOCAL_USAGE									\
"This programm is used for local moving/copying CT\n"					\
"Usage:\n"										\
"\tVE moving:\t%s {CT List}\n"								\
"\t{CT List} = <source CT ID>[:[<dst CT ID>][:[<dstCT private>][:<dstCT root>]]] [...]\n"\
"\tVE copying:\t%s -C {CT List}\n"                                      \
"\t{CT List} = <source CT ID>:<dst CT ID>[:[<dstCT private>][:<dstCT root>]] [...]\n"	\
"  -h, --help                 Get usage info.\n"					\
"      --online               Perform online (zero-downtime) copy/move.\n"

#define VZMIGRATE_OPTIONS								\
"  -r, --remove-area yes|no   Remove/Don't Remove  private area on source node for\n"\
"                             successfully migrated CT. Command-line option\n"\
"                             overrides configuration parameter REMOVEMIGRATED\n"\
"                             in @PRODUCT_NAME_LONG@ config file (see vz(5)).\n"			\
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
"      --config=<config path> Set source config file.\n"			\
"      --nonsharedfs          Force migrate of CT private from shared partition\n" \
"                             to non-shared.\n"  \
"      --whole-file           Use rsync --whole-file option\n" \
"  -t, --timeout              Connection timeout in seconds\n" \
"      --nocompress           Do not compress disk image data on online ploop migration\n" \
"  -v, --verbose              Print verbose information.\n\n" \
"Online option: \n" 									\
"      --online               Perform online (zero-downtime) migration.\n"		\
"      --require-realtime     Force to use only realtime scheme for online migration.\n" \
"                             Migration fails if this method is not available for\n"     \
"                             some reason. It is useful to be sure that delay in\n"      \
"                             service will be the smallest.\n"                           \
"      --noiter               Do not use iterative scheme during online\n"\
"                             migration.\n\n"

#define VZMIGRATE_USAGE									\
"Usage: %s [OPTIONS] <[user@]destination_HN_address> {CT List}\n"			\
"Utility for migration virtual environments between hardware nodes.\n\n"		\
"Mandatory arguments to long options are mandatory for short options too.\n"		\
"  -h, --help                 Get usage info.\n"					\
VZMIGRATE_OPTIONS \
"{CT List} = <source CT ID>[:[<dst CT ID>][:[<dstCT private>][:<dstCT root>]]] [...]\n"\
"without --new-id, --new-name, --dst, --new-root option(s), and\n"	\
"{CT List} = <source CT ID>\n"	\
"otherwise\n" \

#define VZMTEMPLATE_USAGE								\
"This programm is used for remote template(s) migrating\n"					\
"Usage:\n"										\
"\t%s [-b] [-h] [--ssh <options>] <[user@]destination_HN_address> template ...\n"

#define PMIGRATE_C2C_USAGE	VZMIGRATE_OPTIONS

/*
vzagent usage:
vzmdest -agent40 -b --keeper <SRC_NODE> <DST_NODE> <VEID>
vzmsrc -agent40 -b --keeper <SRC_NODE> <DST_NODE> <VEID>

vzmdest -agent -b --keeper <SVE_SRC_NODE> <DST_NODE> <VEID>
vzmsrc -agent -b --keeper <SVE_SRC_NODE> <DST_NODE> <VEID>

*/

static int new_syntax = 0;

static void usage()
{
	const char * ustr = VZMIGRATE_USAGE;

	if (strcmp(prog_name, BNAME_PM_C2C) == 0) {
		ustr = PMIGRATE_C2C_USAGE;
	} else {
		if (VZMoptions.bintype == BIN_LOCAL)
			ustr = VZMLOCAL_USAGE;
		else if (VZMoptions.bintype == BIN_TEMPL)
			ustr = VZMTEMPLATE_USAGE;
	}
	fprintf(stderr, ustr, prog_name, prog_name, prog_name);

	exit(-MIG_ERR_USAGE);
}

static int check_path(const char * path)
{
	assert(path);
	if (*path != '/')
		return -1;
	return 0;
}

// VZAVEList arguments that will be passed to destination side, in
// command line mode
const char * VEArgs[MAX_ARGS + 1] =
    {	NULL
    };

//#define OLD_MODE		3
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
#define APROGRESS_OPTS          18
#define READONLY_OPTS           19
#define SOCKET_OPTS		20
#define KEEP_IMAGES_OPTS	21
#define KEEP_SRC_OPTS		22
#define NEW_UUID_OPTS		23
#define NOCOMPRESS_OPTS		24
#define CONVERT_VZFS_OPTS	25
#define IGNORE_BACKUP_DISK_OPTS	26
#define NOEVENT_OPTS		27

/* parse user:password@host */
static int parse_UPH(
		const char *name,
		char **host,
		char **user,
		char **password)
{
	char *p;

	if ((p = (char *)strchr(name, '@'))) {
		*p = '\0';
		if ((*host = strdup(p + 1)) == NULL)
			return putErr(MIG_ERR_SYSTEM, "strdup() : %m");
		if ((p = (char *)strchr(name, ':'))) {
			*p = '\0';
			if ((*password = strdup(p + 1)) == NULL)
				return putErr(MIG_ERR_SYSTEM,
					"strdup() : %m");
			for (char *c = p + 1; *c; c++) *c = '*';
		}
		if ((*user = strdup(name)) == NULL)
			return putErr(MIG_ERR_SYSTEM, "strdup() : %m");
	} else {
		if ((*host = strdup(name)) == NULL)
			return putErr(MIG_ERR_SYSTEM, "strdup() : %m");
	}
	return 0;
}

static int get_ctid_or_name(const char *str, ctid_t ctid, char **name)
{
	SET_CTID(ctid, NULL);
	*name = NULL;

	if (vzctl2_parse_ctid(str, ctid) != 0) {
		int sz = (strlen(str) + 1) * 2;
		if ((*name = (char *)malloc(sz)) == NULL)
			return putErr(MIG_ERR_SYSTEM, "malloc() : %m");
		if (vzctl2_convertstr(str, *name, sz) != 0 ||
				!vzctl2_is_env_name_valid(*name))
			return putErr(MIG_ERR_USAGE, "Invalid CTID or CT name : %s", str);
	}

	return 0;
}

static void get_ctid_opt(const char * opt, ctid_t ctid)
{
	if (vzctl2_parse_ctid(opt, ctid) != 0)
		usage();
}

static void get_ctid(char *arg, ctid_t ctid_)
{
	int rc;
	char *name = NULL;

	if ((rc = get_ctid_or_name(arg, ctid_, &name)))
		exit(-rc);

	if (name) {
		ctid_t ctid;
		if (vzctl2_get_envid_by_name(name, ctid)) {
			logger(LOG_ERR, "Invalid source CT name specified: %s", arg);
			exit(-MIG_ERR_SYSTEM);
		}
		SET_CTID(ctid_, ctid);
		free(name);
	}
}

/* process ve list for old command-line style */
static int ve_list_process_old(char **argv, CVZMOptions *opts)
{
	int point;
	struct VEOptEntry *entry;
	size_t size;

	// Read list of VE(s)
	for (point = 0; argv[point] != NULL; point ++) {
		if ((entry = new(struct VEOptEntry)) == NULL) {
			logger(LOG_ERR, "Memory allocation failure");
			exit(-MIG_ERR_SYSTEM);
		}
		if (opts->bintype == BIN_TEMPL || opts->bintype == BIN_DEST_TEMPL)
		{
			if (strchr(argv[point], '/'))
			{
				fprintf(stderr, "Invalid template name \"%s\". "
					"Only whole template migrating is supported.\n",
					argv[point]);
				usage();
			}
			std::string templ(argv[point]);
			opts->templMigrateList.push_back(templ.c_str());
			size = strlen(argv[point]) + 3;
			if ((VEArgs[point] = (const char*)malloc(size)) == NULL) {
				logger(LOG_ERR, "Memory allocation failure");
				exit(-MIG_ERR_SYSTEM);
			}
			snprintf((char *)VEArgs[point], size, "'%s'", argv[point]);
		}
		else
		{
			char *arg = argv[point];
			char *p;
			/* Read entry as :
			<src_ctid>[:<dst_ctid>[:<dst_priv_dir>[:<dst_root_dir>]]]
			*/

			// Read 'source' ctid
			if ((p = strchr(arg, ':')) == NULL) {
				get_ctid(arg, entry->src_ctid);
				SET_CTID(entry->dst_ctid, entry->src_ctid);
				goto finish;
			} else {
				*p = '\0';
				get_ctid(arg, entry->src_ctid);
				SET_CTID(entry->dst_ctid, entry->src_ctid);
			}

			// Read 'dst' ctid
			arg = ++p;
			if ((p = strchr(arg, ':')) == NULL) {
				if (strlen(arg))
					get_ctid_opt(arg, entry->dst_ctid);
				goto finish;
			} else {
				*p = '\0';
				if (strlen(arg))
					get_ctid_opt(arg, entry->dst_ctid);
			}

			// Read 'dst' priv_path
			arg = ++p;
			if ((p = strchr(arg, ':')) == NULL) {
				if (strlen(arg)) {
					if (check_path(arg))
						usage();
					entry->priv_path = strdup(arg);
				}
				goto finish;
			} else {
				*p = '\0';
				if (strlen(arg)) {
					if (check_path(arg))
						usage();
					entry->priv_path = strdup(arg);
				}
			}

			// Read 'dst' root_path
			arg = ++p;
			if ((p = strchr(arg, ':')) == NULL) {
				if (strlen(arg)) {
					if (check_path(arg))
						usage();
					entry->root_path = strdup(arg);
				}
				goto finish;
			} else {
				*p = '\0';
				if (strlen(arg)) {
					if (check_path(arg))
						usage();
					entry->root_path = strdup(arg);
				}
			}

			if ((p = strchr(++p, ':')))
				usage();
finish:
			if (opts->bintype == BIN_LOCAL
				&& CMP_CTID(entry->src_ctid, entry->dst_ctid) == 0
				&& (isOptSet(OPT_COPY) || (entry->priv_path == NULL)))
				usage();

			opts->veMigrateList.push_back(entry);

			// save and transform arguments to pass on destination part
			// ssh call 'bash -c' on destination side, so we need transformation
			// replace ve name to veid
			size = 100;
			if (entry->priv_path)
				size += strlen(entry->priv_path) + 1;
			if (entry->root_path) {
				size += strlen(entry->root_path) + 1;
				if (entry->priv_path == NULL)
					size += 1;
			}
			if ((VEArgs[point] = (const char *)malloc(size)) == NULL) {
				logger(LOG_ERR, "Memory allocation failure");
				exit(-MIG_ERR_SYSTEM);
			}
			snprintf((char *)VEArgs[point], size, "'%s:%s",
				entry->src_ctid, entry->dst_ctid);
			if (entry->priv_path) {
				strncat((char *)VEArgs[point], ":",
					size - strlen(VEArgs[point]) - 1);
				strncat((char *)VEArgs[point], entry->priv_path,
					size - strlen(VEArgs[point]) - 1);
			}
			if (entry->root_path) {
				if (!entry->priv_path) {
					strncat((char *)VEArgs[point], ":",
						size - strlen(VEArgs[point]) - 1);
				}
				strncat((char *)VEArgs[point], ":",
					size - strlen(VEArgs[point]) - 1);
				strncat((char *)VEArgs[point], entry->root_path,
					size - strlen(VEArgs[point]) - 1);
			}
			strncat((char *)VEArgs[point], "'",
				size - strlen(VEArgs[point]) - 1);
		}
	}

	VEArgs[point+1] = NULL;
	return 0;
}

bool check_local_addr(char *host) {
	struct ifaddrs *myaddrs, *ifa;
	struct addrinfo hints, *result;
	int ret;
	bool retval = false;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
	hints.ai_socktype = SOCK_DGRAM; /* Datagram socket */
	hints.ai_protocol = IPPROTO_IP; /* IP protocol */

	if ((ret = getaddrinfo(host, 0, &hints, &result)) != 0)
	{
		logger(LOG_ERR, "getaddrinfo(%s) failed: %s", host, gai_strerror(ret));
		return false;
	}

	if (getifaddrs(&myaddrs) != 0)
	{
		logger(LOG_ERR, "getifaddrs failed: %i", errno);
		return false;
	}

	for (ifa = myaddrs; ifa != NULL; ifa = ifa->ifa_next)
	{
		if (ifa->ifa_addr == NULL)
			continue;

		if (!(ifa->ifa_flags & IFF_UP))
			continue;

		if (ifa->ifa_addr->sa_family == result->ai_family)
		{
			if (ifa->ifa_addr->sa_family == AF_INET)
			{
				if (memcmp(&((struct sockaddr_in *)ifa->ifa_addr)->sin_addr,
					&((struct sockaddr_in *)result->ai_addr)->sin_addr,
					sizeof(struct in_addr)) == 0)
				{
					retval = true;
					break;
				}
			}
			else if (ifa->ifa_addr->sa_family == AF_INET6)
			{
				if (memcmp(&((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr,
					&((struct sockaddr_in6 *)result->ai_addr)->sin6_addr,
					sizeof(struct in6_addr)) == 0)
				{
					retval = true;
					break;
				}
			}
		}
	}

	freeaddrinfo(result);
	freeifaddrs(myaddrs);
	return retval;
}

void parse_options (int argc, char **argv)
{
	int rc;
	char buffer[BUFSIZ];

	/* common ssh options */
	string_list_add(&VZMoptions.ssh_options, "-T");
	string_list_add(&VZMoptions.ssh_options, "-q");
	/* blowfish is faster then DES3,
	   but arcfour is faster then blowfish, according #84995 */
	string_list_add(&VZMoptions.ssh_options, "-c");
	string_list_add(&VZMoptions.ssh_options, "arcfour");
	string_list_add(&VZMoptions.ssh_options, "-o");
	string_list_add(&VZMoptions.ssh_options, "StrictHostKeyChecking=no");
	string_list_add(&VZMoptions.ssh_options, "-o");
	string_list_add(&VZMoptions.ssh_options, "CheckHostIP=no");
	string_list_add(&VZMoptions.ssh_options, "-o");
	string_list_add(&VZMoptions.ssh_options, "UserKnownHostsFile=/dev/null");
	string_list_add(&VZMoptions.ssh_options, "-o");
	string_list_add(&VZMoptions.ssh_options, "PreferredAuthentications=publickey,password,keyboard-interactive");

	struct VEOptEntry *entry;
	if ((entry = new(struct VEOptEntry)) == NULL) {
		logger(LOG_ERR, "Memory allocation failure");
		exit(-MIG_ERR_SYSTEM);
	}

	if (vzcnf->removemigrated)
		setOpt(OPT_REMOVE);

	char c;

	static char short_options[] = "hCvr:fszbWt:";

	static struct option long_options[] =
	    {
		    {"copy", no_argument, NULL, 'C'},		// Copy mode
		    {"remove-area", required_argument, NULL, 'r'},	// Remove private area
		    {"nodeps", optional_argument, NULL, 'f'},	// Force migration
		    {"nostart", no_argument, NULL, 's'},	// Don't start VE after migration
		    // Used to run migration in some old mode
		    {"run-as", required_argument, NULL, RUNAS_OPTS},
		    {"ssh", required_argument, NULL, SSH_OPTS}, // additional ssh options
		    {"help", no_argument, NULL, 'h'},
		    {"keeper", optional_argument, NULL, KEEPER_OPTS}, // keeper VEID
		    {"keep-dst", no_argument, NULL, KEEPDST_OPTS},	// Keep destination dir
		    {"online", no_argument, NULL, ONLINE_OPTS},	// Online migration
		    {"lazy", no_argument, NULL, LAZY_OPTS},	// Pagein in online migration
		    {"eztempl", no_argument, NULL, 'z'},	// Eztemplates
			// Skip locking srcVE + rename on srcVE
		    {"readonly", no_argument, NULL, READONLY_OPTS},
		    {"dry-run", no_argument, NULL, DRY_RUN_OPTS},	// option that will perform only checks and will not perform actual data transfer
		    /*
		     * Iterative scheme for online migration is used by default
		     * This option is used to turn it off
		     */
		    {"noiter", no_argument, NULL, NOITER_OPTS},
		    /*
		     * Force to use only iterative scheme for online migration
		     * Migration fails if this scheme is not available
		     */
		    {"require-realtime", no_argument, NULL, REAL_TIME_OPTS},
		    {"new-name", required_argument, NULL, NEW_NAME_OPTS},
		    {"new-id", required_argument, NULL, NEW_ID_OPTS},
		    {"new-private", required_argument, NULL, NEW_PRIVATE_OPTS},
				{"dst", required_argument, NULL, NEW_PRIVATE_OPTS},
		    {"new-root", required_argument, NULL, NEW_ROOT_OPTS},
		    {"batch", no_argument, NULL, 'b'},
//		    {"progress", no_argument, NULL, 'p'},
		    {"nonsharedfs", no_argument, NULL, NONSHAREDFS_OPTS},
		    {"whole-file", no_argument, NULL, WHOLE_FILE_OPTS},
		    {"verbose", no_argument, NULL, 'v'},
		{"timeout", required_argument, NULL, TIMEOUT_OPTS},
		{"aprogress", no_argument, NULL, APROGRESS_OPTS},
		{"skiplock", no_argument, NULL, SKIP_LOCKVE_OPTS}, // Skip locking VE
		{"socket", no_argument, NULL, SOCKET_OPTS},
		{"keep-images", no_argument, NULL, KEEP_IMAGES_OPTS}, // Keep images 
		// Keep source CT - internal for parallels server mode
		{"keep-src", no_argument, NULL, KEEP_SRC_OPTS},
		{"new-uuid", required_argument, NULL, NEW_UUID_OPTS},
		{"nocompress", no_argument, NULL, NOCOMPRESS_OPTS},
		{"ignore-backup-disk", no_argument, NULL, IGNORE_BACKUP_DISK_OPTS},
		{"noevent", no_argument, NULL, NOEVENT_OPTS},
		{0, 0, 0, 0}
	    };
	prog_name = argv[0];

	if (argv[1] != NULL && !strcmp(argv[1], AGENT40_PREFIX))
	{
		// usage migrate from agent 40
		setOpt(OPT_AGENT40);
		setOpt(OPT_AGENT);
		argc --;
		argv ++;
	}
	else if (argv[1] != NULL && !strcmp(argv[1], AGENT_PREFIX))
	{
		// usage migrate from agent
		setOpt(OPT_AGENT);
		argc --;
		argv ++;
	}
	else if (argv[1] != NULL && !strcmp(argv[1], "-ps"))
	{
		/* parallels server mode : dispatcher will call
		   vzmsrc/vzmdest to migrate of container */
		setOpt(OPT_PS_MODE);
		if (argc < 8)
		{
			logger(LOG_ERR, "Syntax error in -ps mode");
			exit(-MIG_ERR_USAGE);
		}
		VZMoptions.cmd_sock = get_fd(argv[2]);
		VZMoptions.data_sock = get_fd(argv[3]);
		VZMoptions.tmpl_data_sock = get_fd(argv[4]);
		VZMoptions.swap_sock = get_fd(argv[5]);

		char *p = getenv("VZ_PROGRESS_FD");
		if (p)
			VZMoptions.progress_fd = atoi(p);

		if ( VZMoptions.cmd_sock < 0 || VZMoptions.data_sock < 0 ||
		     VZMoptions.tmpl_data_sock < 0 || VZMoptions.swap_sock < 0)
			exit(-MIG_ERR_CONN_BROKEN);
		
		argc -= 5;
		argv += 5;
	}

	while ((c = getopt_long(argc, argv, short_options,
	                        long_options, NULL)) != -1)
	{
		switch (c)
		{
		case SSH_OPTS:
		{
			char *str, *token;
			if (optarg == NULL)
				usage();
			for (str = optarg; ;str = NULL) {
				if ((token = strtok(str, " \t")) == NULL)
					break;
				if (strlen(token))
					string_list_add(&VZMoptions.ssh_options, token);
			}
		}
		break;

		case DRY_RUN_OPTS:
			setOpt(OPT_DRY_RUN);
			break;

		case RUNAS_OPTS:
			VZMoptions.version = atoi(optarg);
			break;

		case KEEPER_OPTS:
			if (optarg)
				get_ctid_opt(optarg, g_keeperCTID);
			else
				SET_CTID(g_keeperCTID, SERVICE_CTID);
			setOpt(OPT_KEEPER);
			break;

		case KEEPDST_OPTS:
			setOpt(OPT_KEEP_DST);
			break;

		case ONLINE_OPTS:
			setOpt(OPT_ONLINE);
			break;

		case LAZY_OPTS:
			logger(LOG_ERR, "Option '--lazy' is not supported");
// TODO : to remove lazy code
			exit(-MIG_ERR_USAGE);

		case APROGRESS_OPTS:
			setOpt(OPT_APROGRESS);
			setOpt(OPT_USE_RSYNC);
			break;

 		case SKIP_LOCKVE_OPTS:
			setOpt(OPT_SKIP_LOCKVE);
			break;

		case READONLY_OPTS:
			setOpt(OPT_READONLY);
			break;

		case NOITER_OPTS:
			setOpt(OPT_NOITER);
			break;

		case REAL_TIME_OPTS:
			setOpt(OPT_REALTIME);
			break;

		case 'C':
			if (VZMoptions.bintype != BIN_LOCAL &&
				strcmp(prog_name, BNAME_PM_C2C))
				usage();
			setOpt(OPT_COPY);
			break;
		case 'r':
			if (optarg == NULL
			        || (VZMoptions.bintype != BIN_SRC &&
				strcmp(prog_name, BNAME_PM_C2C)) ||
				optarg[0] == '-')
				usage();
			if (!strcmp(optarg, "yes"))
				setOpt(OPT_REMOVE);
			else if (!strcmp(optarg, "no"))
				unSetOpt(OPT_REMOVE);
			else
				usage();
			break;
		case 's':
			setOpt(OPT_NOSTART);
			break;
		case 'f':
		{
			if (VZMoptions.bintype != BIN_SRC && VZMoptions.bintype != BIN_LOCAL &&
				VZMoptions.bintype != BIN_TEMPL && strcmp(prog_name, BNAME_PM_C2C))
			{
				usage();
			}
			if (optarg == NULL)
			{
				setOpt(OPT_FORCE);
				setOpt(OPT_SKIP_CHECKCPU);
				setOpt(OPT_SKIP_DISKSPACE);
				setOpt(OPT_SKIP_TECHNOLOGIES);
				setOpt(OPT_SKIP_LICENSE);
				setOpt(OPT_SKIP_RATE);
				setOpt(OPT_SKIP_EXT_BINDMOUNT);
				setOpt(OPT_SKIP_TEMPLATE_AREA_SYNC);

				break;
			}

			char *str;
			char *tmp_tok;
			for (str = optarg; ;str = NULL) {
				if ((tmp_tok = strtok(str, ",")) == NULL)
					break;
				if (!strcmp(tmp_tok, "cpu_check"))
					setOpt(OPT_SKIP_CHECKCPU);
				else if (!strcmp(tmp_tok, "all"))
				{
					setOpt(OPT_FORCE);
					setOpt(OPT_SKIP_CHECKCPU);
					setOpt(OPT_SKIP_DISKSPACE);
					setOpt(OPT_SKIP_TECHNOLOGIES);
					setOpt(OPT_SKIP_LICENSE);
					setOpt(OPT_SKIP_RATE);
					setOpt(OPT_SKIP_EXT_BINDMOUNT);
					setOpt(OPT_SKIP_TEMPLATE_AREA_SYNC);
				}
				else if (!strcmp(tmp_tok, "disk_space"))
					setOpt(OPT_SKIP_DISKSPACE);
				else if (!strcmp(tmp_tok, "technologies"))
					setOpt(OPT_SKIP_TECHNOLOGIES);
				else if (!strcmp(tmp_tok, "license"))
					setOpt(OPT_SKIP_LICENSE);
				else if (!strcmp(tmp_tok, "rate"))
					setOpt(OPT_SKIP_RATE);
				else if (!strcmp(tmp_tok, "bindmount"))
					setOpt(OPT_SKIP_EXT_BINDMOUNT);
				else if (!strcmp(tmp_tok, "template_area_sync"))
					setOpt(OPT_SKIP_TEMPLATE_AREA_SYNC);
				else if (!strcmp(tmp_tok, "kernel_modules"))
					setOpt(OPT_SKIP_KERNEL_MODULES);
				else
					usage();
			}
		}
		break;
		case 'z':
			setOpt(OPT_EZTEMPLATE);
			break;
		case 'v':
			debug_level = LOG_DEBUG;
			break;
		case NEW_NAME_OPTS: {
			size_t sz;
			char *buf;

			if (optarg == NULL)
				usage();

			sz = 2*(strlen(optarg)+1);
			if ((buf = (char *)malloc(sz)) == NULL) {
				logger(LOG_ERR, "Memory allocation failure");
				exit(-MIG_ERR_SYSTEM);
			}

			/* convert to utf-8 */
			if (vzctl2_convertstr(optarg, buf, sz) || \
					!vzctl2_is_env_name_valid(buf)) {
				logger(LOG_ERR, "Invalid destination CT name "\
					"specified: %s", optarg);
				exit(-MIG_ERR_USAGE);
			}

			entry->dst_name = buf;
			new_syntax = 1;
			break;
		}
		case NEW_ID_OPTS:
			if (optarg == NULL)
				usage();
			get_ctid_opt(optarg, entry->dst_ctid);
			new_syntax = 1;
			break;
		case NEW_UUID_OPTS:
		{
			/* this is internal option for CT UUID */
			ctid_t normUuid;
			if (vzctl2_get_normalized_uuid(optarg, normUuid, sizeof(ctid_t)))
				exit(-MIG_ERR_USAGE);
			entry->uuid = strdup(normUuid);
			new_syntax = 1;
			break;
		}
		case NEW_PRIVATE_OPTS:
			if (optarg == NULL)
				usage();
			entry->priv_path = strdup(optarg);
			new_syntax = 1;
			break;
		case NEW_ROOT_OPTS:
			if (optarg == NULL)
				usage();
			entry->root_path = strdup(optarg);
			new_syntax = 1;
			break;
		case 'b':
			/* switch on by default */
			break;
/* progress is not available for tar
		case 'p':
			setOpt(OPT_PROGRESS);
			break;*/
		case NONSHAREDFS_OPTS:
			setOpt(OPT_NONSHAREDFS);
			break;
		case WHOLE_FILE_OPTS:
			setOpt(OPT_WHOLE_FILE);
			break;
		case TIMEOUT_OPTS:
			if (optarg == NULL)
				usage();
			VZMoptions.tmo.val = atoi(optarg);
			VZMoptions.tmo.customized = 1;
			break;
		case SOCKET_OPTS:
			setOpt(OPT_SOCKET);
			break;
		case KEEP_IMAGES_OPTS:
			setOpt(OPT_KEEP_IMAGES);
			break;
		case KEEP_SRC_OPTS:
			setOpt(OPT_KEEP_SRC);
			break;
		case NOCOMPRESS_OPTS:
			setOpt(OPT_NOCOMPRESS);
			break;
		case IGNORE_BACKUP_DISK_OPTS:
			setOpt(OPT_IGNORE_BACKUP_DISK);
			break;
		case NOEVENT_OPTS:
			setOpt(OPT_NOEVENT);
			break;
		case 'h':
		default:
			usage();
		}
	}

	/* initialize destination CTID using uuid if it was not explicitly specified */
	if (EMPTY_CTID(entry->dst_ctid) && (entry->uuid != NULL))
		SET_CTID(entry->dst_ctid, entry->uuid);

	snprintf(VZMoptions.tmo.str, sizeof(VZMoptions.tmo.str), "%ld", VZMoptions.tmo.val);
	snprintf(buffer, sizeof(buffer), "ServerAliveInterval=%ld", VZMoptions.tmo.val/3);
	string_list_add(&VZMoptions.ssh_options, "-o");
	string_list_add(&VZMoptions.ssh_options, "ServerAliveCountMax=3");
	string_list_add(&VZMoptions.ssh_options, "-o");
	string_list_add(&VZMoptions.ssh_options, buffer);

	argc -= optind;
	argv += optind;

	if (!strcmp(prog_name, BNAME_PM_C2C)) {
		/*
		 * we're now called with the following argv:
		 *    localhost/<ctid> <host>/<newid>
		 * whilst the following code expects this to be
		 *    <host> <ctid> --new-id=<newid>
		 * or
		 *    <host> <ctid>:<newid>
		 * let's try hard not to confuse it...
		 */

		new_syntax = 2;

		if (argc < 2)
			usage();

		ctid_t ctid;
		if (vzctl2_parse_ctid(argv[1], ctid) == 0) {
			SET_CTID(entry->dst_ctid, ctid);
			VZMoptions.bintype = BIN_LOCAL;
			open_logger("vzmlocal");
		} else {
			char *p;
			if ((p = strchr(argv[1], '/'))) {
				/*
				   pmigrate.c2c is internal command and should get
				   new ct name from --new_name parameter only.
				   will ignore name (https://jira.sw.ru/browse/PCLIN-27852)
				*/
				*p++ = '\0';
				get_ctid(p, entry->dst_ctid);
			}
			if ((rc = parse_UPH(argv[1],
					&VZMoptions.dst_addr,
					&VZMoptions.dst_user,
					&VZMoptions.dst_pwd)))
			{
				exit(-rc);
			}
			struct addrinfo hints, *addr, *addrlist;
			int ret;

			memset(&hints, 0, sizeof(struct addrinfo));
			hints.ai_flags    = AI_CANONNAME;
			hints.ai_family   = AF_INET;
			hints.ai_socktype = SOCK_STREAM;
			if ((ret = getaddrinfo(VZMoptions.dst_addr, NULL, &hints, &addrlist)))
			{
				hints.ai_family   = AF_INET6;
				if ((ret = getaddrinfo(VZMoptions.dst_addr, NULL, &hints, &addrlist)))
				{
					logger(LOG_ERR, "getaddrinfo(%s) : %s",
							VZMoptions.dst_addr, gai_strerror(ret));
					exit(-MIG_ERR_USAGE);
				}
			}

			VZMoptions.bintype = BIN_SRC;
			open_logger("vzmsrc");
			for (addr = addrlist; addr; addr = addr->ai_next) {
				if (addr->ai_family == AF_INET6) {
					sockaddr_in6* sin = (sockaddr_in6* )addr->ai_addr;
					if (memcmp(&sin->sin6_addr,
						&in6addr_loopback, sizeof(in6addr_loopback)) == 0)
					{
						VZMoptions.bintype = BIN_LOCAL;
						open_logger("vzmlocal");
						break;
					}
				} else {
					sockaddr_in* sin = (sockaddr_in* )addr->ai_addr;
					if (ntohl(sin->sin_addr.s_addr) == INADDR_LOOPBACK)
					{
						VZMoptions.bintype = BIN_LOCAL;
						open_logger("vzmlocal");
						break;
					}
				}
			}
			freeaddrinfo(addrlist);
		}

		/* perform postponed due to late initialization checks */
		if (VZMoptions.bintype != BIN_LOCAL && isOptSet(OPT_COPY))
			usage();
		if (VZMoptions.bintype != BIN_SRC && isOptSet(OPT_REMOVE))
			usage();
		if (VZMoptions.bintype != BIN_SRC &&
			VZMoptions.bintype != BIN_TEMPL &&
			(isOptSet(OPT_FORCE) || isOptSet(OPT_SKIP_CHECKCPU) ||
			isOptSet(OPT_FORCE) || isOptSet(OPT_SKIP_DISKSPACE) ||
			isOptSet(OPT_SKIP_TECHNOLOGIES) ||
			isOptSet(OPT_SKIP_LICENSE) || isOptSet(OPT_SKIP_RATE) ||
			isOptSet(OPT_SKIP_EXT_BINDMOUNT) ||
			isOptSet(OPT_SKIP_TEMPLATE_AREA_SYNC) ||
			isOptSet(OPT_SKIP_KERNEL_MODULES) ))
			usage();
	}

	if (isOptSet(OPT_ONLINE) && isOptSet(OPT_REALTIME) &&
	        isOptSet(OPT_NOITER))
	{
		logger(LOG_ERR, "Can't use --require-realtime option with --noiter option");
		exit(-MIG_ERR_USAGE);
	}
	if (isOptSet(OPT_ONLINE) && isOptSet(OPT_READONLY))
	{
		logger(LOG_ERR, "Can't use --online option with --readonly option");
		exit(-MIG_ERR_USAGE);
	}
	if (isOptSet(OPT_ONLINE) && isOptSet(OPT_NOSTART))
	{
		logger(LOG_WARNING, "Can't use --nostart option with online migration, option ignored");
		unSetOpt( OPT_NOSTART);
	}
	if (isOptSet(OPT_ONLINE) && isOptSet(OPT_KEEPER))
	{
		logger(LOG_WARNING, "Can't use --keeper option with online migration, option ignored");
		unSetOpt(OPT_KEEPER);
	}
	if (!isOptSet(OPT_ONLINE) && isOptSet(OPT_NOITER)) {
		logger(LOG_ERR, "Option --noiter is available "\
			"for online migration only");
		exit(-MIG_ERR_USAGE);
	}
	if (!isOptSet(OPT_ONLINE) && isOptSet(OPT_REALTIME)) {
		logger(LOG_ERR, "Option --require-realtime is available "\
			"for online migration only");
		exit(-MIG_ERR_USAGE);
	}

	switch (VZMoptions.bintype)
	{
	case BIN_LOCAL:
		break;
	case BIN_SRC:
	case BIN_TEMPL:
		if (isOptSet(OPT_AGENT))
		{
			// src & dest
			if (argc < 2)
				usage();
			if ((VZMoptions.src_addr = strdup(*argv++)) == NULL) {
				logger(LOG_ERR, "strdup() : %m");
				exit(-MIG_ERR_SYSTEM);
			}
			if ((VZMoptions.dst_addr = strdup(*argv++)) == NULL) {
				logger(LOG_ERR, "strdup() : %m");
				exit(-MIG_ERR_SYSTEM);
			}
			argc -= 2;
		}
		else
		{
			if (argc < 1)
				usage();

			if (new_syntax != 2) {
				/* parse destination : [user[:password]@]<node> */
				if ((rc = parse_UPH(*argv++,
						&VZMoptions.dst_addr,
						&VZMoptions.dst_user,
						&VZMoptions.dst_pwd)))
				{
					exit(-rc);
				}
				argc -= 1;
			}
		}
		break;
	case BIN_DEST:
	case BIN_DEST_TEMPL:
		if (isOptSet(OPT_AGENT))
		{
			// src & dest
			if (argc < 2)
				usage();
			if ((VZMoptions.src_addr = strdup(*argv++)) == NULL) {
				logger(LOG_ERR, "strdup() : %m");
				exit(-MIG_ERR_SYSTEM);
			}
			if ((VZMoptions.dst_addr = strdup(*argv++)) == NULL) {
				logger(LOG_ERR, "strdup() : %m");
				exit(-MIG_ERR_SYSTEM);
			}
			argc -= 2;
		}
		else
		{
			// read protocol info
			// or if can't then we have OLD migrate on source side
			if (argc < 1)
				usage();
			char * dummy;
			VZMoptions.remote_version = strtoul(*argv++, &dummy, 10);
			if (*dummy != '\0')
				VZMoptions.remote_version = MIGRATE_VERSION_OLD;
			argc--;
		}
		break;
	default:
		assert(0);
		return;
	}

	if (argc < 1)
		usage();
	if (argc > MAX_VE_AVAILABLE)
	{
		logger(LOG_ERR, "Maximum number of VEs is limited by %d",
		       MAX_VE_AVAILABLE);
		usage();
	}

	if (new_syntax) {
		size_t size;

		/* read source veid or vename only */
		if (new_syntax == 1 && argc != 1) {
			logger(LOG_ERR, "Only one veid/vename should be used "\
				"with --new-* options");
			usage();
		}

		if (new_syntax == 2) {
			/* parse source : [[user[:password]@]<node>/]<CTID>|<name> */
			char *p;
			if ((p = strchr(argv[0], '/'))) {
				char *addr, *user, *pwd;

				*p++ = '\0';
				if ((rc = parse_UPH(argv[0], &addr, &user, &pwd)))
				{
					exit(-rc);
				}

				if (!check_local_addr(addr)) {
					logger(LOG_ERR, "Migration is available "
						"from localhost only");
					exit(-MIG_ERR_USAGE);
				}
			} else {
				p = argv[0];
			}
			get_ctid(p, entry->src_ctid);

			if (EMPTY_CTID(entry->dst_ctid))
				SET_CTID(entry->dst_ctid, entry->src_ctid);
		} else {
			if (strchr(argv[0], ':')) {
				logger(LOG_ERR, "Old ve list syntax can not be used "\
						"with --new-* options: %s", argv[0]);
				usage();
			}
			get_ctid(argv[0], entry->src_ctid);

			if (EMPTY_CTID(entry->dst_ctid))
				SET_CTID(entry->dst_ctid, entry->src_ctid);

			// check is private specified during local move, it's mandatory
			if (VZMoptions.bintype == BIN_LOCAL && !isOptSet(OPT_COPY)
					&& (entry->priv_path == NULL))
				usage();
		}
		VZMoptions.veMigrateList.push_back(entry);

		// save and transform arguments to pass on destination part
		// ssh call 'bash -c' on destination side, so we need transformation
		// replace ve name to veid
		size = 100;
		if (entry->priv_path)
			size += strlen(entry->priv_path) + 1;
		if (entry->root_path) {
			size += strlen(entry->root_path) + 1;
			if (!entry->priv_path)
				size += 1;
		}
		if ((VEArgs[0] = (const char *)malloc(size)) == NULL) {
			logger(LOG_ERR, "Memory allocation failure");
			exit(-MIG_ERR_SYSTEM);
		}
		snprintf((char *)VEArgs[0], size, "'%s:%s",
			entry->src_ctid, entry->dst_ctid);
		if (entry->priv_path) {
			strncat((char *)VEArgs[0], ":",
				size - strlen(VEArgs[0]) - 1);
			strncat((char *)VEArgs[0], entry->priv_path,
				size - strlen(VEArgs[0]) - 1);
		}
		if (entry->root_path) {
			if (!entry->priv_path) {
				strncat((char *)VEArgs[0], ":",
					size - strlen(VEArgs[0]) - 1);
			}
			strncat((char *)VEArgs[0], ":",
				size - strlen(VEArgs[0]) - 1);
			strncat((char *)VEArgs[0], entry->root_path,
				size - strlen(VEArgs[0]) - 1);
		}
		strncat((char *)VEArgs[0], "'",
			size - strlen(VEArgs[0]) - 1);
		VEArgs[1] = NULL;
	} else {
		// Read list of VE(s)
		ve_list_process_old(argv, &VZMoptions);
	}

	// create bigname, that consist of src/dst addresses and list of VEs
	// it needs to be a unique (known) socket name for 'vzmpipe' and 'vzmdest' communication
	// Only for agent mode.
	if (isOptSet(OPT_AGENT))
	{
		assert(VZMoptions.src_addr && VZMoptions.dst_addr);
		std::size_t pos;
		std::string compat_id;

		VZMoptions.bigname += VZMoptions.src_addr;
		VZMoptions.bigname += VZMoptions.dst_addr;

		if (VZMoptions.bintype == BIN_TEMPL || VZMoptions.bintype == BIN_DEST_TEMPL) {
			for (TemplOptEntries::const_iterator it = VZMoptions.templMigrateList.begin();
				it != VZMoptions.templMigrateList.end(); ++it)
			{
				VZMoptions.bigname += ":" + *it;
			}
		} else {
			for (VEOptEntries::const_iterator it = VZMoptions.veMigrateList.begin();
				it != VZMoptions.veMigrateList.end(); ++it)
			{
				compat_id = (*it)->src_ctid;
				pos = compat_id.find("-");
				if (pos != std::string::npos)
					VZMoptions.bigname += std::string(":") + compat_id.substr(0, pos);
				else
					VZMoptions.bigname += std::string(":") + (*it)->src_ctid;

				compat_id = (*it)->dst_ctid;
				pos = compat_id.find("-");
				if (pos != std::string::npos)
					VZMoptions.bigname += std::string(":") + compat_id.substr(0, pos);
				else
					VZMoptions.bigname += std::string(":") + (*it)->dst_ctid;
			}
		}
	}

	if (isOptSet(OPT_PS_MODE))
	{
		if (VZMoptions.bintype == BIN_TEMPL || VZMoptions.bintype == BIN_DEST_TEMPL) {
			if (VZMoptions.templMigrateList.size() != 1) {
				logger(LOG_ERR, "You must specify only one template in -ps mode");
				exit(-MIG_ERR_USAGE);
			}
		} else {
			if (VZMoptions.veMigrateList.size() != 1) {
				logger(LOG_ERR, "You must specify only one CT in -ps mode");
				exit(-MIG_ERR_USAGE);
			}
		}
	}

	if (VZMoptions.dst_user && strcmp(VZMoptions.dst_user, "root")) {
		if (!isOptSet(OPT_AGENT) && !isOptSet(OPT_AGENT40)) {
			setOpt(OPT_SUDO);
			if (!isOptSet(OPT_SOCKET))
				/* to use ssh port forwarding for sudo */
				setOpt(OPT_SSH_FWD);
		}
	}
}

const string getProgArgs(Arguments args)
{
	assert(args);
	string s;
	while (*args)
	{
		s += " ";
		s += *args++;
	}
	return s;
}

int arrangeArgs(const char ** new_args, int max_size, Arguments args, ...)
{
	va_list ap;
	va_start(ap, args);
	int rc = arrangeArgs(new_args, max_size, args, ap);
	va_end(ap);
	return rc;
}

int arrangeArgs(const char ** new_args, int max_size, Arguments args, va_list pl)
{
	(void) max_size;
	assert(args);
	const char ** point = new_args;
	while (*args)
	{
		assert(point < (new_args + max_size));
		*point++ = *args++;
	}
	while ((*point = va_arg(pl, const char *)))
	{
		assert(point < (new_args + max_size));
		point++;
	}
	*point++ = NULL;

	return (point - new_args) / sizeof(char*);
}

int arrangeArgs(const char ** new_args, int max_size, Arguments args1, Arguments args2)
{
	(void) max_size;
	assert(new_args && args1 && args2);
	const char ** point = new_args;

	while (*args1)
	{
		assert(point < (new_args + max_size));
		*point++ = *args1++;
	}
	while (*args2)
	{
		assert(point < (new_args + max_size));
		*point++ = *args2++;
	}
	*point++ = NULL;

	return (point - new_args) / sizeof(char*);
}

#define BIN_VZMDEST	"/usr/sbin/vzmdest"
#define BIN_VZMDESTEMPL	"/usr/sbin/vzmdestmpl"
#define OLD_MIGRATE_INVITATION	"vzmdest"

int init_connection(MigrateStateCommon *st)
{
	int rc;
	int i;

	if (isOptSet(OPT_AGENT)) {
		if ((rc = vza_init_cli(&st->channel.ctx, &st->channel.conn)))
			return rc;
		goto finish;
	} else if (isOptSet(OPT_PS_MODE)) {
		rc = st->channel.createParallelsServerChannel();
		if (rc)
			return rc;
		/* Send own version to vzmdest */
		if ((rc = st->channel.sendPkt(CMD_START_PARAMS "%d", MIGRATE_VERSION)))
			return rc;
		/* wait reply with vzmdest version */
		char *reply = st->channel.readPkt(PACKET_SEPARATOR, &rc);
		if (reply == NULL) {
			return putErr(MIG_ERR_PROTOCOL, MIG_MSG_REPLY);
		} else if (rc) {
			return putErr(rc, MIG_MSG_REPLY);
		}
		if (sscanf(reply, VZMDEST_REPLY, &VZMoptions.remote_version) != 1)
			return putErr(MIG_ERR_PROTOCOL, "invalid reply from server : %s", reply);

		goto finish;
	} else if (isOptSet(OPT_SOCKET)) {
		rc = st->channel.createSockChannel(VEArgs);
		if (rc)
			return rc;
		goto finish;
	}
	// simply start 'vzmdest' through ssh
	const char ** args;
	char version[ITOA_BUF_SIZE];
	struct string_list args_list;
	string_list_init(&args_list);

	snprintf(version, sizeof(version), "%u", VZMoptions.version);

	if (isOptSet(OPT_SUDO))
		string_list_add(&args_list, BIN_SUDO);
	string_list_add(&args_list, VZMoptions.bintype == BIN_TEMPL ? (char*)BIN_VZMDESTEMPL : (char*)BIN_VZMDEST);
	string_list_add(&args_list, version);
	if (debug_level >= LOG_DEBUG)
		string_list_add(&args_list, "-v");
	if (isOptSet(OPT_ONLINE))
		string_list_add(&args_list, "--online");
	if (isOptSet(OPT_EZTEMPLATE))
		string_list_add(&args_list, "-z");
	for (i = 0; VEArgs[i]; i++)
		string_list_add(&args_list, (char *)VEArgs[i]);
	if ((rc = string_list_to_array(&args_list, (char ***)&args)) == 0) {
		const char ** ssh_args;
		if (isOptSet(OPT_SSH_FWD))
			st->channel.fwdAddPort(&VZMoptions);
		if ((rc = string_list_to_array(&VZMoptions.ssh_options, (char ***)&ssh_args)) == 0) {
			rc = st->channel.createSshChannel(ssh_args, args);
			for (i = 0; ssh_args[i]; i++)
				free((void *)ssh_args[i]);
			free((void *)ssh_args);
		}
		for (i = 0; args[i]; i++)
			free((void *)args[i]);
		free((void *)args);
	}
	string_list_clean(&args_list);
	if (rc) {
		logger(LOG_ERR, "Can not create connection to %s", VZMoptions.dst_addr);
		return rc;
	}

	// read ssh output and report to user
	rc = -1;
	int code;
	const char * str;

	while ((str = st->channel.readPkt('\n', &code)))
	{
		int remote_version = -1;
		if (sscanf(str, VZMDEST_REPLY, &remote_version) == 1)
		{
			// ssh connection established,
			// reply was received from destination side
			VZMoptions.remote_version = remote_version;
			rc = 0;
		}
		else if (!strncmp(str, OLD_MIGRATE_INVITATION, strlen(OLD_MIGRATE_INVITATION)))
		{
			VZMoptions.remote_version = MIGRATE_VERSION_OLD;
			rc = 0;
		}
		if (!rc)
			break;

		// report any (usually error message) ssh output
		logger(LOG_ERR, "%s", str);
	}

	if (rc != 0)
	{
		int status = st->channel.closeChannel();
		switch (status)
		{
		case 127:
			return putErr(MIG_ERR_CANT_CONNECT, MIG_MSG_NOT_INSTALL);
		}
		return putErr(MIG_ERR_CANT_CONNECT, MIG_MSG_CANT_CONNECT);
	}

	// read initialization reply
	rc = st->channel.readReply();
	if (rc != 0)
		return rc;
finish:
	// migrations support only protocol >= 400 on destination.
	logger(LOG_DEBUG, "remote_version %d", VZMoptions.remote_version);

	logger(LOG_INFO, "Connection to destination node (%s) is successfully established",
	       VZMoptions.dst_addr);
	return 0;
}

int vzlayout_to_option(int layout)
{
	if (layout >= VZCTL_LAYOUT_5)
		return MIGINIT_LAYOUT_5;
	else if (layout == VZCTL_LAYOUT_4)
		return MIGINIT_LAYOUT_4;
	return 0;
}

int veformat_to_option(int veformat)
{
	if (veformat == VZ_T_VZFS4)
		return MIGINIT_VZFS4;
	else if (veformat == VZ_T_SIMFS)
		return MIGINIT_SIMFS;
	return 0;
}

int option_to_vzlayout(int options)
{
	if (options & MIGINIT_LAYOUT_5)
		return VZCTL_LAYOUT_5;
	else if (options & MIGINIT_LAYOUT_4)
		return VZCTL_LAYOUT_4;
	return VZCTL_LAYOUT_3;
}

int option_to_veformat(int options)
{
	if (options & MIGINIT_SIMFS)
		return VZ_T_SIMFS;
	else if (options & MIGINIT_VZFS4)
		return VZ_T_VZFS4;
	return VZ_T_VZFS3;
}

StringListWrapper::StringListWrapper()
{
	string_list_init(&m_list);
}

StringListWrapper::~StringListWrapper()
{
	string_list_clean(&m_list);
}

std::vector<std::string> StringListWrapper::toVector() const
{
	std::vector<std::string> vec;
	string_list_el *e;

	string_list_for_each(&m_list, e) {
		vec.push_back(e->s);
	}

	return vec;
}

ExecveArrayWrapper::ExecveArrayWrapper(const std::vector<std::string>& array)
{
	m_count = (array.size() + 1);
	m_array = new char* [m_count];

	for (size_t i = 0; i < array.size(); ++i) {
		m_array[i] = new char [array[i].size() + 1];
		strncpy(m_array[i], array[i].c_str(), array[i].size() + 1);
	}
	m_array[array.size()] = NULL;
}

ExecveArrayWrapper::~ExecveArrayWrapper()
{
	for (size_t i = 0; i < m_count; ++i) {
		delete [] m_array[i];
	}
	delete [] m_array;
}
