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
#ifndef _BINCOM_H_
#define _BINCOM_H_

#include <signal.h>
#include <stdarg.h>

#include <string>
#include <vector>
using namespace std;

#define BNAME_LOCAL		"vzmlocal"
#define BNAME_SRC		"vzmsrc"
#define BNAME_MIGRATE		"vzmigrate"
#define BNAME_TEMPLATE		"vzmtemplate"
#define BNAME_PM_C2C		"pmigrate.c2c"
#define BNAME_DEST		"vzmdest"

#include "common.h"
#include "util.h"

#define INIT_BIN(btype, debuglevel, logname) do {	\
	VZMoptions.bintype = btype;			\
	debug_level = debuglevel;			\
	open_logger(logname);				\
} while (0)

int init_sig_handlers(__sighandler_t handler = NULL);
int disable_sig_handler();
void parse_options (int argc, char **argv);

struct VEOptEntry
{
	ctid_t src_ctid;
	ctid_t dst_ctid;
	const char * root_path;
	const char * priv_path;
	char * dst_name;
	char * uuid;
	VEOptEntry()
	{
		SET_CTID(src_ctid, NULL);
		SET_CTID(dst_ctid, NULL);
		root_path = priv_path = dst_name = uuid = NULL;
	};
	~VEOptEntry()
	{
		if (dst_name)
		{
			free(dst_name);
			dst_name = NULL;
		}
		if (uuid)
			free(uuid);
	};
};
typedef vector<struct VEOptEntry *> VEOptEntries;
typedef vector<string> TemplOptEntries;

#define VZMDEST_REPLY		"migrate %d"

#define MIGRATE_VERSION			MIGRATE_VERSION_700
#define MIGRATE_VERSION_700		700
#define MIGRATE_VERSION_612		612
#define MIGRATE_VERSION_611 	611
/* fix for converting second level quota for online migration */
#define MIGRATE_VERSION_608 	608
/* add degradation to rsync with checksum if tracker failed on vzfs -> vzfs*/
#define MIGRATE_VERSION_607 	607
/* CMD_CREATE_PLOOP_SNAPSHOT_NO_ROLLBACK */
#define MIGRATE_VERSION_606	606
/* convertation with bindmounts */
#define MIGRATE_VERSION_605 	605
/* new ploop (large disks) */
#define MIGRATE_VERSION_604 	604
/* HA cluster */
/* pcs */
/* ploop-based CT */
#define MIGRATE_VERSION_550 	550
/* iSCSI storage support added */
/* kernel modules check added */
#define MIGRATE_VERSION_500 	500
/* ssh forwarding was added (OPT_SSH_FWD) */
#define MIGRATE_VERSION_470 	470
/* nfs support added */
#define MIGRATE_VERSION_460 	460
#define MIGRATE_VERSION_401 	401
#define MIGRATE_VERSION_400 	400
#define MIGRATE_VERSION_250 	250 // in virtuozzo 3.0 used this protocol
#define MIGRATE_VERSION_202 	202
#define MIGRATE_VERSION_OLD 	0

#define BIN_LOCAL	0
#define BIN_SRC		1
#define BIN_DEST	3

#define OPT_COPY	(1ULL << 0)
#define OPT_AGENT	(1ULL << 1)
#define OPT_REMOVE	(1ULL << 2)
#define OPT_FORCE	(1ULL << 3)
#define OPT_NOSTART	(1ULL << 4)
#define OPT_PROGRESS	(1ULL << 5)
#define OPT_NOQUOTA	(1ULL << 6)
#define OPT_NOTRACK	(1ULL << 7)
#define OPT_KEEPER	(1ULL << 8)
#define OPT_KEEP_DST	(1ULL << 9)
#define OPT_ONLINE	(1ULL << 10)
#define OPT_NOCONTEXT	(1ULL << 11)
#define OPT_REPAIR_NEWTEM	(1ULL << 12) /* not used */
#define OPT_NOITER	(1ULL << 13)
#define OPT_REALTIME	(1ULL << 14)
#define OPT_SKIP_LOCKVE (1ULL << 15)
#define OPT_SKIP_CHECKCPU (1ULL << 16)
#define OPT_SKIP_DISKSPACE (1ULL << 17)
#define OPT_SKIP_TECHNOLOGIES (1ULL << 18)
#define OPT_SKIP_LICENSE (1ULL << 19)
#define OPT_SKIP_RATE (1ULL << 20)
#define OPT_EZTEMPLATE (1ULL << 21)
#define OPT_DRY_RUN (1ULL << 22)
#define OPT_SKIP_EXT_BINDMOUNT (1ULL << 24)
#define OPT_AGENT40 (1ULL << 25)
#define OPT_NONSHAREDFS (1ULL << 26)
#define OPT_WHOLE_FILE	(1ULL << 27)
/* This option added forcibly to use rsync instead of tar.
   Now it will use in 'progress-bar' mode for EZ directories
   and private area coping. This option send to destination
   node and if node supported it, will use rsync.
   For 3.0 : will always use rsync.
   For 4.0.0 : will use rsync for private area if .migrated
   exist on dst. */
#define OPT_USE_RSYNC	(1ULL << 28)
/* To show progress messages.
   Used in agent mode only to show progress bar in GUI (#100902) */
#define OPT_APROGRESS	(1ULL << 29)
#define OPT_READONLY    (1ULL << 30)
#define OPT_SKIP_TEMPLATE_AREA_SYNC (1ULL << 31)
#define OPT_SOCKET	(1ULL << 32)
#define OPT_KEEP_IMAGES	(1ULL << 33)
#define OPT_SUDO	(1ULL << 34)
#define OPT_SSH_FWD	(1ULL << 35) /* to use ssh port forwarding (-L option) */
#define OPT_PS_MODE	(1ULL << 36)
#define OPT_KEEP_SRC	(1ULL << 37) /* Keep source CT - internal option for OPT_PS_MODE */
#define OPT_SKIP_CPT_IMAGE_VERSION	(1ULL << 38) /* unused */
#define OPT_SKIP_CAPABILITIES		(1ULL << 39) /* unused */
#define OPT_SKIP_KERNEL_MODULES		(1ULL << 40)
/* do not compress disk image data on online ploop migration */
#define OPT_NOCOMPRESS	(1ULL << 41)
#define OPT_CONVERT_VZFS	(1ULL << 42)
#define OPT_SKIP_UMOUNT	(1ULL << 43)
#define OPT_IGNORE_BACKUP_DISK	(1ULL << 44)
#define OPT_NOEVENT	(1ULL << 45)

#define DSTACT_UNDUMP_VE	10
#define DSTACT_RESUME_VE	11

extern ctid_t g_keeperCTID;
extern const char * service_root;

struct timeout {
	long val;
	char str[100];
	int customized;
};

struct CVZMOptions
{
	VEOptEntries veMigrateList;
	TemplOptEntries templMigrateList;

	string bigname;
	unsigned long long options;
	char * src_addr;
	char * dst_addr;
	char * dst_user;
	char * dst_pwd;
	int bintype;
	int remote_version;
	int version;
	int invert_lazy_flag;
	struct timeout tmo;
	struct string_list ssh_options;
	int cmd_sock;
	int data_sock;
	int tmpl_data_sock;
	int swap_sock;

	CVZMOptions();
	~CVZMOptions();
};

#define isOptSet(b) (isSetBit(VZMoptions.options, b))
#define setOpt(b) (setBit(VZMoptions.options, b))
#define unSetOpt(b) (unsetBit(VZMoptions.options, b))

extern CVZMOptions VZMoptions;
extern const char * VEArgs[];

extern const char * ssh_args[];
extern const char * ssh_test[];

#define VZA_SSH_MAIN_SFX	""
#define VZA_SSH_ONLINE_SFX	":1"
#define VZA_SSH_TAR_SFX		":2"

#define DEF_DIR_MODE 0755

/* Default connection timeout in seconds.
   Up to 1 hour for migration large VE from 3.0.
   vzmigrate-3.0 can not set timeout, but time of start of tracker
   can be more than 30 mins (#99865) */
#define IO_TIMEOUT     3600

#define BIN_VZCTL	"/usr/sbin/vzctl"
#define BIN_VZPKG	"/usr/sbin/vzpkg"
#define BIN_PLOOP	"/usr/sbin/ploop"
#define BIN_HAMAN	"/usr/sbin/shaman"

#define BIN_SUDO "sudo"

#define BIN_TAR "/bin/tar"

#define BIN_PHAUL				"/usr/libexec/phaul/p.haul"
#define BIN_PHAUL_SRV			"/usr/libexec/phaul/p.haul-service"
#define PHAUL_LOG_FILE			"/var/log/phaul.log"
#define PHAUL_SRV_LOG_FILE		"/var/log/phaul-service.log"

#ifndef GFS_MAGIC
#define GFS_MAGIC               (0x01161970)
#endif
#ifndef NFS_SUPER_MAGIC
#define NFS_SUPER_MAGIC                     0x6969
#endif
#ifndef REISERFS_SUPER_MAGIC
#define REISERFS_SUPER_MAGIC		0x52654973
#endif
#ifndef PCS_SUPER_MAGIC
#define PCS_SUPER_MAGIC			0x65735546
#endif

/*
 AFAIK there are free ports, according
 http://www.iana.org/assignments/port-numbers
*/
#define VZMD_DEF_PORT "4422"

typedef const char * const Arguments[];
int arrangeArgs(const char ** new_args, int max_size, Arguments args, ...);
int arrangeArgs(const char ** new_args, int max_size, Arguments args, va_list pl);
int arrangeArgs(const char ** new_args, int max_size, Arguments args1, Arguments args2);

const string getProgArgs(Arguments args);

// Migrate initialization options
enum {
	MIGINIT_KEEP_DST	= 1,
	MIGINIT_LAYOUT_4	= (1<<1),
	MIGINIT_VZFS4		= (1<<2),
	MIGINIT_LAYOUT_5	= (1<<3),
	MIGINIT_SIMFS		= (1<<4),
	MIGINIT_CONVERT_VZFS	= (1<<5),
};

int vzlayout_to_option(int layout);
int veformat_to_option(int veformat);
int option_to_vzlayout(int options);
int option_to_veformat(int options);

enum {
	SIMPLECOPY  = 0,
	FASTCOPY    = 1,
	DUMPCOPY    = 2,
	SUSPENDCOPY = 3, /* unused */
	FASTCOPY_BINDMOUNTS = 4,
	FASTCOPY_CHECKSUM = 5,
	FASTCOPY_TRACKER = 6,
};

/* Helper class to simplify string_list construction and destruction */
class StringListWrapper {
public:
	StringListWrapper();
	~StringListWrapper();
	string_list& getList() { return m_list; }
	std::vector<std::string> toVector() const;
private:
	// Forbidden class methods
	StringListWrapper(const StringListWrapper&);
	StringListWrapper& operator =(const StringListWrapper&);
private:
	string_list m_list;
};

/*
 * Helper class to simplify construction of argv or envp arguments for execve
 * and similar functions.
 */
class ExecveArrayWrapper {
public:
	ExecveArrayWrapper(const std::vector<std::string>& array);
	~ExecveArrayWrapper();
	char *const * getArray() const { return m_array; }
private:
	// Forbidden class methods
	ExecveArrayWrapper(const ExecveArrayWrapper&);
	ExecveArrayWrapper& operator =(const ExecveArrayWrapper&);
private:
	size_t m_count;
	char** m_array;
};

#endif
