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
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/sysmacros.h>
#include <libgen.h>
#include <linux/limits.h>
#include <sys/vfs.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <mntent.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <linux/types.h>

#include <vzctl/libvzctl.h>

#include <sstream>
#include <vector>
#include <string>

#include "migsrcremote.h"
#include "migssh.h"
#include "vzacompat.h"
#include "channel.h"
#include "remotecmd.h"
#include "veentry.h"
#include "util.h"
#include "multiplexer.h"

#define DUMMY_DEST "0.0.0.0:/dummy"

#ifdef __x86_64__
#define	__NR_syncfs	306
#else
#define	__NR_syncfs	344
#endif

extern struct vz_data *vzcnf;
extern const char * actionScripts[];

static int copy_remote_tar(
		MigrateSshChannel *ch,
		const char *cmd,
		const char *bdir,
		const list<string> &names);

void reportStage(const char* stage)
{
        int rc;

	if (VZMoptions.progress_fd <= 0 || fcntl(VZMoptions.progress_fd, F_GETFL) == -1
		|| !stage || !stage[0])
		return;

	std::string s = stage;
	s += "\n";
	rc = write(VZMoptions.progress_fd, s.c_str(), s.length());
	if (rc == -1)
		logger(LOG_ERR, "Failed to write inside reportStage: %m");
}

MigrateStateRemote::MigrateStateRemote(
		const char * src_ctid,
		const char * dst_ctid,
		const char * priv,
		const char * root,
		const char *dst_name)
	: MigrateStateSrc(src_ctid, dst_ctid, NULL, priv, root, dst_name),
	m_bIsPrivOnShared(false)
{
	is_keep_dir = 0;

	m_isTargetInHaCluster = 0;

	/* TODO: check g_keeperCTID */
	if (isOptSet(OPT_KEEPER)) {
		keepVE = new VEObj(g_keeperCTID);
		addCleaner(clean_delVeobj, keepVE, NULL, ANY_CLEANER);
	}

	m_criuErrLog = std::string(vzcnf->dumpdir);
	m_criuErrLog.append("/").append(srcVE->ctid()).append("-criu_err.log");
	unlink(m_criuErrLog.c_str());
	addCleaner(clean_removeFile, m_criuErrLog.c_str());
};

MigrateStateRemote::~MigrateStateRemote()
{
}

int MigrateStateRemote::checkIPAddresses()
{
	char cmd[BUFSIZ];
	struct string_list_el *p;

	if (string_list_empty(&srcVE->ve_data.ipaddr))
		return 0;

	strcpy(cmd, CMD_CHECK_IPS);
	string_list_for_each(&srcVE->ve_data.ipaddr, p) {
		strncat(cmd, " ", sizeof(cmd)-strlen(cmd)-1);
		strncat(cmd, p->s, sizeof(cmd)-strlen(cmd)-1);
	}
	logger(LOG_INFO, "Checking IP addresses on destination node");
	return channel.sendCommand(cmd);
}

//check rate
int MigrateStateRemote::checkRate()
{
	if (VZMoptions.remote_version < MIGRATE_VERSION_400)
		return 0;

	if (string_list_empty(&srcVE->ve_data.rate))
		return 0;
	logger(LOG_INFO, "Checking RATE parameters in config");
	return channel.sendCommand(CMD_CHECKRATE);
}

//check avail license
int MigrateStateRemote::checkAvailLicense()
{
	// skip license check for old versions and starting from Vz7
	if ((VZMoptions.remote_version < MIGRATE_VERSION_400) ||
		(VZMoptions.remote_version >= MIGRATE_VERSION_700))
		return 0;

	logger(LOG_INFO, "Checking license restrictions");
	return channel.sendCommand(CMD_CHECKLICENSE);
}

/* check target VE name */
int MigrateStateRemote::checkDstName()
{
	if (dstVE->ve_data.name == NULL)
		return 0;
	if (strlen(dstVE->ve_data.name) == 0)
		return 0;
	if (VZMoptions.remote_version < MIGRATE_VERSION_400) {
		logger(LOG_WARNING, "Cannot check target CT name: old remote"\
			" version: %d", VZMoptions.remote_version);
		return 0;
	}
	logger(LOG_INFO, "Check target CT name: %s", dstVE->ve_data.name);
	return channel.sendCommand(CMD_VENAME " %s", dstVE->ve_data.name);
}

int MigrateStateRemote::checkDiskSpaceValues(
		unsigned long long bytes, unsigned long long inodes)
{
	char buf[255];

	if (VZMoptions.remote_version < MIGRATE_VERSION_400)
		return 0;

	snprintf(buf, sizeof(buf), CMD_CHECK_DISKSPACE " %llu %llu", bytes, inodes);
	logger(LOG_DEBUG, "%s", buf);

	return channel.sendCommand(buf);
}

int MigrateStateRemote::checkTechnologies()
{
	char buf[ITOA_BUF_SIZE];

	if (VZMoptions.remote_version < MIGRATE_VERSION_400)
		return 0;

	logger(LOG_INFO, "Checking technologies");

	ostringstream outStr;
	snprintf(buf, sizeof(buf), "%lu", srcVE->ve_data.technologies);
	outStr << CMD_CHECK_TECHNOLOGIES << " " << buf;
	logger(LOG_DEBUG, "%s",  outStr.str().c_str());

	channel.sendPkt(PACKET_SEPARATOR, outStr.str().c_str());
	int errcode = 0;
	const char * reply = channel.readReply(&errcode);
	if (reply == NULL)
		return putErr(MIG_ERR_CONN_BROKEN, MIG_MSG_REPLY);
	if (errcode != 0)
		putErr(errcode, "%s", reply);

	istringstream is(reply);
	string cmd;
	unsigned long utech = 0;

	if ((is >> cmd >> utech) == NULL || \
			cmd.compare(CMD_CHECK_TECHNOLOGIES) != 0)
		return putErr(MIG_ERR_PROTOCOL, MIG_MSG_PROTOCOL);

	if (utech) {
		size_t i;
		unsigned long tech;
		char buf[100];
		const char *str;

		buf[0] = '\0';
		for (i = 0; i < sizeof(utech); i++) {
			tech = utech & (1 << i);
			if (tech == 0)
				continue;
			if ((str = vzctl2_tech2name(tech)) == NULL)
				continue;
			strncat(buf, " ", sizeof(buf)-strlen(buf)-1);
			strncat(buf, str, sizeof(buf)-strlen(buf)-1);
		}
		return putErr(MIG_ERR_TECHNOLOGIES, MIG_MSG_TECHNOLOGIES, buf);
	}

	return 0;
}

/* adjust some options with recipient
   note : now we use 64-bits variable, but previous vzmigrate use 32 bits only */
int MigrateStateRemote::checkOptions(unsigned long long *options)
{
	int rc;
	unsigned long long opts = 0;
	char buffer[BUFSIZ];

	if (VZMoptions.remote_version >= MIGRATE_VERSION_470) {
		opts |= *options & OPT_SSH_FWD;
	}

	if (VZMoptions.remote_version >= MIGRATE_VERSION_460) {
		opts |= *options & OPT_WHOLE_FILE;
		opts |= *options & OPT_USE_RSYNC;
	} else if (VZMoptions.remote_version == MIGRATE_VERSION_401) {
		opts |= (*options & 0xFFFFFFFF) & OPT_WHOLE_FILE;
		opts |= (*options & 0xFFFFFFFF) & OPT_USE_RSYNC;
	}

	if (opts) {
		/* do not send command if opts == 0 (as sample for vzmdest version 3.0) */
		snprintf(buffer, sizeof(buffer), CMD_CHECK_OPTIONS " %llu", opts);
		logger(LOG_DEBUG, buffer);

		if ((rc = sendRequest(buffer, (long *)&opts)))
			return rc;
	}

	if ((*options & OPT_WHOLE_FILE) && !(opts & OPT_WHOLE_FILE)) {
		logger(LOG_INFO, "Option --whole-file is not supported by recipient, ignored");
		*options &= ~OPT_WHOLE_FILE;
	}
	if ((*options & OPT_USE_RSYNC) && !(opts & OPT_USE_RSYNC)) {
		logger(LOG_INFO, "OPT_USE_RSYNC is not supported by recipient, ignored");
		*options &= ~OPT_USE_RSYNC;
	}
	if ((*options & OPT_SSH_FWD) && !(opts & OPT_SSH_FWD)) {
		if (isOptSet(OPT_SUDO)) {
			return putErr(MIG_ERR_SYSTEM, "The destination side does not support --sudo options");
		} else {
			logger(LOG_INFO, "OPT_SSH_FWD is not supported by recipient, ignored");
			*options &= ~OPT_SSH_FWD;
		}
	}

	return 0;
}

/* check that keep dir exist on destination node */
int MigrateStateRemote::checkKeepDir()
{
	if (m_nFlags & VZMSRC_SHARED_PRIV)
		/* forget about it for private on the same
		   shared cluster partition */
		return 0;

	logger(LOG_INFO, "Checking keep dir for private area copy");

	return sendRequest((char *)CMD_CHECK_KEEP_DIR, &is_keep_dir);
}

/* get & check ploop format for ploop-based VE private */
int MigrateStateRemote::checkPloopFormat()
{
	int rc;
	int version;
	ostringstream outStr;

	if (srcVE->layout < VZCTL_LAYOUT_5)
		return 0;

	if ((rc = srcVE->getPloopMaxVersion(version)))
		return rc;

	// 0 - raw, 1 - old, 2 -new formats
	// 0 & 1 are supports by psbm-6
	if (version < 2)
		return 0;

	if (VZMoptions.remote_version < MIGRATE_VERSION_604)
		return putErr(MIG_ERR_PLOOP_FORMAT, MIG_MSG_PLOOP_FORMAT, version);

	logger(LOG_INFO, "Checking ploop format %d", version);
	outStr << CMD_CHECK_PLOOP_FORMAT << " " << version;
	logger(LOG_DEBUG, "%s",  outStr.str().c_str());

	return channel.sendCommand(outStr.str().c_str());
}

/* check shared fs type and id for source VE private,
   and send request in success.
   destination node return '1' if target VE private is
   on same shared fs with the same local path */
int MigrateStateRemote::checkSharedDir(
		const char *cmd,
		const char *dir,
		const char *title,
		int *shared,
		int *reply)
{
	int rc = 0;
	char path[PATH_MAX+1];
	int fd;
	char *name;
	long ret;
	long fstype;
	int dir_shared;

	*shared = 0;
	*reply = 0;
	/* vzmigrate does not known nothing about cluster until 400 */
	if (VZMoptions.remote_version < MIGRATE_VERSION_400)
		return 0;

	if ((rc = is_path_on_shared_storage(dir, &dir_shared, &fstype)))
		return rc;

	if (!dir_shared)
		return 0;

	/* For NFS we can't get unique FS ID.
	   Therefore will create temporary file via mkstemp,
	   send file name in request and seek it on dst node.
	   And since 4.7 will use this scheme for gfs/gfs2 too.
	   (see https://jira.sw.ru/browse/PCLIN-29873)
	*/
	if (	(fstype == NFS_SUPER_MAGIC) &&
		(VZMoptions.remote_version < MIGRATE_VERSION_401))
			return 0;

	if (	(fstype == PCS_SUPER_MAGIC) &&
		(VZMoptions.remote_version < MIGRATE_VERSION_550))
			return 0;

	*shared = 1;

	logger(LOG_DEBUG, "Source %s resides on shared partition %s",
			title, fstype == NFS_SUPER_MAGIC ? "NFS" : "vstorage");
	/* create temporary file */
	snprintf(path, sizeof(path), "%s/vzmigrate_shared_file_XXXXXX", dir);
	if ((fd = mkstemp(path)) == -1)
		return putErr(MIG_ERR_SYSTEM, "mkstemp(%s)", path);
	close(fd);
	name = basename(path);

	std::ostringstream req;

	req << cmd << " " << name << " " << dir;	
	rc = sendRequest(req.str().c_str(), &ret);
	unlink(path);
	if (ret) {
		logger(LOG_INFO, "Source and target %s resides "
			"on the same shared partition", title);
	}
	*reply = ret;

	return rc;
}

int MigrateStateRemote::checkSharedFile(const char *dir, bool *shared)
{
	int rc, fd;
	char file[PATH_MAX+1];
	long reply;

	snprintf(file, sizeof(file), "%s/vzmigrate_shared_file_XXXXXX", dir);

	if ((fd = mkstemp(file)) == -1)
		return putErr(MIG_ERR_SYSTEM, "mkstemp(%s) : %m", file);
	close(fd);

	std::ostringstream req;

	req << CMD_CHECK_SHARED_FILE" " << file;
	rc = sendRequest(req.str().c_str(), &reply);

	unlink(file);

	*shared = !!reply;

	return rc;
}

int MigrateStateRemote::checkSharedDisk()
{
	int rc;

	for (ct_disk::iterator it = srcVE->m_disks.begin();
			it != srcVE->m_disks.end(); ++it)
	{
		if (it->is_device())
			it->shared = true;
		else if (it->is_external()) {
			if ((rc = checkSharedFile(it->image.c_str(), &(it->shared))))
				return rc;
		} else if (m_nFlags & VZMSRC_SHARED_PRIV)
			it->shared = true;

		if (it->is_shared())
			logger(LOG_ERR, "Shared disk detected %s",
					it->image.c_str());
	}

	return 0;
}

/* check cluster id for source VE private, and send request in success.
   destination node return '1' if target VE private is on same cluster */
int MigrateStateRemote::checkClusterID()
{
	int rc = 0;
	int shared;
	int is_thesame_shared;

	if (VZMoptions.remote_version < MIGRATE_VERSION_400)
		return 0;

	logger(LOG_INFO, "Check cluster ID");

	/* for VE private */
	if ((rc = checkSharedDir(
		CMD_CHECK_SHARED_PRIV,
		srcVE->priv, "CT private",
		&shared, &is_thesame_shared)))
		return rc;

	m_bIsPrivOnShared = shared;
	if (shared && !is_thesame_shared && !isOptSet(OPT_NONSHAREDFS)) {
		/*
		 * Changing CTID while migrating CT, residing on a shared partition
		 * is not supported because of possible private area intersection
		 * problems on a destination node.
		 * See https://jira.sw.ru/browse/PSBM-14346
		 */
		if (CMP_CTID(srcVE->ctid(), dstVE->ctid()) != 0) {
			return putErr(MIG_ERR_NONSHAREDFS,
				"Changing ID for CT "
				"which private directory resides on the\n"
				"shared partition is not supported, change "
				"ID manually, e.g. by using vzmlocal.\n"
				"Or use --nonsharedfs option to force copying "
				"CT private data.");
		} else if (dstVE->priv != srcVE->priv) {
			return putErr(MIG_ERR_NONSHAREDFS,
				"Changing private area for CT on the "
				"shared partition is not supported, use\n"
				"--nonsharedfs option to force copying "
				"CT private data.");
		} else {
			return putErr(MIG_ERR_NONSHAREDFS,
				"CT private directory on the "
				"destination node resides on the\n"
				"non-shared partition, use "
				"--nonsharedfs option to force copying\n"
				"CT private data.");
		}
	}
	if (is_thesame_shared)
		m_nFlags |= VZMSRC_SHARED_PRIV;

	if ((rc = checkSharedDisk()))
		return rc;

	/* for template area */
	if (srcVE->veformat != VZ_T_SIMFS) {
		if ((rc = checkSharedDir(
			CMD_CHECK_SHARED_TMPL,
			srcVE->tmplDir().c_str(), "template area",
			&shared, &is_thesame_shared)))
			return rc;
		if (shared && !is_thesame_shared) {
			logger(LOG_WARNING, "template area on the destination "
				"node resides on the\n"
				"non-shared partition, will to copy.");
		}
		if (is_thesame_shared)
			m_nFlags |= VZMSRC_SHARED_TMPL;
	}

	/* for dump dir */
	if (isOptSet(OPT_ONLINE)) {
		/* dumpdir is placed at private, so just check is private shared */
		if (m_nFlags & VZMSRC_SHARED_PRIV)
			m_nFlags |= VZMSRC_SHARED_DUMP;
	}

	return 0;
}

int MigrateStateRemote::doCtMigration()
{
	// Sanity checks and preparations
	int rc = preMigrateStage();
	if (rc)
		goto error;

	if (srcVE->isrun()) {
		if (srcVE->layout < VZCTL_LAYOUT_5)
			return putErr(-1, MIG_MSG_SIMFS_TRYOFFLINE);
		if (VZMoptions.remote_version < MIGRATE_VERSION_700)
			return putErr(-1, MIG_MSG_TRYOFFLINE);

		if (isOptSet(OPT_KEEP_SRC))
			rc = doPloopCtClone();
		else
			rc = doCtMigrationPhaul();
	} else
		rc = doCtMigrationOffline();

	if (rc)
		goto error;

	return 0;

error:
	finishDestination();
	return rc;
}

int MigrateStateRemote::doCtMigrationOffline()
{
	int rc;

	if (srcVE->ismount()) {
		rc = srcVE->umount();
		if (rc)
			return rc;
	}

	if (srcVE->layout >= VZCTL_LAYOUT_5)
		rc = doOfflinePloopCtMigration();
	else
		rc = doOfflineSimfsCtMigration();

	if (rc)
		return rc;

	// keeper, restore state VE
	if ((rc = startVEStage()))
		return rc;

	// VE final cleaning
	rc = postFinalStage();

	return rc;
}

int MigrateStateRemote::doCtMigrationPhaul()
{
	// Handle online migration of ploop container (in live or restart modes)
	int rc = doOnlinePloopCtMigration();
	if (rc != 0)
		return rc;

	// Container restored on destination; CAN'T FAIL STARTING FROM THIS POINT
	rc = channel.sendCommand(CMD_FINAL " %d", DSTACT_NOTHING);

	// VE final cleaning
	if (rc == 0)
		postFinalStage();

	return rc;
}

int MigrateStateRemote::sendVersionCmd()
{
	int errcode = 0;

	channel.sendPkt(PACKET_SEPARATOR, CMD_VERSION " %d", VZMoptions.version);
	const char *reply = channel.readReply(&errcode);

	if (reply == NULL)
		return putErr(MIG_ERR_CONN_BROKEN, MIG_MSG_REPLY);
	if (errcode == MIG_ERR_PROTOCOL)
		VZMoptions.remote_version = MIGRATE_VERSION_OLD;
	else if (errcode != 0)
		return putErr(errcode, "%s", reply);
	VZMoptions.remote_version = atoi(reply);

	return 0;
}

int MigrateStateRemote::sendInitCmd()
{
	int options = 0;

	options |= vzlayout_to_option(srcVE->layout);
	options |= veformat_to_option(srcVE->veformat);
	options |= isOptSet(OPT_KEEP_DST) ? MIGINIT_KEEP_DST : 0;
	if (isOptSet(OPT_KEEP_SRC))
		options |= MIGINIT_KEEP_SRC; 

	return channel.sendCommand(CMD_INIT " %s %d", dstVE->ctid(), options);
}

int MigrateStateRemote::checkRemoteVersion()
{
	if (VZMoptions.remote_version < MIGRATE_VERSION_400) {
		return putErr(MIG_ERR_LAYOUT, MIG_MSG_LAYOUT, srcVE->layout);
	} else if (VZMoptions.remote_version < MIGRATE_VERSION_550) {
		/* check new layout */
		if (srcVE->layout >= VZCTL_LAYOUT_5)
			return putErr(MIG_ERR_LAYOUT, MIG_MSG_LAYOUT, srcVE->layout);
	} else if (VZMoptions.remote_version < MIGRATE_VERSION_700) {
		/* online migration from 7.0 to lower version is not supported */
		if (isOptSet(OPT_ONLINE))
			return putErr(MIG_ERR_ONLINE_ELDER, MIG_MSG_ONLINE_ELDER);
	}

	if (VZMoptions.remote_version < MIGRATE_VERSION_607 &&
			srcVE->m_disks.size() > 1)
		return putErr(MIG_ERR_MULTIPLOOP_IS_NOT_SUP, MIG_MSG_MULTIPLOOP_IS_NOT_SUP);

	if (isOptSet(OPT_USE_RSYNC) && (srcVE->layout >= VZCTL_LAYOUT_5))
		return putErr(MIG_ERR_LAYOUT,
				"The migration via rsync is not supported for ploop-based CT");

	// Backward compatibility for migration with compression on pre-7.0.9 hosts
	if (VZMoptions.remote_version < MIGRATE_VERSION_709 && !isOptSet(OPT_NOCOMPRESS))
	{
		logger(LOG_INFO, "Enabling backward compatibility for compressed migration.");
		string_list_add(&VZMoptions.ssh_options, "-C");
		setOpt(OPT_NOCOMPRESS);
	}

	return 0;
}

int MigrateStateRemote::createKeepDstSnapshots()
{
	int rc = 0;
	std::list<std::string> created;
	ct_disk disks(srcVE->m_disks.get(disk_is_non_shared));
	// Create snapshots with predefined GUID.
	for (ct_disk::iterator it = disks.begin(); it != disks.end(); ++it)
	{
		bool exists;
		if ((rc = ploopHasSnapshot(get_dd_xml(it->image).c_str(), KEEP_DST_SNAPSHOT_GUID, &exists)))
			break;
		if (exists)
			continue;
		if ((rc = ploopCreateSnapshot(get_dd_xml(it->image).c_str(), KEEP_DST_SNAPSHOT_GUID)))
			break;
		created.push_back(it->image);
	}

	if (rc) {
		for (std::list<std::string>::iterator it = created.begin(); it != created.end(); ++it)
		{
			ploopDeleteSnapshot(get_dd_xml(*it).c_str(), KEEP_DST_SNAPSHOT_GUID);
		}
	}
	return rc;
}

int MigrateStateRemote::preMigrateStage()
{
	int rc;
	string quot;

	START_STAGE();
	reportStage(MIG_INFO_STAGE_CHECK_PRECONDITION);

	if (keepVE) {
		if ((rc = keepVE->init_existed()))
			return rc;
	}

	if ((rc = srcVE->init_existed()))
		return rc;

	if (isOptSet(OPT_AGENT) && isOptSet(OPT_ONLINE) && !srcVE->isrun())
		unSetOpt(OPT_ONLINE);

	if (!isOptSet(OPT_READONLY)) {
		if ((rc = srcVE->lock()))
			return rc;
	}

	if ((rc = checkCommonSrc()))
		return rc;

	if ((rc = sendInitCmd()))
		return rc;

	if (isOptSet(OPT_AGENT)) {
		if ((rc = sendVersionCmd()))
			return rc;
	}

	if ((rc = checkRemoteVersion()))
		return rc;

	if ((rc = checkBindMounts()))
		return rc;

	/* check on the same cluster migration case */
	if ((rc = checkClusterID()))
		return rc;
	if (m_nFlags & VZMSRC_SHARED_PRIV) {
		char path[PATH_MAX+1];

		/* do not copy private and track files too */
		/* and create original VE config backup */
		snprintf(path, sizeof(path), "%s" SUFFIX_MIGRATED,
				srcVE->confRealPath().c_str());
		unlink(path);
		if (copy_file(path, srcVE->confRealPath().c_str()))
			return putErr(MIG_ERR_COPY, MIG_MSG_COPY_FILE,
				srcVE->confRealPath().c_str(), path,
				getError());
		/* rollback on error */
		addCleaner(clean_restoreVEconf, srcVE);
	}

	/* adjust some options with recipient */
	if ((rc = checkOptions(&VZMoptions.options)))
		return rc;

	if ((rc = adjustTimeout(&VZMoptions.tmo)))
		return rc;

	if (VZMoptions.remote_version >= MIGRATE_VERSION_400) {
		if ((rc = checkKeepDir()))
			return rc;
	}

	// check license if target VE will be running
	if (srcVE->isrun() && !isOptSet(OPT_NOSTART)) {
		rc = checkAvailLicense();
		if (rc == MIG_ERR_LICENSE)
		{
			if (!isOptSet(OPT_SKIP_LICENSE) && !isOptSet(OPT_FORCE))
				return putErr(MIG_ERR_LICENSE, MIG_MSG_LICENSE, getError());
			logger(LOG_WARNING, MIG_MSG_LICENSE, getError());
			setOpt(OPT_NOSTART);
		}
		else if (rc != 0)
			return rc;
	}

	if (isOptSet(OPT_ONLINE))
	{
		// check and load kernel modules on dst side
		if (!isOptSet(OPT_SKIP_KERNEL_MODULES) && !isOptSet(OPT_FORCE)) {
			rc = checkKernelModules();
			if (rc)
				return rc;
		}
	}

	// check technologies
	rc = checkTechnologies();
	if (rc == MIG_ERR_TECHNOLOGIES)
	{
		if (!isOptSet(OPT_SKIP_TECHNOLOGIES) && !isOptSet(OPT_FORCE))
			return rc;
		setOpt(OPT_NOSTART);
	}
	else if (rc != 0)
		return rc;

	// check disk space (skip this check if --keep-dst option specified)
	if (!is_keep_dir) {
		rc = checkDiskSpace();
		if ((rc = checkDiskSpaceRC(rc)))
			return rc;
	}

	// check IP addresses on destination HN
	rc = checkIPAddresses();
	if (rc == MIG_ERR_IP_IN_USE)
	{
		// some IP addresses already in use
		if (!isOptSet(OPT_FORCE))
			return putErr(rc, MIG_MSG_IP_IN_USE, getError());
		logger(LOG_WARNING, MIG_MSG_IP_IN_USE_WARN, getError(), dstVE->ctid());
		setOpt(OPT_NOSTART);
	}
	else if (rc != 0)
		return rc;

	if (dstVE->ve_data.name == NULL) {
		/* New name for target VE does not defined.
		Try to get name of source VE. */
		if (srcVE->ve_data.name) {
			dstVE->ve_data.name = strdup(srcVE->ve_data.name);
		}
	}
	/* send & check target VE name */
	if ((rc = checkDstName()))
		return rc;

	// check mount scripts
	string path;
	path = srcVE->scriptPath("mount");
	if (access(path.c_str(), F_OK) == 0) {
		if (!isOptSet(OPT_FORCE))
			return putErr(MIG_ERR_ACTIONS,
				"CT %s has mount script, use '-f' option", srcVE->ctid());
		logger(LOG_WARNING,
			"CT %s has mount script, check target CT before start",
			srcVE->ctid());
		setOpt(OPT_NOSTART);
	}

	// copy config
	if (!(m_nFlags & VZMSRC_SHARED_PRIV)) {
		if ((rc = h_copy_remote_rsync_file(srcVE->confRealPath().c_str())))
			return rc;
	}

	// check rate_parameter
	rc = checkRate();
	if (rc == MIG_ERR_RATE)
	{
		if (!isOptSet(OPT_SKIP_RATE) && !isOptSet(OPT_FORCE))
			return putErr(rc, MIG_MSG_RATE, getError());
		logger(LOG_WARNING, MIG_MSG_RATE, getError());
		setOpt(OPT_NOSTART);
	}
	else if (rc != 0)
		return rc;

	if ((rc = sendHaClusterID()))
		return rc;

	if (isOptSet(OPT_DRY_RUN))
		return MIG_ERR_DRYRUN;

	if ((rc = checkPloopFormat()))
		return rc;

	if (!isOptSet(OPT_READONLY) && isOptSet(OPT_KEEP_DST) &&
		(srcVE->layout >= VZCTL_LAYOUT_5) &&
		(VZMoptions.remote_version >= MIGRATE_VERSION_701)) {
		if ((rc = createKeepDstSnapshots()))
			return rc;
	}

	END_STAGE();

	return 0;
}

void MigrateStateRemote::unregisterHA()
{
	if (!isOptSet(OPT_KEEP_SRC))
	{
		// this code works for all types of CT at any state
		if (m_bIsPrivOnShared && !m_isTargetInHaCluster && srcVE->ve_data.ha_enable)
		{
			logger(LOG_DEBUG, "unregister HA cluster resource %s", srcVE->ctid());
			runHaman(srcVE->ctid(), "del");
		}
	}
}

/*
 * Stage of src VE stopping. Function handle only legacy migration scenarios
 * since most part of live migration logic moved to p.haul.
 */
int MigrateStateRemote::stopVE()
{
	int rc = 0;

	assert(!isOptSet(OPT_ONLINE));

	if (isOptSet(OPT_KEEPER))
		if ((rc = exchangeKeeperIPs()))
			return rc;

	if (srcVE->isrun())
	{
		if ((rc = srcVE->stop(isOptSet(OPT_SKIP_UMOUNT))))
			return rc;
		addCleaner(clean_startVE, srcVE);
	}

	return rc;
}

/*
 * Stage of dst VE starting.
 */
int MigrateStateRemote::startVE()
{
	int rc = 0;
/* 'path' is required for code which is under 'if 0' atm */
#if 0
	char path[PATH_MAX+1];
#endif

	assert(!isOptSet(OPT_ONLINE));

	if (isOptSet(OPT_ONLINE))
	{
// need to adjust to new c/r technology
#if 0
		// VE restoring
		if (use_iteration && VZMoptions.invert_lazy_flag)
		{
			// Set LAZY flag on dst node
			// We need to do this only one time
			rc = invertLazyFlag();
			if (rc != 0)
			{
				logger(LOG_ERR, MIG_MSG_ITER, dstVE->ctid(), getError());
				return rc;
			}
			VZMoptions.invert_lazy_flag = 0;
		}

		if (m_nFlags & VZMSRC_SHARED_PRIV) {
			if ((rc = srcVE->kill_chkpnt())) {
				logger(LOG_ERR, MIG_MSG_STOP, srcVE->ctid(), getError());
				return rc;
			}
			addCleaner(clean_startVE, srcVE, NULL);
			if ((rc = srcVE->umount())) {
				logger(LOG_ERR, MIG_MSG_STOP, srcVE->ctid(), getError());
				return rc;
			}
		}

		// target will register resource on HA cluster here
		rc = channel.sendCommand(CMD_UNDUMP " %d", DSTACT_UNDUMP_VE);
		if (rc != 0)
		{
			logger(LOG_ERR, MIG_MSG_UNDUMP, dstVE->ctid(), getError());
			/* for debug purposes */
			snprintf(path, sizeof(path), "%s.saved", srcVE->dumpfile);
			rename(srcVE->dumpfile, path);
			logger(LOG_ERR, "Dumpfile %s saved", path);
			return rc;
		}

		rc = channel.sendCommand(CMD_RESUME " %d", DSTACT_RESUME_VE);
		if (rc != 0)
		{
			logger(LOG_ERR, MIG_MSG_DST_RESUME, dstVE->ctid(), getError());
			/* for debug purposes */
			snprintf(path, sizeof(path), "%s.saved", srcVE->dumpfile);
			rename(srcVE->dumpfile, path);
			logger(LOG_ERR, "Dumpfile %s saved", path);
			rename(srcVE->dumpfile, path);
			return rc;
		}

		/* CT was resumed on DST so ignore cancelation */
		disable_sig_handler();

		if (!(m_nFlags & VZMSRC_SHARED_PRIV)) {
			if (srcVE->kill_chkpnt())
				logger(LOG_ERR, MIG_MSG_STOP, srcVE->ctid(), getError());

			if (srcVE->umount())
				logger(LOG_ERR, MIG_MSG_STOP, srcVE->ctid(), getError());
		} else {
			if (!isOptSet(OPT_KEEP_SRC)) {
				/* and unregister */
				if ((rc = srcVE->unregister())) {
					logger(LOG_ERR, "Can't unregister CT %s", srcVE->ctid());
					return rc;
				}
				/* and set rollback on error */
				addCleaner(clean_registerVE, srcVE);
			}
		}
#endif
	} else {
		if (m_nFlags & VZMSRC_SHARED_PRIV) {
			if (!isOptSet(OPT_KEEP_SRC)) {
				/* and unregister */
				if ((rc = srcVE->unregister())) {
					logger(LOG_ERR, "Can't unregister CT %s", srcVE->ctid());
					return rc;
				}
				/* and set rollback on error */
				addCleaner(clean_registerVE, srcVE);
			}
		}

		int action;
		if (m_srcInitStatus & ENV_STATUS_RUNNING)
			action = DSTACT_START_VE;
		else if (m_srcInitStatus & ENV_STATUS_MOUNTED)
			action = DSTACT_MOUNT_VE;
		else
			action = DSTACT_NOTHING;

		/* CT will be started on DST so ignore cancelation */
		disable_sig_handler();

		// target will register resource on HA cluster here
		rc = channel.sendCommand(CMD_FINAL " %d",
			isOptSet(OPT_NOSTART) ? 0 : action);
		if (rc)
			return rc;
	}

	return rc;
}

int MigrateStateRemote::invertLazyFlag()
{
/* TODO: checkit */
	if (VZMoptions.remote_version < MIGRATE_VERSION_400)
		/* protocol 250 known nothing about this command
		   try to do not send it and continue */
		return 0;
	return channel.sendCommand(CMD_INVERTLAZY);
}

/* https://jira.sw.ru/browse/PSBM-7314 */
int MigrateStateRemote::checkKernelModules()
{
	logger(LOG_INFO, "Check of requires kernel modules");
	const char *modules = "/proc/modules";
	const char *kernel_modules_list[] = {"autofs4 ", "nfs ", "sunrpc ", NULL};
	char buf[BUFSIZ];
	int rc = 0;
	FILE *fp;
	int i;
	ostringstream out_list;

	if (VZMoptions.remote_version < MIGRATE_VERSION_500)
		return 0;

	if ((fp = fopen(modules, "r")) == NULL)
		return putErr(MIG_ERR_SYSTEM, "fopen('%s') : %m", modules);

	while (1) {
		errno = 0;
		if ((fgets(buf, sizeof(buf), fp)) == NULL) {
			if (errno) {
				logger(LOG_ERR, "fgets(%s) : %m", modules);
				rc = MIG_ERR_SYSTEM;
			}
			break;
		}
		for (i = 0; kernel_modules_list[i]; ++i) {
			if (strncmp(buf, kernel_modules_list[i],
					strlen(kernel_modules_list[i])) == 0)
			{
				out_list << kernel_modules_list[i];
				break;
			}
		}
	}
	fclose(fp);

	if (rc)
		return rc;

	if (out_list.str().empty())
		return 0;

	return channel.sendCommand(CMD_CHECK_KERNEL_MODULES" %s", out_list.str().c_str());
}

int MigrateStateRemote::checkBindMounts()
{
	logger(LOG_INFO, "Checking bindmounts");

	// (77611 vzmigrate & ext. bindmount w/o --force)
	if (srcVE->hasExternalBindmounts())
	{
		logger(LOG_DEBUG, "CT has external bind mounts.");
		// some ext bindmount in config
		if (!isOptSet(OPT_SKIP_EXT_BINDMOUNT) && !isOptSet(OPT_FORCE))
			return putErr(MIG_ERR_EXT_BINDMOUNT, MIG_MSG_EXT_BINDMOUNT, getError());
		logger(LOG_WARNING, MIG_MSG_EXT_BINDMOUNT, getError());
		setOpt(OPT_NOSTART);
	}

	return 0;
}

int MigrateStateRemote::sendHaClusterID()
{
	int rc;
	string id;
	char cmd[BUFSIZ];

	if (VZMoptions.remote_version < MIGRATE_VERSION_550)
		return 0;

	if (!(m_nFlags & VZMSRC_SHARED_PRIV))
		return 0;

	rc = getHaClusterNodeID(id);
	if (rc)
		return rc;

	if (id.empty())
		return 0;

	// TODO : send cluster name too
	snprintf(cmd, sizeof(cmd), CMD_HA_CLUSTER_NODE_ID " %s", id.c_str());
	rc = sendRequest(cmd, &m_isTargetInHaCluster);
	if (rc)
		return rc;
	// one assumption : only one HA cluster on one pstorage
	logger(LOG_INFO, "CT is shared and both nodes are in HA cluster.");
	return 0;
}

int MigrateStateRemote::postFinalStage()
{
	START_STAGE();
	int rc;

	// Remove VE:
	// if remove=no
	// 	rename scripts/conf file to .migrated
	//	move VE private area to .migrated

	// destroy source VE

	// bug #68013
	if (isOptSet(OPT_READONLY))
	{
		END_STAGE();
		return 0;
	}

	unregisterHA();

	if (isOptSet(OPT_KEEP_SRC) || !isOptSet(OPT_REMOVE))
		deleteKeepDstSnapshots(*srcVE);

	if (isOptSet(OPT_KEEP_SRC))
	{
		END_STAGE();
		return 0;
	}

	/* call before VE_PRIVATE_destroy */
	if (srcVE->layout >= VZCTL_LAYOUT_5)
		cleanExternalDisk();

	if (!isOptSet(OPT_REMOVE))
	{
		/* save VE scripts, config, private & vzcache */
		char path[PATH_MAX+1];

		if (!(m_nFlags & VZMSRC_SHARED_PRIV)) {

			removeSrcPrivate();

			clean_removeFile(srcVE->confPath().c_str(),
				NULL);
			snprintf(path, sizeof(path),
				"%s" SUFFIX_MIGRATED "/ve.conf",
				srcVE->priv);
			/* and create config for source VE as
			symlink to backuped config, for vzctl destroy only */
			rc = symlink(path, srcVE->confPath().c_str());
			if (rc != 0)
				logger(LOG_ERR, "Failed to create symlink");
		}
	}

	deletePloopStatfsFiles();

	/* and destroy VE without exitcode check */
	if (!(m_nFlags & VZMSRC_SHARED_PRIV)) {
		srcVE->destroy();
	} else {
		if (srcVE->unregister())
			logger(LOG_ERR, "Failed to unregister");
	}

	END_STAGE();
	return 0;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *	Next functions provide 'copy' functionality for different cases
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 */

int MigrateStateRemote::h_copy_remote_rsync_file(const char * path)
{
	list<string> args;
	args.push_back("--delete");
	args.push_back(path);
	args.push_back(DUMMY_DEST);
	return remoteRsyncSrc(CMD_CONFSET, false, args);
}

/* Restore VE config from backup (<veprivate>/ve.conf.migrated)
   Used for migration in the same cluster */
int MigrateStateRemote::clean_restoreVEconf(const void * arg1, const void *)
{
	char path[PATH_MAX+1];
	VEObj *ve = (VEObj *)arg1;
	assert(ve);

	logger(LOG_DEBUG, "Restore CT %s config", ve->ctid());
	snprintf(path, sizeof(path), "%s" SUFFIX_MIGRATED,
			ve->confRealPath().c_str());
	if (rename(path, ve->confRealPath().c_str()) == -1)
		logger(LOG_DEBUG, "rename(%s, %s) error: %s",
			path, ve->confRealPath().c_str(), strerror(errno));
	return 0;
};

/* start VE */
int MigrateStateRemote::clean_startVE(const void * arg1, const void *)
{
	VEObj *ve = (VEObj *)arg1;
	assert(ve);

	logger(LOG_DEBUG, "Start CT %s", ve->ctid());
	ve->start();
	return 0;
};

/* copy <dir> to remote host by tar via ssh in vzagent mode */
static int copy_remote_tar(
		MigrateSshChannel *ch,
		const char *cmd,
		const char *bdir,
		const list<string> &params)
{
	int rc;
	char **args;
	string_list ls;
	list<string>::const_iterator e;
	int i;

	assert(ch->isConnected());

	string_list_init(&ls);
	string_list_add(&ls, BIN_TAR);
	string_list_add(&ls, (char *)"-c");
	string_list_add(&ls, (char *)"--numeric-owner");
	string_list_add(&ls, (char *)"-S");
	string_list_add(&ls, (char *)"-f");
	string_list_add(&ls, (char *)"-");
	string_list_add(&ls, (char *)"-C");
	string_list_add(&ls, (char *)bdir);
	for (e = params.begin(); e != params.end(); ++e)
		string_list_add(&ls, (char *)e->c_str());

	if ((rc = string_list_to_array(&ls, &args)))
		goto cleanup_0;

	if (isOptSet(OPT_AGENT)) {
		if ((rc = vza_send_data(&ch->ctx, ch->conn, cmd, args)))
			goto cleanup_0;
	} else if (isOptSet(OPT_PS_MODE)) {
		int retcode = 0;
		int sock = PSMode::get_socket();
		if (sock < 0) {
			rc = putErr(MIG_ERR_VZSOCK, "data_sock and tmpl_data_sock are closed");
			goto cleanup_0;
		}
		if ((rc = ch_send_str(&ch->ctx, ch->conn, cmd)))
			goto cleanup_0;

		do_block(sock);
		rc = vzm_execve(args, NULL, sock, sock, &retcode);
		PSMode::finish_socket();
		if ((rc) && (retcode == 1)) {
			/* https://jira.sw.ru/browse/PCLIN-29957
			   note : this function calls for tar only */
			logger(LOG_WARNING, "Ignore %s exit code %d, continue",
						args[0], retcode);
			rc = 0;
		}
	} else if (isOptSet(OPT_SOCKET)) {
		if ((rc = ch_send_str(&ch->ctx, ch->conn, cmd)))
			goto cleanup_0;

		if ((rc = vzsock_send_data(&ch->ctx, ch->conn, (char * const *)args))) {
			rc = putErr(MIG_ERR_VZSOCK, "vzsock_send_data() return %d", rc);
			goto cleanup_0;
		}
	} else if (isOptSet(OPT_SSH_FWD)) {
		if ((rc = ch->fwdSendData(cmd, args)))
			goto cleanup_0;
	} else {
		if ((rc = ssh_send_data(&ch->ctx, ch->conn, cmd, args)))
			goto cleanup_0;
	}

	if ((rc = ch->readReply()))
		goto cleanup_0;

cleanup_0:
	for (i = 0; args[i]; i++)
		free((void *)args[i]);
	free((void *)args);
	string_list_clean(&ls);
	return rc;
}

int MigrateStateRemote::clean_termPhaul(const void * arg, const void *)
{
	const int TERM_TIMEOUT = 3;
	pid_t* phaulPid = (pid_t*)arg;

	if (*phaulPid > 0)
		term_clean(*phaulPid, TERM_TIMEOUT);

	delete phaulPid;
	return 0;
}

int MigrateStateRemote::copy_remote(const char *src, struct string_list *exclude,
		bool use_rsync)
{
	struct string_list_el *e;
	std::list<string> args;
	int rc;

	logger(LOG_DEBUG, "Copy %s", src);
	if (exclude) {
		string_list_for_each(exclude, e) {
			args.push_back("--exclude");
			args.push_back(e->s);
		}
	}

	if (use_rsync) {
		args.push_back("--delete");
		args.push_back(rsync_dir(src));
		args.push_back(DUMMY_DEST);
		rc = remoteRsyncSrc(CMD_PLOOP_COPY_SYNC, true, args);
	} else {
		args.push_back(".");
		rc = copy_remote_tar(&channel, CMD_PLOOP_COPY, src, args);
	}

	return rc;
}

int MigrateStateRemote::backup_dd_xml(const ct_disk &disks)
{
	int rc;

	for (ct_disk::const_iterator it = disks.begin();
			it != disks.end(); ++it)
	{
		std::string s = get_dd_xml(it->image.c_str());
		std::string d = s + ".mig";

		rc = copy_file(d.c_str(), s.c_str());
		if (rc)
			return rc;

		addCleanerRemove(clean_removeFile, d.c_str(), ANY_CLEANER);
	}

	return 0;
}
		
int MigrateStateRemote::copy_disk(const ct_disk &disks, struct string_list *exclude)
{
	for (ct_disk::const_iterator it = disks.begin();
			it != disks.end(); ++it)
	{
		int rc = copy_delta(it->image.c_str(), exclude);
		if (rc)
			return rc;
	}

	return 0;
}

static bool disk_is_ext_non_shared(const struct disk_entry &d)
{
	return d.is_external() && !d.is_shared();
}

int MigrateStateRemote::copy_ct(struct string_list *exclude)
{
	int rc;
	bool use_rsync = (is_keep_dir || isOptSet(OPT_USE_RSYNC));

	reportStage(MIG_INFO_STAGE_COPY_STATIC_DATA);
	logger(LOG_ERR, "copy CT private %s", srcVE->priv);
	if (!(m_nFlags & VZMSRC_SHARED_PRIV)) {
		rc = copy_remote(srcVE->priv, exclude, use_rsync);
		if (rc)
			return rc;
	}

	rc = copy_disk(srcVE->m_disks.get(disk_is_ext_non_shared), exclude);
	if (rc)
		return rc;

	return 0;
}

int MigrateStateRemote::copy_delta(const char *delta, struct string_list *exclude)
{
	int rc;
	struct string_list_el *e;
	std::list<string> args;

	if (exclude) {
		string_list_for_each(exclude, e) {
			args.push_back("--exclude");
			args.push_back(e->s);
		}
	}

	args.push_back(delta);
	if (is_external_disk(delta)) {
		logger(LOG_ERR, "copy external disk %s", delta);
		std::ostringstream d;

		d << CMD_COPY_EXTERNAL_DISK" " << delta;
		rc = copy_remote_tar(&channel, d.str().c_str(), "/", args);
	} else {
		logger(LOG_ERR, "copy disk %s", delta);
		rc = copy_remote_tar(&channel, CMD_PLOOP_COPY, srcVE->priv, args);
	}

	return rc;
}

int MigrateStateRemote::copy_deltas(struct string_list *deltas)
{
	int rc = 0;
	struct string_list_el *e;

	string_list_for_each(deltas, e) {
		rc = copy_delta(e->s, NULL);
		if (rc)
			break;
	}

	return rc;
}

int MigrateStateRemote::syncPageCacheAndFreezeFS(const char *mnt)
{
	int fd;

	logger(LOG_INFO, "sync page cache and flush journal %s", mnt);

	/* sync kernel page cache to image (https://jira.sw.ru/browse/PSBM-11831) */
	fd = open(mnt, O_RDONLY|O_NONBLOCK|O_DIRECTORY);
	if (fd == -1) {
		logger(LOG_ERR, "open(%s) : %m", srcVE->root);
		return -1;
	}
	if (syscall(__NR_syncfs, fd) == -1) {
		logger(LOG_ERR, "syscall() : %m");
		goto err;
	}
	/* to flush journal (https://jira.sw.ru/browse/PSBM-13081) */
	if (ioctl(fd, FIFREEZE, 0) == -1) {
		logger(LOG_ERR, "ioctl(FIFREEZE) : %m");
		goto err;
	}

	return fd;
err:
	close(fd);

	return -1;
}

void MigrateStateRemote::unfreezeFS(int fd)
{
	if (ioctl(fd, FITHAW, 0))
		 logger(LOG_ERR, "ioctl(FITHAW) : %m");
}

int MigrateStateRemote::open_active_deltas(struct string_list *active_deltas)
{
	int rc;
	struct string_list_el *e;

	string_list_for_each(active_deltas, e) {
		struct ploop_delta_desc *d;

		d = (struct ploop_delta_desc *)calloc(1, sizeof(struct ploop_delta_desc));

		rc = ploop_delta_desc_open(srcVE->priv, e->s, d);
		if (rc)
			return rc;

		m_deltas.push_back(d);
	}

	return 0;
}

void MigrateStateRemote::close_active_deltas()
{
	listDeltaDesc_t::const_iterator it;

	for (it = m_deltas.begin(); it != m_deltas.end(); ++it) {
		ploop_delta_desc_close(*it);
		free(*it);
	}
	m_deltas.clear();
}

// safe to call multiple times
void MigrateStateRemote::finishDestination()
{
	// sending empty message is indistinguishable from EOF in libvzsock
	// thus destination will finish it execution and we read EOF on our
	// side too. Before dst side close its channel it will cleanup.
	if (channel.sendPkt(PACKET_SEPARATOR, "") == 0)
		channel.readReply();
}

int MigrateStateRemote::doOfflinePloopCtMigration()
{
	return copy_ct(NULL);
}


int MigrateStateRemote::doOfflineSimfsCtMigration()
{
	return copy_ct(NULL);
}

int MigrateStateRemote::doPloopCtClone()
{
	int rc;
	StringListWrapper active_delta;

	rc = backup_dd_xml(srcVE->m_disks);
	if (rc)
		return rc;

	rc = srcVE->tsnapshot(srcVE->gen_snap_guid());
	if (rc)
		return rc;

	addCleaner(clean_deleteSnapshot, srcVE, srcVE->snap_guid(), ANY_CLEANER);

	rc = getActivePloopDelta(srcVE->m_disks.get(disk_is_non_shared),
		&active_delta.getList());
	if (rc)
		return rc;

	rc = copy_ct(&active_delta.getList());
	if (rc)
		return rc;

	rc = srcVE->tsnapshot_delete(srcVE->snap_guid());
	if (rc)
		return rc;

	return channel.sendCommand(CMD_FINAL " %d", DSTACT_NOTHING);
}

/* Handle online migration using p.haul */
int MigrateStateRemote::doOnlinePloopCtMigration()
{
	StringListWrapper active_delta;
	int rc;

	rc = getActivePloopDelta(srcVE->m_disks.get(disk_is_non_shared),
		&active_delta.getList());
	if (rc)
		return rc;

	// Prepare data structures needed for phaul connections multiplexing
	rc = preparePhaulConnection(active_delta.toVector());
	if (rc)
		return rc;

	// Copy static data of container to destination
	rc = copy_ct(&active_delta.getList());
	if (rc)
		return rc;

	// Prepare CT for p.haul migration
	rc = prePhaulMigration();
	if (rc)
		return rc;

	// Run iterative memory and fs migration via p.haul
	return runPhaulMigration();
}

/*
 * Prepare data structures needed for phaul connections multiplexing on source
 * side and ask destination to prepare its data stuctures as well.
 *
 * Command CMD_PREPARE_PHAUL_CONN has following format:
 * %count%\n[%delta_path1%\n[%delta_path2%\n[...]]] (count of active ploop
 * deltas and list of deltas paths separated by '\n').
 */
int MigrateStateRemote::preparePhaulConnection(
	const std::vector<std::string>& activeDeltas)
{
	// Prepare CMD_PREPARE_PHAUL_CONN command string
	std::ostringstream cmdStr;
	cmdStr << CMD_PREPARE_PHAUL_CONN << " ";
	cmdStr << activeDeltas.size() << "\n";
	for (size_t i = 0; i < activeDeltas.size(); ++i) {
		cmdStr << activeDeltas[i] << "\n";
	}

	// Send CMD_PREPARE_PHAUL_CONN command to destination
	int rc = channel.sendCommand(cmdStr.str().c_str());
	if (rc)
		return rc;

	// Create and initialize phaul channels
	std::auto_ptr<PhaulChannels> channels(new PhaulChannels(activeDeltas));
	if (channels->init() != 0)
		return putErr(-1, MIG_MSG_PREP_SRC_PHAUL_CONN);

	// Transfer channels ownership from local object to class object
	m_phaulChannels = channels;
	return 0;
}

/*
 * Employ reqired Virtuozzo-specific preparations and workarounds before p.haul
 * migration start.
 */
int MigrateStateRemote::prePhaulMigration()
{
	// Create ploop major:minor map as workaround needed for criu
	return srcVE->createDevmap();
}

/*
 * Exec p.haul and handle connections multiplexing.
 */
int MigrateStateRemote::runPhaulMigration()
{
	const char *s = isOptSet(OPT_ONLINE) ? MIG_INFO_LIVE_STARTED : MIG_INFO_WARM_STARTED;
	reportStage(s);
	logger(LOG_INFO, s);

	// Transfer channels ownership from class object to local object
	std::auto_ptr<PhaulChannels> channels = m_phaulChannels;
	if (channels.get() == NULL)
		return putErr(MIG_ERR_PHAUL, MIG_MSG_RUN_PHAUL);

	// Exec phaul
	std::vector<std::string> phaulArgs = getPhaulArgs(*channels);
	pid_t phaulPid = execPhaul(phaulArgs);
	if (phaulPid == -1)
		return putErr(MIG_ERR_PHAUL, MIG_MSG_RUN_PHAUL);

	// Close phaul channels ends
	channels->closePhaulChannelFds();

	// Send CMD_RUN_PHAUL_MIGRATION command to destination. ATTENTION!, have
	// to read reply further in this function unconditionally!
	int rc = channel.sendPkt(PACKET_SEPARATOR, CMD_RUN_PHAUL_MIGRATION);
	if (rc)
		return rc;

	// Create io multiplexer
	multiplexer::IoMultiplexer ioMultiplexer(channel,
		channels->getVzmigrateChannelFds(), phaulPid, true, !isOptSet(OPT_NOCOMPRESS));

	// Run phaul io multiplexing
	rc = ioMultiplexer.runMultiplexing();
	if (!ioMultiplexer.isChildTerminated()) {
		addCleaner(clean_termPhaul, (new pid_t(phaulPid)), NULL, ANY_CLEANER);
	}

	// Read CMD_RUN_PHAUL_MIGRATION command reply and check result
	int remoteRc = channel.readReply();
	if ((remoteRc != 0) || (rc != 0)) {
		logCriuErrors();
		return putErr(MIG_ERR_PHAUL, MIG_MSG_RUN_PHAUL_LOG, PHAUL_LOG_FILE);
	}

	logger(LOG_INFO, MIG_INFO_COMPLETED);
	return 0;
}

/*
 * Return vector of command line arguments for p.haul exec.
 */
std::vector<std::string> MigrateStateRemote::getPhaulArgs(
	const PhaulChannels& channels)
{
	std::vector<std::string> args;
	args.push_back(BIN_PHAUL);
	args.push_back("vz");
	args.push_back(srcVE->ctid());

	// Pass phaul connections as socket file descriptors
	args.push_back("--fdrpc");
	args.push_back(channels.getPhaulFdrpcArg());

	args.push_back("--fdmem");
	args.push_back(channels.getPhaulFdmemArg());

	std::string fdfsArg = channels.getPhaulFdfsArg();
	if (!fdfsArg.empty()) {
		args.push_back("--fdfs");
		args.push_back(fdfsArg);
	}

	// Specify destination CTID if it differs from source CTID
	if (CMP_CTID(srcVE->ctid(), dstVE->ctid()) != 0) {
		args.push_back("--dst-id");
		args.push_back(dstVE->ctid());
	}

	// Specify mode as restart if online migration disabled
	if (!isOptSet(OPT_ONLINE)) {
		args.push_back("--mode");
		args.push_back("restart");
	}

	// Explicitly enable or disable predumps creation (iterations)
	if (isOptSet(OPT_NOITER))
		args.push_back("--no-pre-dump");
	else {
		args.push_back("--pre-dump");
		args.push_back("--auto-dedup");
	}

	// Specify force option to skip cpu compatibility checks if needed
	if (isOptSet(OPT_SKIP_CHECKCPU))
		args.push_back("--skip-cpu-check");

	std::string sharedArg(getPhaulSharedDisksArg());
	if (!sharedArg.empty()) {
		args.push_back("--vz-shared-disks");
		args.push_back(sharedArg);
	}

	std::string secondaryDisksArg = getPhaulSecondaryDisksArg();
	if (!secondaryDisksArg.empty()) {
		args.push_back("--vz-secondary-disks");
		args.push_back(secondaryDisksArg);
	}

	std::string dumpdir(vzcnf->dumpdir);
	dumpdir.append("/").append(srcVE->ctid());

	args.push_back("--img-path");
	args.push_back(dumpdir);

	// Specify path to phaul log
	args.push_back("--log-file");
	args.push_back(PHAUL_LOG_FILE);

	// Setup maximal phaul/criu verbosity level if debug output enabled
	if (debug_level >= LOG_DEBUG) {
		args.push_back("-v");
		args.push_back("4");
	}

	if (isOptSet(OPT_KEEP_IMAGES))
		args.push_back("--keep-images");

	if (isOptSet(OPT_NOSTART))
		args.push_back("--nostart");

	if (VZMoptions.remote_version < MIGRATE_VERSION_709)
		args.push_back("--sync-copy");

	// Specify path to CRIU error log file
	const std::string criuErrLog = getCriuErrLog();
	if (!criuErrLog.empty()) {
		args.push_back("--criu-errorlog");
		args.push_back(getCriuErrLog());
	}

	return args;
}

std::string MigrateStateRemote::getPhaulSharedDisksArg() const
{
	ct_disk disks(srcVE->m_disks.get(disk_is_shared_not_device));
	if (disks.empty())
		return "";

	std::ostringstream shared;
	const char* delim = "";
	ct_disk::const_iterator it(disks.begin());
	ct_disk::const_iterator last(disks.end());
	for (; it != last; ++it) {
		shared << delim << it->image;
		delim = ",";
	}

	logger(LOG_INFO, "shared disks: %s", shared.str().c_str());
	return shared.str();
}

/*
 * Return value of --vz-secondary-disks argument. It contain list of secondary
 * ploop disks in format %uuid%:%major%:%minor%[,...]. Consider all additional
 * disks of container (second, third and so on) are secondary.
 */
std::string MigrateStateRemote::getPhaulSecondaryDisksArg() const
{
	struct stat st;
	int rc;
	ct_disk disks(srcVE->m_disks.get(disk_is_secondary_or_device));

	std::ostringstream arg;
	const char* delim = "";
	for (ct_disk::const_iterator it = disks.begin(); it != disks.end(); ++it) {
		std::string dev = it->image;

		if (!it->is_device()) {
			char d[PATH_MAX];
			char p[PATH_MAX];

			rc = vzctl2_get_ploop_dev2(it->image.c_str(), d,
					sizeof(d), p, sizeof(p));
			if (rc != 0) {
				logger(LOG_ERR, MIG_MSG_INTERNAL, "vzctl2_get_ploop_dev", rc);
				continue;
			}
			dev = p;
		}

		if (stat(dev.c_str(), &st) == -1) {
			logger(LOG_ERR, MIG_MSG_INTERNAL, "stat", errno);
			continue;
		}

		// Append disks separator
		arg << delim;
		delim = ",";

		// Append %uuid%:%major%:%minor% tuple
		arg << it->uuid << ":" << major(st.st_rdev) << ":"
			<< minor(st.st_rdev);
	}

	return arg.str();
}

pid_t MigrateStateRemote::execPhaul(const std::vector<std::string>& args)
{
	ExecveArrayWrapper argsArray(args);
	pid_t pid;

	if (vzm_execve_quiet_nowait(argsArray.getArray(), NULL, -1, &pid) != 0)
		return putErr(-1, MIG_MSG_EXEC_PHAUL, BIN_PHAUL);

	return pid;
}

bool MigrateStateRemote::isSameLocation()
{
	return m_nFlags & VZMSRC_SHARED_PRIV;
}

/* Delete .statfs files for all shared disks of container */
void MigrateStateRemote::deletePloopStatfsFiles()
{
	const char* PLOOP_STATFS_FILENAME = ".statfs";

	for (ct_disk::const_iterator it = srcVE->m_disks.begin();
			it != srcVE->m_disks.end(); ++it)
	{
		if (!it->is_shared())
			continue;
		ostringstream statfsFilename;
		statfsFilename << it->image << "/" << PLOOP_STATFS_FILENAME;
		clean_removeFile(statfsFilename.str().c_str(), NULL);
	}
}

std::string MigrateStateRemote::getCriuErrLog() const
{
	return m_criuErrLog;
}

void MigrateStateRemote::logCriuErrors() {
	FILE *fd;
	char buf[BUFSIZ-6], obuf[BUFSIZ];

	if ((fd = fopen(getCriuErrLog().c_str(), "r")) == NULL)
		return;

	while(fgets(buf, sizeof(buf), fd)) {
		buf[strcspn(buf, "\n")] = '\0';
		sprintf(obuf, "CRIU: %s", buf);
		reportStage(obuf);
		logger(LOG_ERR, obuf);
	}
}
