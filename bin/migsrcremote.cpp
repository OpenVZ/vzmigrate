/* $Id$
 *
 * Copyright (c) SWsoft, 2006-2007
 *
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
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

#include "migsrcremote.h"
#include "migssh.h"
#include "vzacompat.h"
#include "channel.h"
#include "remotecmd.h"
#include "veentry.h"
#include "util.h"

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

MigrateStateRemote::MigrateStateRemote(
		unsigned src_ve,
		unsigned dst_ve,
		const char * priv,
		const char * root,
		const char *dst_name)
: MigrateStateSrc(src_ve, dst_ve, priv, root, dst_name),
m_bIsPrivOnShared(false)
{
	use_iteration = true;
	cpu_flags = 0;

	swapch = NULL;

	m_isTargetInHaCluster = 0;

/* TODO: check keeperVEID */
	if (isOptSet(OPT_KEEPER)) {
		keepVE = new VEObj(keeperVEID);
		addCleaner(clean_delEntry, keepVE, NULL, ANY_CLEANER);
	}
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
	if (VZMoptions.remote_version < MIGRATE_VERSION_400)
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

/* get & check ploop format for ploop-based VE private */
int MigrateStateRemote::checkPloopFormat()
{
	int rc;
	int ret;
	char path[PATH_MAX+1];
	struct ploop_spec spec;
	struct ploop_disk_images_data *di;
	ostringstream outStr;

	if (srcVE->layout < VZCTL_LAYOUT_5)
		return 0;

	GET_DISKDESCRIPTOR_XML(srcVE->priv, path)
	ret = ploop_read_disk_descr(&di, path);
	if (ret) {
		rc = putErr(MIG_ERR_PLOOP, "ploop_read_diskdescriptor(%s) : %s [%d]",
				path, ploop_get_last_error(), ret);
		goto cleanup;
	}
	memset((void *)&spec, 0, sizeof(spec));
	ret = ploop_get_spec(di, &spec);
	if (ret)
		rc = putErr(MIG_ERR_PLOOP,
			"ploop_get_spec() : %s [%d]", ploop_get_last_error(), ret);

	// 0 - raw, 1 - old, 2 -new formats
	// 0 & 1 are supports by psbm-6
	if (spec.fmt_version < 2) {
		rc = 0;
		goto cleanup;
	}

	if (VZMoptions.remote_version < MIGRATE_VERSION_604) {
		rc = putErr(MIG_ERR_PLOOP_FORMAT, MIG_MSG_PLOOP_FORMAT, spec.fmt_version);
		goto cleanup;
	}

	logger(LOG_INFO, "Checking ploop format %d", spec.fmt_version);
	outStr << CMD_CHECK_PLOOP_FORMAT << " " << spec.fmt_version;
	logger(LOG_DEBUG, "%s",  outStr.str().c_str());

	return channel.sendCommand(outStr.str().c_str());

cleanup:
	ploop_free_diskdescriptor(di);
	return rc;
}

int MigrateStateRemote::establishSshChannel()
{
	int rc, ret;
	char buffer[BUFSIZ];
	int fds[2];
	const char *bin_dst;

	if (!isOptSet(OPT_NOITER)) {
		bin_dst = BIN_VZITERIND;
		snprintf(buffer, sizeof(buffer), CMD_ITERCH " %u", dstVE->veid());
	} else {
		return putErr(MIG_ERR_PROTOCOL, "Bad mode for swap channel");
	}

	if (isOptSet(OPT_AGENT)) {
		int *sock = new(int);
		assert(sock);
		if ((rc = vza_start_swap_cli(&channel.ctx,
				channel.conn, dstVE->veid(), sock, &swapch)))
			return rc;
		addCleaner(clean_closeSocket, (void *)sock, NULL, ANY_CLEANER);
	} else if (isOptSet(OPT_PS_MODE)) {
		/* create & send command to start swap channel of server */
		if ((rc = ch_send_cmd(&channel.ctx, channel.conn, buffer)))
			return rc;

		if ((ret = vzsock_open_conn(&channel.ctx, NULL, &swapch)))
			return putErr(MIG_ERR_VZSOCK,
				"vzsock_open_conn() return %d\n", ret);
		fds[0] = VZMoptions.swap_sock;
		fds[1] = VZMoptions.swap_sock;
		if ((ret = vzsock_set_conn(&channel.ctx, swapch,
				VZSOCK_DATA_FDPAIR, fds, sizeof(fds))))
			return putErr(MIG_ERR_VZSOCK,
				"vzsock_set_conn() return %d\n", ret);
	} else if (isOptSet(OPT_SSH_FWD)) {
		if ((rc = channel.fwdStartSwapCli(buffer, &swapch)))
			return rc;
		addCleaner(clean_closeChannel, swapch, NULL,
			!isOptSet(OPT_NOITER) ? ANY_CLEANER : ERROR_CLEANER);
		return 0;
	} else {
		if ((rc = ssh_start_swap_cli(&channel.ctx, bin_dst,
				dstVE->veid(), &swapch)))
			return rc;
	}
	addCleaner(clean_closeChannel, swapch, NULL);

	/* read reply from channel */
	if ((rc = ch_recv(&channel.ctx, swapch, '\n',
			buffer, sizeof(buffer))))
		return rc;

	if (strcmp(buffer, "OK")) {
		logger(LOG_ERR, "%s", buffer);
		return putErr(MIG_ERR_CANT_CONNECT, MIG_MSG_CANT_CONNECT);
	}

	logger(LOG_DEBUG, "Swap channel established");
	return 0;
}

/* check shared fs type and id for source VE private,
   and send request in success.
   destination node return '1' if target VE private is
   on same shared fs with the same local path */
int MigrateStateRemote::checkSharedDir(
		const char *cmd400,
		const char *cmd401,
		const char *dir,
		const char *title,
		const char *uuid,
		int *shared,
		int *reply)
{
	int rc = 0;
	char path[PATH_MAX+1];
	int fd;
	char *buffer = NULL;
	size_t size;
	char *name;
	char id[PATH_MAX+MAXHOSTNAMELEN+2];
	long ret;
	long fstype;
	int dir_shared;

	*shared = 0;
	*reply = 0;
	/* vzmigrate does not known nothing about GFS cluster until 400 */
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

	if ((fstype == GFS_MAGIC) && (VZMoptions.remote_version < MIGRATE_VERSION_470))
	{
		char mpoint[PATH_MAX+1];
		char lpath[PATH_MAX+1];

		if ((rc = split_path(path, mpoint, sizeof(mpoint), lpath, sizeof(lpath))))
			return rc;
		if (strlen(lpath) == 0)
			strcpy(lpath, ".");
		if ((rc = gfs_cluster_getid(mpoint, id, sizeof(id))))
			return rc;

		logger(LOG_DEBUG, "Source %s resides on shared partition "
			"(GFS cluster %s)", title, id);
		size = strlen(cmd400) + strlen(id) + strlen(lpath) + 4;
		if (uuid)
			size += strlen(uuid) + 1;
		if ((buffer = (char *)malloc(size)) == NULL)
			return putErr(MIG_ERR_SYSTEM,
				"malloc(): %s", strerror(errno));

		if (uuid)
			snprintf(buffer, size, "%s %s %s %s",
				cmd400, id, uuid, lpath);
		else
			snprintf(buffer, size, "%s %s %s", cmd400, id, lpath);
		rc = sendRequest(buffer, &ret);
	}
	else
	{
		logger(LOG_DEBUG, "Source %s resides on shared partition (NFS/GFS/GFS2/PCS)", title);
		/* create temporary file */
		snprintf(path, sizeof(path), "%s/vzmigrate_shared_file_XXXXXX", dir);
		if ((fd = mkstemp(path)) == -1)
			return putErr(MIG_ERR_SYSTEM, "mkstemp(%s)", path);
		close(fd);
		name = basename(path);

		/* and send request and wait answer */
		size = strlen(cmd401) + strlen(name) + 4;
		if ((buffer = (char *)malloc(size)) == NULL) {
			unlink(path);
			return putErr(MIG_ERR_SYSTEM, "malloc(): %s", strerror(errno));
		}
		snprintf(buffer, size, "%s %s", cmd401, name);
		rc = sendRequest(buffer, &ret);
		unlink(path);
	}
	if (ret) {
		logger(LOG_INFO, "Source and target %s resides "
			"on the same shared partition", title);
	}
	if (buffer)
		free(buffer);
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
		if (it->is_external()) {
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
		CMD_CHECK_CLUSTER, CMD_CHECK_SHARED_PRIV,
		srcVE->priv, "CT private", NULL,
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
		if (srcVE->veid() != dstVE->veid()) {
			return putErr(MIG_ERR_NONSHAREDFS,
				"Changing ID for CT "
				"which private directory resides on the\n"
				"shared partition is not supported, change "
				"ID manually, e.g. by using vzmlocal.\n"
				"Or use --nonsharedfs option to force copying"
				"CT private data.");
		} else if (dstVE->priv != srcVE->priv) {
			return putErr(MIG_ERR_NONSHAREDFS,
				"Changing private area for CT on the "
				"shared partition is not supported, use\n"
				"--nonsharedfs option to force copying"
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

	/* for dump dir */
	if (isOptSet(OPT_ONLINE)) {
		if (srcVE->layout < VZCTL_LAYOUT_4)
		{
			if ((rc = checkSharedDir(
				CMD_CHECK_CLUSTER_DUMP, CMD_CHECK_SHARED_DUMP,
				srcVE->dumpDir().c_str(), "dumpdir", NULL,
				&shared, &is_thesame_shared)))
			return rc;
		} else {
			// on layout > 3 dumpdir is placed at private
			is_thesame_shared = m_nFlags & VZMSRC_SHARED_PRIV;
		}
		if (is_thesame_shared)
			m_nFlags |= VZMSRC_SHARED_DUMP;
	}

	return 0;
}

int MigrateStateRemote::doCtMigration()
{
	int rc = 0;

	if ((rc = preMigrateStage()))
		goto error;

	if (srcVE->isrun() && is_shared() && isOptSet(OPT_ONLINE))
		rc = doOnlinePloopSharedCtMigration();
	else
		rc = doCtMigrationDefault();

	if (rc)
		goto error;

	return 0;

error:
	finishDestination();
	return rc;
}

int MigrateStateRemote::doCtMigrationDefault()
{
	int rc = 0;

	if (srcVE->isrun()) {
		rc = doOnlinePloopCtMigration();
	} else {
		rc = doOfflinePloopCtMigration();
	}
	if (rc)
		return rc;

	// keeper, offlineManagement, restore state VE
	if ((rc = startVEStage()))
		return rc;

	// VE final cleaning
	rc = postFinalStage();

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
	options |= isOptSet(OPT_CONVERT_VZFS) ? MIGINIT_CONVERT_VZFS : 0;
	options |= isOptSet(OPT_KEEP_DST) ? MIGINIT_KEEP_DST : 0;

	return channel.sendCommand(CMD_INIT " %d %d", dstVE->veid(), options);

}

int MigrateStateRemote::checkRemoteVersion()
{
	if (VZMoptions.remote_version < MIGRATE_VERSION_400) {
		return putErr(MIG_ERR_LAYOUT, MIG_MSG_LAYOUT, \
			srcVE->layout);
	} else if (VZMoptions.remote_version < MIGRATE_VERSION_460) {
		/* online migration 4.6 -> 4.0 is impossible
		   (https://jira.sw.ru/browse/PCLIN-28082) */
		if (isOptSet(OPT_ONLINE) && !isOptSet(OPT_FORCE))
			return putErr(MIG_ERR_ONLINE_ELDER, MIG_MSG_ONLINE_ELDER);
	} else if (VZMoptions.remote_version < MIGRATE_VERSION_550) {
		/* check new layout */
		if (srcVE->layout >= VZCTL_LAYOUT_5)
			return putErr(MIG_ERR_LAYOUT, MIG_MSG_LAYOUT, \
				srcVE->layout);
	}

	if (VZMoptions.remote_version < MIGRATE_VERSION_608 &&
			isOptSet(OPT_CONVERT_VZFS) && srcVE->isrun())
		return putErr(MIG_ERR_SECOND_LEVEL_BUG, MIG_MSG_SECOND_LEVEL_BUG);

	if (VZMoptions.remote_version < MIGRATE_VERSION_607 &&
			srcVE->m_disks.size() > 1)
		return putErr(MIG_ERR_MULTIPLOOP_IS_NOT_SUP, MIG_MSG_MULTIPLOOP_IS_NOT_SUP);

	if (isOptSet(OPT_USE_RSYNC) && (srcVE->layout >= VZCTL_LAYOUT_5))
		return putErr(MIG_ERR_LAYOUT,
				"The migration via rsync is not supported for ploop-based CT");
}

int MigrateStateRemote::preMigrateStage()
{
	int rc;
	string quot;

	START_STAGE();

	if (keepVE) {
		if ((rc = keepVE->init_existed()))
			return rc;
	}
/*
	// bug 57973 (but in agent mode source don't call ssh).
	// ssh connection kill moved to main function (#79439)
	if (!isOptSet(OPT_AGENT))
		addCleaner(clean_channel, &channel, NULL, ANY_CLEANER);
*/
	if ((rc = srcVE->init_existed()))
		return rc;

	if (!isOptSet(OPT_READONLY)) {
		if ((rc = srcVE->lock()))
			return rc;
	}

	if ((rc = checkCommonSrc()))
		return rc;

	if ((srcVE->veformat == VZ_T_VZFS3) && !isOptSet(OPT_USE_RSYNC)) {
		/* since 4.0.1 vzmigrate use default tar, which does
		   not support magic symlinks, #475567 */
		setOpt(OPT_USE_RSYNC);
		logger(LOG_DEBUG, "Will use rsync for container with vzfs3");
	}

	if ((rc = sendInitCmd()))
		return rc;

	if (isOptSet(OPT_AGENT)) {
		if ((rc = sendVersionCmd()))
			return rc;
	}

	if ((rc = checkRemoteVersion()))
		return rc;


	// do not use --sparse option for ploop image copy
	use_sparse_opt = (srcVE->layout < VZCTL_LAYOUT_5);

	if ((rc = checkBindMounts()))
		return rc;

	// Use iterative scheme by default
	use_iteration = (isOptSet(OPT_NOITER) || isOptSet(OPT_CONVERT_VZFS)) ? false : true;

	/* check on the same cluster migration case -
	   before config migration only */
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

	/* adjust some options with recipient - before establishSshChannel() due to OPT_SSH_FWD */
	if ((rc = checkOptions(&VZMoptions.options)))
		return rc;

	if (isOptSet(OPT_ONLINE) && use_iteration)
	{
		rc = establishSshChannel();
		if (rc != 0 && use_iteration)
		{
			if (isOptSet(OPT_REALTIME))
			{
				logger(LOG_ERR, MIG_MSG_REALTIME);
				return rc;
			}
			else
				logger(LOG_WARNING, MIG_MSG_ITER_MIG);
			use_iteration = false;
			setOpt(OPT_NOITER);
		}
	}

	if ((rc = adjustTimeout(&VZMoptions.tmo)))
		return rc;

	// check license if target VE will be running
	if (srcVE->isrun() && !isOptSet(OPT_NOSTART)) {
		rc = checkAvailLicense();
		if (rc == MIG_ERR_LICENSE)
		{
			if (!isOptSet(OPT_SKIP_LICENSE) && !isOptSet(OPT_FORCE))
				return putErr(MIG_ERR_LICENSE, MIG_MSG_LICENSE, getError());
			logger(LOG_WARNING, MIG_MSG_LICENSE, getError(), dstVE->veid());
			setOpt(OPT_NOSTART);
		}
		else if (rc != 0)
			return rc;
	}

	if (isOptSet(OPT_ONLINE))
	{
		/* check and load kernel modules on dst side,
		   but skip check (do not load modules on target) if opt is specified */
		if (!isOptSet(OPT_SKIP_KERNEL_MODULES) && !isOptSet(OPT_FORCE)) {
			rc = checkKernelModules();
			if (rc)
				return rc;
		}
		// Check CPT image version
		rc = checkCPTImageVersion();
		if (rc && !isOptSet(OPT_SKIP_CPT_IMAGE_VERSION) && !isOptSet(OPT_FORCE))
			return rc;
		//check Capabilities
		//TODO: check error inside checkCapabilities
		rc = checkCapabilities();
		if (rc && !isOptSet(OPT_SKIP_CAPABILITIES) && !isOptSet(OPT_FORCE))
			return rc;
	}

	//check Technologies
	rc = checkTechnologies();
	if (rc == MIG_ERR_TECHNOLOGIES)
	{
		if (!isOptSet(OPT_SKIP_TECHNOLOGIES) && !isOptSet(OPT_FORCE))
			return rc;
		setOpt(OPT_NOSTART);
	}
	else if (rc != 0)
		return rc;

	rc = checkDiskSpace();
	if ((rc = checkDiskSpaceRC(rc)))
		return rc;

	// check IP addresses on destination HN
	rc = checkIPAddresses();
	if (rc == MIG_ERR_IP_IN_USE)
	{
		// some IP addresses already in use
		if (!isOptSet(OPT_FORCE))
			return putErr(rc, MIG_MSG_IP_IN_USE, getError());
		logger(LOG_WARNING, MIG_MSG_IP_IN_USE_WARN, getError(), dstVE->veid());
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
				"CT#%d has mount script, use '-f' option",
				srcVE->veid());
		logger(LOG_WARNING,
			"CT#%d has mount script, check target CT before start",
			srcVE->veid());
		setOpt(OPT_NOSTART);
	}

	// copy config, and turn-on quota
	// NOTE:: order is important
	if (!(m_nFlags & VZMSRC_SHARED_PRIV)) {
		if ((rc = h_copy_remote_rsync_file(CMD_CONFSET, srcVE->confRealPath().c_str())))
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

	END_STAGE();

	return 0;
}

int MigrateStateRemote::copyDumpFile()
{
	int rc;

	logger(LOG_INFO, MSG_FUNC_COPY_DUMP, srcVE->dumpfile);
	if (m_nFlags & VZMSRC_SHARED_DUMP)
		rc = h_copy_cluster_dump(srcVE->dumpfile);
	else
		rc = h_copy_remote_rsync_dump(srcVE->dumpfile);
	if (!rc)
		logger(LOG_INFO, "done");

	return rc;
}

int MigrateStateRemote::suspendVEOnline()
{
	int rc;

	if ((rc = memoryCopyOnline()))
		return rc;

	if ((rc = srcVE->suspend(cpu_flags, use_iteration)))
		return putErr(rc, MIG_MSG_SUSPEND, srcVE->veid(), getError());
	addCleaner(clean_resumeVE, srcVE);

	if ((rc = srcVE->dump()))
		return putErr(rc, MIG_MSG_DUMP, srcVE->veid(), getError());

	return 0;
}

int MigrateStateRemote::suspendVEOffline()
{
	return suspendVE();
}

bool MigrateStateRemote::isDumpFilesDiffer()
{
	return srcVE->layout < VZCTL_LAYOUT_4;
}

int MigrateStateRemote::memoryCopyOnline()
{
	int ret;
	int fds[2];
	size_t size;
	int rc;

	if (swapch)
	{
		if (isOptSet(OPT_SSH_FWD)) {
			memcpy(&fds[0], swapch, sizeof(fds[0]));
			memcpy(&fds[1], swapch, sizeof(fds[1]));
		} else {
			size = sizeof(fds);
			if ((ret = vzsock_get_conn(&channel.ctx, swapch,
					VZSOCK_DATA_FDPAIR, fds, &size)))
				return putErr(MIG_ERR_VZSOCK,
					"vzsock_get_conn() return %d\n", ret);
		}
	}

	if (use_iteration)
	{
		if ((rc = srcVE->vm_iteration(fds[0], fds[1])))
		{
			logger(LOG_ERR, MIG_MSG_VM_PREP, srcVE->veid(), getError());
			logger(LOG_WARNING, MIG_MSG_ITER_MIG);
			if (isOptSet(OPT_REALTIME))
				return rc;
			if (NULL != swapch)
			{
				// We can try to perform simple
				// online migration
				ch_send_str(&channel.ctx, swapch, "Closed");
				// Close swap channel for command line and ssh forwarding modes
				// It is needs to terminate vziterind on target node to call CPT_PUT_CONTEXT
				// (https://jira.sw.ru/browse/PSBM-18868)
				// for agent and ps modes vzmdest will terminate vziterind directly on target
				if (isOptSet(OPT_SSH_FWD))
					channel.fwdCloseSwap(swapch);
				else if (!isOptSet(OPT_AGENT) && !isOptSet(OPT_PS_MODE))
					vzsock_close_conn(&channel.ctx, (void *)swapch);

				use_iteration = false;
			}
		}
	}

	return 0;
}

void MigrateStateRemote::unregisterHA()
{
	if (!isOptSet(OPT_KEEP_SRC))
	{
		// this code works for all types of CT at any state
		if (m_bIsPrivOnShared && !m_isTargetInHaCluster && srcVE->ve_data.ha_enable)
		{
			logger(LOG_DEBUG, "unregister HA cluster resource %u", srcVE->veid());
			runHaman(srcVE->veid(), "del");
		}
	}
}

int MigrateStateRemote::startVE()
{
	int rc = 0;
	char path[PATH_MAX+1];

	if (isOptSet(OPT_ONLINE))
	{
		// VE restoring
		if (use_iteration && VZMoptions.invert_lazy_flag)
		{
			// Set LAZY flag on dst node
			// We need to do this only one time
			rc = invertLazyFlag();
			if (rc != 0)
			{
				logger(LOG_ERR, MIG_MSG_ITER, dstVE->veid(), getError());
				return rc;
			}
			VZMoptions.invert_lazy_flag = 0;
		}

		if (m_nFlags & VZMSRC_SHARED_PRIV) {
			if ((rc = srcVE->kill_chkpnt())) {
				logger(LOG_ERR, MIG_MSG_STOP,
						srcVE->veid(), getError());
				return rc;
			}
			addCleaner(clean_startVE, srcVE, NULL);
			if ((rc = srcVE->umount())) {
				logger(LOG_ERR, MIG_MSG_STOP,
						srcVE->veid(), getError());
				return rc;
			}
		}

		// target will register resource on HA cluster here
		rc = channel.sendCommand(CMD_UNDUMP " %d", DSTACT_UNDUMP_VE);
		if (rc != 0)
		{
			logger(LOG_ERR, MIG_MSG_UNDUMP, dstVE->veid(), getError());
			/* for debug purposes */
			snprintf(path, sizeof(path), "%s.saved", srcVE->dumpfile);
			rename(srcVE->dumpfile, path);
			logger(LOG_ERR, "Dumpfile %s saved", path);
			return rc;
		}

		rc = channel.sendCommand(CMD_RESUME " %d", DSTACT_RESUME_VE);
		if (rc != 0)
		{
			logger(LOG_ERR, MIG_MSG_DST_RESUME, dstVE->veid(), getError());
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
				logger(LOG_ERR, MIG_MSG_STOP,
					srcVE->veid(), getError());

			if (srcVE->umount())
				logger(LOG_ERR, MIG_MSG_STOP,
					srcVE->veid(), getError());
		} else {
			if (!isOptSet(OPT_KEEP_SRC)) {
				/* and unregister */
				if ((rc = srcVE->unregister())) {
					logger(LOG_ERR, "Can't unregister CT %u",
							srcVE->veid());
					return rc;
				}
				/* and set rollback on error */
				addCleaner(clean_registerVE, srcVE);
			}
		}
	} else {
		if (m_nFlags & VZMSRC_SHARED_PRIV) {
			if (!isOptSet(OPT_KEEP_SRC)) {
				/* and unregister */
				if ((rc = srcVE->unregister())) {
					logger(LOG_ERR, "Can't unregister CT %u",
							srcVE->veid());
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
		// target will register resource on HA cluster here
		rc = channel.sendCommand(CMD_FINAL " %d", isOptSet(OPT_NOSTART)
	                           ? 0 : action);
		if (rc)
			return rc;

		if (isOptSet(OPT_CONVERT_VZFS)) {
			srcVE->kill_chkpnt();
			srcVE->umount();
		}
	}

	unregisterHA();

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

int MigrateStateRemote::checkCapabilities()
{
	/* logger(LOG_INFO, "Checking capabilities for online migration"); */
	/* int errcode = 0; */
	/* int rc = 0; */
	/* int retcode = 0; */
	/* unsigned unsupported; */

	/* channel.sendPkt(PACKET_SEPARATOR, CMD_CAPS); */
	/* const char * reply = channel.readReply(&errcode); */
	/* if (reply == NULL) */
	/* 	return putErr(MIG_ERR_CONN_BROKEN, MIG_MSG_REPLY); */
	/* if (errcode != 0) */
	/* 	return putErr(errcode, "%s", reply); */

	/* istringstream is(reply); */
	/* string cmd; */

	/* if ((is >> cmd >> cpu_flags) == NULL) */
	/* 	return putErr(MIG_ERR_PROTOCOL, MIG_MSG_PROTOCOL); */

	/* if (cmd.compare("CAPS") != 0) */
	/* { */
	/* 	logger(LOG_ERR, MIG_MSG_GET_CPU_CAPS); */
	/* 	if (isOptSet(OPT_FORCE)) */
	/* 	{ */
	/* 		logger(LOG_WARNING, MSG_FORCE_USED); */
	/* 		return 0; */
	/* 	} */
	/* 	else */
	/* 		return putErr(MIG_ERR_SYSTEM, MIG_MSG_GET_CPU_CAPS); */
	/* } */

	/* if (VZMoptions.remote_version <= MIGRATE_VERSION_460) { */
	/* 	  /1* See https://jira.sw.ru/browse/PSBM-11558 and *1/ */
	/* 	  /1* https://jira.sw.ru/browse/PCLIN-30480. *1/ */
	/* 	  /1* 13th bit is NO_IPV6 flag for 2.6.18 kernel *1/ */
	/* 	  /1* move it to 28th bit and clean *1/ */
	/* 	if (cpu_flags & (1U << CPT18_NO_IPV6)) */
	/* 		cpu_flags |= 1U << CPT32_NO_IPV6; */
	/* 	else */
	/* 		cpu_flags &= ~(1U << CPT32_NO_IPV6); */
	/* 	cpu_flags &= ~(1U << CPT18_NO_IPV6); */
	/* } */

	/* if (test_caps(srcVE->veid(), cpu_flags, &retcode, &unsupported)) */
	/* 	return putErr(MIG_ERR_SYSTEM, MIG_MSG_CHECK_CAPS); */

	/* switch (retcode) { */
	/* case 0: */
	/* 	return 0; */
	/* case VECAPS_UNSUPPORTED_FEATURE: */
	/* 	if (unsupported & (1 << CPT_EXTERNAL_PROCESS)) */
	/* 		return putErr(MIG_ERR_EXTERNAL_PROCESS, */
	/* 			"External process is in the container. " */
	/* 			"Probably 'vzctl exec' or 'vzctl enter' is active. " */
	/* 				); */
	/* 	rc = putErr(MIG_ERR_UNSUPP_CPU_CAPS, MIG_MSG_UNSUPPORTED); */
	/* 	logger(LOG_ERR, MIG_MSG_TRYOFFLINE); */
	/* 	return rc; */
	/* case VECAPS_NO_CPU_FEATURE: */
	/* 	if (!isOptSet(OPT_SKIP_CHECKCPU) && !isOptSet(OPT_FORCE)) { */
	/* 		//bug #65099 */
	/* 		rc = putErr(MIG_ERR_INSUFF_CPU_CAPS, MIG_MSG_INSUFF_CPU); */
	/* 		logger(LOG_ERR, MIG_MSG_VECAPS_FORCE); */
	/* 		return rc; */
	/* 	} */
	/* 	logger(LOG_ERR, MIG_MSG_INSUFF_CPU); */
	/* 	return 0; */
	/* case VECAPS_NO_IPV6_MODULE: */
	/* 	if (!isOptSet(OPT_FORCE)) { */
	/* 		rc = putErr(MIG_ERR_NO_IPV6_MODULE_CAPS, */
	/* 				MIG_MSG_NO_IPV6_MODULE_CAPS); */
	/* 		logger(LOG_ERR, MIG_MSG_VECAPS_FORCE); */
	/* 		return rc; */
	/* 	} */
	/* 	logger(LOG_ERR, MIG_MSG_NO_IPV6_MODULE_CAPS); */
	/* 	return 0; */
	/* case VECAPS_NO_SLM_MODULE: */
	/* 	if (!isOptSet(OPT_FORCE)) { */
	/* 		rc = putErr(MIG_ERR_NO_SLM_MODULE_CAPS, */
	/* 				MIG_MSG_NO_SLM_MODULE_CAPS); */
	/* 		logger(LOG_ERR, MIG_MSG_VECAPS_FORCE); */
	/* 		return rc; */
	/* 	} */
	/* 	logger(LOG_ERR, MIG_MSG_NO_SLM_MODULE_CAPS); */
	/* 	return 0; */
	/* case VECAPS_NO_MNT_NAMESPACES: */
	/* 	if (!isOptSet(OPT_FORCE)) { */
	/* 		rc = putErr(MIG_ERR_NO_MNT_NAMESPACES_CAPS, */
	/* 				MIG_MSG_NO_MNT_NAMESPACES_CAPS); */
	/* 		logger(LOG_ERR, MIG_MSG_VECAPS_FORCE); */
	/* 		return rc; */
	/* 	} */
	/* 	logger(LOG_ERR, MIG_MSG_NO_MNT_NAMESPACES_CAPS); */
	/* 	return 0; */
	/* default: */
	/* 	return putErr(MIG_ERR_SYSTEM, */
	/* 		"CT capabilities check returned %d", retcode); */
	/* } */

	/* return 0; */
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

int MigrateStateRemote::checkCPTImageVersion()
{
	int rc;

	if (VZMoptions.remote_version < MIGRATE_VERSION_460)
		return 0;

	logger(LOG_INFO, "Checking CPT image version for online migration");
	char buf[BUFSIZ];
	const char *cmd = BIN_VZTESTVER;
	FILE *fd;

	if ((fd = popen(cmd, "r")) == NULL)
		return putErr(MIG_ERR_SYSTEM, "popen('%s') : %m", cmd);

	if (fgets(buf, sizeof(buf), fd) == NULL) {
		pclose(fd);
		return putErr(MIG_ERR_SYSTEM,
			"can't get CPT image version (%s) : %m", cmd);
	}
	pclose(fd);

	rc = channel.sendCommand(CMD_CPT_VER " %s", buf);
	if ((VZMoptions.remote_version < MIGRATE_VERSION_550) || (rc == MIG_ERR_INCOMPAT_CPT_VER))
	{
		return putErr(rc, "Online migration is not supported.\n"
			"You are trying to migrate a running Container"
			" to the destination server with an old kernel.\n"
			"To migrate the Container, first update the kernel on"
			" the destination server or stop the Container before migration.");
	}
	return rc;
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

	if (srcVE->hasInternalBindmounts() &&
		VZMoptions.remote_version < MIGRATE_VERSION_605 &&
		isOptSet(OPT_CONVERT_VZFS))
		return putErr(MIG_ERR_CONVERT_BINDMOUNTS, MIG_MSG_CONVERT_BINDMOUNTS);

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
	int rc;
	START_STAGE();

	// Remove VE:
	// if remove=no
	// 	rename scripts/conf file to .migrated
	//	move VE private area to .migrated

	// destroy source VE

	// bug #68013
	if (isOptSet(OPT_READONLY) || isOptSet(OPT_KEEP_SRC))
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
			symlink(path, srcVE->confPath().c_str());
		}
	}

	/* and destroy VE without exitcode check */
	if (!(m_nFlags & VZMSRC_SHARED_PRIV))
		srcVE->destroy();

	END_STAGE();
	return 0;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *	Next functions provide 'copy' functionality for different cases
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 */


int MigrateStateRemote::h_copy_remote_rsync_dump(const char * src)
{
	if (isOptSet(OPT_KEEP_DUMP))
		logger(LOG_INFO, "Dumpfile will be saved as %s", srcVE->dumpfile);

	list<string> args;
	args.push_back("--delete");
	args.push_back(src);
	args.push_back(DUMMY_DEST);
	return remoteRsyncSrc(CMD_DUMPCOPY, false, args);
}

/* dumpdirs of source and target nodes are on the same cluster.
   Do not rsync dumpfile, copy name only */
int MigrateStateRemote::h_copy_cluster_dump(const char * dumpfile)
{
	int rc;
	char path[PATH_MAX];
	char *fname;

	if (isOptSet(OPT_KEEP_DUMP)) {
		snprintf(path, sizeof(path), "%s.1", srcVE->dumpfile);
		/* pcs is not support hardlinks */
		copy_file(path, srcVE->dumpfile);
		logger(LOG_ERR, "Dumpfile will be saved as %s", path);
	}

	assert(channel.isConnected());

	strncpy(path, dumpfile, sizeof(path));
	fname = basename(path);
	if ((rc = channel.sendCommand(CMD_CLUSTER_DUMPCOPY " %s", fname)))
		return rc;

	return 0;
}

int MigrateStateRemote::h_copy_remote_rsync_file(const char * cmd, const char * path)
{
	list<string> args;
	args.push_back("--delete");
	args.push_back(path);
	args.push_back(DUMMY_DEST);
	return remoteRsyncSrc(cmd, false, args);
}

/* Restore VE config from backup (<veprivate>/ve.conf.migrated)
   Used for migration in the same cluster */
int MigrateStateRemote::clean_restoreVEconf(const void * arg1, const void *)
{
	char path[PATH_MAX+1];
	VEObj *ve = (VEObj *)arg1;
	assert(ve);

	logger(LOG_DEBUG, "Restore CT %d config", ve->veid());
	snprintf(path, sizeof(path), "%s" SUFFIX_MIGRATED,
			ve->confRealPath().c_str());
	if (rename(path, ve->confRealPath().c_str()) == -1)
		logger(LOG_DEBUG, "rename(%s, %s) error: %s",
			path, ve->confRealPath().c_str(), strerror(errno));
	return 0;
};

/* start VE */
int MigrateStateRemote::clean_startVE(const void * arg1, const void * arg2)
{
	VEObj *ve = (VEObj *)arg1;
	assert(ve);

	logger(LOG_DEBUG, "Start CT %d", ve->veid());
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
	string_list_add(&ls, (char *)"--ignore-failed-read");
	string_list_add(&ls, (char *)"--numeric-owner");
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
		int *sock;
		/* for pcs-based CT migration we use tar twice for private migration,
		   but it is not needs copy temlate area for such CT. So will use tmpl_data_sock
		   for second step of copy of private area (https://jira.sw.ru/browse/PSBM-13684) */
		if (VZMoptions.data_sock == -1) {
			if (VZMoptions.tmpl_data_sock == -1) {
				rc = putErr(MIG_ERR_VZSOCK, "data_sock and tmpl_data_sock are closed");
				goto cleanup_0;
			} else {
				sock = &VZMoptions.tmpl_data_sock;
			}
		} else {
			sock = &VZMoptions.data_sock;
		}
		if ((rc = ch_send_str(&ch->ctx, ch->conn, cmd)))
			goto cleanup_0;

		do_block(*sock);
		rc = vzm_execve(args, NULL, *sock, *sock, &retcode);
		/* it's obligatory to close socket -
		   otherwise tar on destination node will not exit */
		close(*sock);
		*sock = -1;
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

int MigrateStateRemote::clean_closeChannel(const void * arg, const void *)
{
	logger(LOG_DEBUG, MIG_MSG_RST_CHANNEL);
	// Close pageout channel
	if (isOptSet(OPT_SSH_FWD))
		channel.fwdCloseSwap(arg);
	else
		vzsock_close_conn(&channel.ctx, (void *)arg);

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

	logger(LOG_ERR, "copy CT private %s", srcVE->priv);
	if (!(m_nFlags & VZMSRC_SHARED_PRIV)) {
		rc = copy_remote(srcVE->priv, exclude, isOptSet(OPT_USE_RSYNC));
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
	int rc;
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

int MigrateStateRemote::copy_active_delta(struct ploop_delta_desc *desc)
{
	char cmd[PATH_MAX];
	int rc;

	snprintf(cmd, sizeof(cmd), CMD_ONLINE_PLOOP_COPY_1 " %lu %s",
		desc->blksize, desc->delta);
	if ((rc = ch_send_cmd(&channel.ctx, channel.conn, cmd)))
		return rc;

	rc = ploop_src_online_copy_image_1(channel.getFd(1), VZMoptions.tmo.val,
			!isOptSet(OPT_NOCOMPRESS), desc);
	if (rc)
		return putErr(MIG_ERR_PLOOP,
			"Online copy of ploop image failed on stage 1, retcode %d", rc);

	/* wait command completition on target side */
	if ((rc = ch_read_retcode(&channel.ctx, channel.conn)))
		return rc;

	return rc;
}

int MigrateStateRemote::copy_active_delta_dirty(struct ploop_delta_desc *desc)
{
	int rc, fd = -1;
	char cmd[PATH_MAX];

	if (desc->mnt) {
		fd = syncPageCacheAndFreezeFS(desc->mnt);
		if (fd == -1)
			return MIG_ERR_SYSTEM;
	}

	logger(LOG_INFO, "Copy dirty blocks %s", desc->delta);
	snprintf(cmd, sizeof(cmd), CMD_ONLINE_PLOOP_COPY_2 " %lu %s",
		desc->blksize, desc->delta);

	if ((rc = ch_send_cmd(&channel.ctx, channel.conn, cmd)))
		goto err;

	if ((rc = ploop_src_online_copy_image_2(desc))) {
		rc =  putErr(MIG_ERR_PLOOP,
			"Online copy of ploop image failed on stage 2, retcode %d", rc);
		goto err;
	}

	/* wait command completition on target side */
	if ((rc = ch_read_retcode(&channel.ctx, channel.conn)))
		goto err;

err:
	if (fd != -1) {
		unfreezeFS(fd);
		close(fd);
	}

	return rc;
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

int MigrateStateRemote::copy_active_deltas()
{
	int rc;
	listDeltaDesc_t::const_iterator it;

	for (it = m_deltas.begin(); it != m_deltas.end(); ++it) {
		rc = copy_active_delta(*it);
		if (rc)
			return rc;
	}

	return 0;
}

int MigrateStateRemote::copy_active_deltas_dirty()
{
	int rc;
	listDeltaDesc_t::const_iterator it;

	for (it = m_deltas.begin(); it != m_deltas.end(); ++it) {
		rc = copy_active_delta_dirty(*it);
		if (rc)
			return rc;
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

// create copy of DiskDescription.xml
int MigrateStateRemote::createDiskDescriptorXmlCopy(const char *basedir, const char *delta,
		char *dd_copy, size_t size, int cleaner)
{
	char path[PATH_MAX+1];
	char fname[PATH_MAX+1];

	snprintf(path, sizeof(path), "%s/" DISKDESCRIPTOR_XML,
			get_full_path(basedir, delta, fname, sizeof(fname)));
	snprintf(dd_copy, size, "%s.migrate.xml", path);
	if (copy_file(dd_copy, path))
		return putErr(MIG_ERR_COPY, MIG_MSG_COPY_FILE, path, dd_copy, getError());
	addCleanerRemove(clean_removeFile, dd_copy, cleaner);

	/* *.lck file for xml config will create during snapshot creation.
	   now anybody remove .lck files so will do it yourself */
	snprintf(path, sizeof(path), "%s.lck", dd_copy);
	addCleanerRemove(clean_removeFile, path, cleaner);
	return 0;
}

static bool disk_is_non_shared(const struct disk_entry &d)
{
	return !d.is_shared();
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

/*
src node                                                dst node

copy external disk(s)

copy default DiskDescriptor.xml to local file
migrate memory
vzctl chkpnt --suspend

copy external active delta(s)

vzctl chkpnt --dump
create snapshot A
                                                        create snapshot B
                                                        vzctl chkpnt --undump
                                                        register CT
                                                        vzctl chkpnt --restore
vzctl chkpnt --kill
vzctl umount
                                                        merge snapshot B
                                                        finish
unregister CT
remove custom DiskDescriptor.xml
remove snapshot A
finish
*/
int MigrateStateRemote::doOnlinePloopSharedCtMigration()
{
	int rc;
	char path[PATH_MAX+1];
	// create copy of DiskDescription.xml
	char dd_xml2[PATH_MAX+1];
	char dd_xml[PATH_MAX+1];
	struct string_list active_delta;
	std::list<std::string> snap_info_list;
	std::list<std::string>::const_iterator sit;

	string_list_init(&active_delta);

	ct_disk disks = srcVE->m_disks.get(disk_is_non_shared);

	rc = getActivePloopDelta(disks, &active_delta);
	if (rc)
		return rc;

	rc = open_active_deltas(&active_delta);
	if (rc)
		goto err1;

	rc = copy_ct(&active_delta);
	if (rc)
		goto err1;

	rc = copy_active_deltas();
	if (rc)
		goto err1;

	/*
	 * start of offline mode
	 */
	if ((rc = stopVE()))
		goto err1;

	srcVE->gen_snap_guid();
	for (ct_disk::const_iterator it = srcVE->m_disks.begin();
			it != srcVE->m_disks.end(); ++it)
	{
		if (!it->is_shared())
			continue;

		rc = createDiskDescriptorXmlCopy(srcVE->priv, it->image.c_str(),
				dd_xml2, sizeof(dd_xml2), ANY_CLEANER);
		if (rc)
			goto err;

		rc = MigrateStateCommon::ploopCreateSnapshot(dd_xml2, srcVE->snap_guid());
		if (rc)
			goto err;

		snap_info_list.push_back(dd_xml2);

		std::ostringstream d;
		d << (VZMoptions.remote_version < MIGRATE_VERSION_606 ?
			CMD_CREATE_PLOOP_SNAPSHOT : CMD_CREATE_PLOOP_SNAPSHOT_NO_ROLLBACK);
		d << " " <<  srcVE->snap_guid() << " " << it->image;
		if ((rc = ch_send_cmd(&channel.ctx, channel.conn, d.str().c_str())))
			goto err;
	}

	if (use_iteration && VZMoptions.invert_lazy_flag) {
		// Set LAZY flag on dst node
		// We need to do this only one time
		rc = invertLazyFlag();
		if (rc != 0) {
			logger(LOG_ERR, MIG_MSG_ITER, dstVE->veid(), getError());
			goto err;
		}
		VZMoptions.invert_lazy_flag = 0;
	}

	/* Copy external active deltas stage(2) */
	rc = copy_active_deltas_dirty();
	if (rc)
		goto err;

	close_active_deltas();

	rc = channel.sendCommand(CMD_UNDUMP);
	if (rc != 0)
	{
		logger(LOG_ERR, MIG_MSG_UNDUMP, dstVE->veid(), getError());
		/* for debug purposes */
		snprintf(path, sizeof(path), "%s.saved", srcVE->dumpfile);
		rename(srcVE->dumpfile, path);
		logger(LOG_ERR, "Dumpfile %s saved", path);
		goto err;
	}

	rc = channel.sendCommand(CMD_NON_FINAL_RESUME);
	if (rc != 0)
	{
		logger(LOG_ERR, MIG_MSG_DST_RESUME, dstVE->veid(), getError());
		/* for debug purposes */
		snprintf(path, sizeof(path), "%s.saved", srcVE->dumpfile);
		rename(srcVE->dumpfile, path);
		logger(LOG_ERR, "Dumpfile %s saved", path);
		goto err;
	}

	/* CT is running on destination side now, so will ignore error
	 * on source and try to remove CT by any path (https://jira.sw.ru/browse/PSBM-12622) */

	/*
	 * At the first to copy original CT config to /etc/..., so shared config may
	 * be changed by target side. see https://jira.sw.ru/browse/PSBM-12643
	 */

	if (m_nFlags & VZMSRC_SHARED_PRIV) {
		snprintf(path, sizeof(path), "%s" SUFFIX_MIGRATED, srcVE->confRealPath().c_str());
		unlink(srcVE->confPath().c_str());
		copy_file(srcVE->confPath().c_str(), path);
	}

	// Now we should restore (before dst VE starting) VEs IP from keeperVE
	if (isOptSet(OPT_KEEPER))
	{
		assert(keepVE);
		restoreIPs(*keepVE, *srcVE);
	}

	if (!offlineTurned)
	{
		if (srcVE->offlineManagement(false)) {
			addCleaner(clean_restoreOfflineManagement, srcVE);
			offlineTurned = true;
		}
	}

	/* stop and umount CT _before_ merge on target */
	if (srcVE->kill_chkpnt())
		logger(LOG_ERR, MIG_MSG_STOP, srcVE->veid(), getError());

	if (srcVE->umount()) {
		logger(LOG_ERR, MIG_MSG_STOP, srcVE->veid(), getError());
	} else {
		// do not merge snapshot on target if umount failed
		// https://jira.sw.ru/browse/PSBM-21804
		for (ct_disk::const_iterator it = srcVE->m_disks.begin();
				it != srcVE->m_disks.end(); ++it)
		{
			if (!it->is_shared())
				continue;

			std::ostringstream d;
			d << CMD_MERGE_PLOOP_SNAPSHOT << " " << srcVE->snap_guid() << " "
				<< it->image;
			ch_send_cmd(&channel.ctx, channel.conn, d.str().c_str());

		}
	}

	/* and stop target side */
	channel.sendCommand(CMD_STOP);

	/* to remote snapshot */

	for (sit = snap_info_list.begin(); sit != snap_info_list.end(); ++sit)
		if (MigrateStateCommon::ploopGetTopImageFileName((*sit).c_str(), path, sizeof(path)) == 0)
			unlink(path);

	/* and unregister */
	srcVE->unregister();
	unregisterHA();
	cleanExternalDisk();

	if (!(m_nFlags & VZMSRC_SHARED_PRIV))
		clean_removeDir(srcVE->priv, NULL);

	string_list_clean(&active_delta);
	close_active_deltas();

	return 0;

err:
	/* will wait till vzmdest complete rollback and close socket
	   to avoid fatal async undump/merge on shared PCS
	   https://jira.sw.ru/browse/PSBM-11228 */

	finishDestination();

	/* CT has reregistered on CMD_UNDUMP stage return back */
	srcVE->registration();

	for (sit = snap_info_list.begin(); sit != snap_info_list.end(); ++sit) {
		const char *xml2 = (*sit).c_str();

		/* remove top delta from dst */
		snprintf(dd_xml, strlen(xml2) - sizeof(".migrate.xml") + 2, "%s", xml2);
		if (MigrateStateCommon::ploopGetTopImageFileName(dd_xml, path, sizeof(path)) == 0) {
			if (unlink(path))
				logger(LOG_ERR, "Failed to remove dst top delta %s: %m", path);
		}

		/* rollback two DiskDescriptor.xml hack
		 * move back DiskDescriptor.xml
		 */
		if (rename(xml2, dd_xml) == 0 || copy_file(dd_xml, xml2) == 0)
			MigrateStateCommon::ploopDeleteSnapshot(dd_xml, srcVE->snap_guid());
	}

err1:
	string_list_clean(&active_delta);
	close_active_deltas();

	return rc;
}

/* Offline migration with shared VE_PRIVATE
 * copy external disk and regiter on dst
 */
int MigrateStateRemote::doOfflinePloopCtMigration()
{
	return copy_ct(NULL);
}

int MigrateStateRemote::doOnlinePloopCtMigration()
{
	int rc;
	struct string_list active_delta;

	string_list_init(&active_delta);

	rc = getActivePloopDelta(srcVE->m_disks.get(disk_is_non_shared),
			&active_delta);
	if (rc)
		return rc;

	rc = open_active_deltas(&active_delta);
	if (rc)
		goto err;

	rc = copy_ct(&active_delta);
	if (rc)
		goto err;

	rc = copy_active_deltas();
	if (rc)
		goto err;

	/* skip CT unmount to perform copy_active_deltas_dirty */
	setOpt(OPT_SKIP_UMOUNT);
	if ((rc = stopVE()))
		goto err;

	rc = copy_active_deltas_dirty();
	if (rc)
		goto err;

	close_active_deltas();

	srcVE->umount();

	return 0;
err:
	close_active_deltas();

	return rc;
}

bool MigrateStateRemote::isSameLocation()
{
	return m_nFlags & VZMSRC_SHARED_PRIV;
}
