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
#include <sys/wait.h>
#include <sys/vfs.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <fcntl.h>
#include <vector>
#include <string>

#include <vzctl/libvzctl.h>
#include <ploop/libploop.h>

#include "util.h"
#include "migratedst.h"
#include "migssh.h"
#include "common.h"
#include "veentry.h"
#include "vzacompat.h"
#include "channel.h"
#include "migchannel.h"
#include "multiplexer.h"

extern struct vz_data *vzcnf;
extern void *istorage_ctx;

MigrateStateDstRemote::MigrateStateDstRemote(VEObj * ve, int options)
	: MigrateStateCommon()
	, dstVE(ve)
	, m_initOptions(options)
{
	assert(dstVE != NULL);

	addCleaner(clean_delVeobj, dstVE, NULL, ANY_CLEANER);

	func_copyFirst = &MigrateStateDstRemote::h_copy_remote_tar;
	func_copyFile = &MigrateStateDstRemote::h_copy_remote_rsync_file;

	is_thesame_private = 0;
	is_privdir_exist = 0;
	is_keepdir_exist = 0;
	is_priv_on_shared = 0;
	m_nXxlTimeout = 0;
	m_convertQuota2[0] = '\0';
};

MigrateStateDstRemote::~MigrateStateDstRemote()
{
}

int MigrateStateDstRemote::clean_destroy(const void * arg, const void *)
{
	VEObj * ve = (VEObj *) arg;
	assert(ve);
/*	call destroy for 'unexisted' VE too (non-existed private, etc...)
	if (!ve->isexist())
		return 0; */
	logger(LOG_DEBUG, MIG_MSG_RST "destroy CT %s", ve->ctid());
	ve->destroy();
	return 0;
};

int MigrateStateDstRemote::clean_unregister(const void * arg, const void *)
{
	VEObj * ve = (VEObj *) arg;
	assert(ve);
	logger(LOG_DEBUG, MIG_MSG_RST "unregister CT %s", ve->ctid());
	ve->unregister();
	return 0;
};

int MigrateStateDstRemote::clean_umount(const void * arg, const void *)
{
	VEObj * ve = (VEObj *) arg;
	assert(ve);
	logger(LOG_DEBUG, MIG_MSG_RST "umount CT %s", ve->ctid());
	ve->umount();
	return 0;
};

int MigrateStateDstRemote::clean_deletePloopSnapshot(const void * arg1, const void *arg2)
{
	return MigrateStateCommon::ploopDeleteSnapshot((const char *)arg1, ((const char *)arg2));
};

int MigrateStateDstRemote::clean_unregisterOnHaCluster(const void * arg1, const void *arg2)
{
	VEObj * ve = (VEObj *) arg1;
	assert(ve);
	char *sHaClusterNodeID = (char *)arg2;
	assert(sHaClusterNodeID);

	if ((sHaClusterNodeID == NULL) || (strlen(sHaClusterNodeID) == 0)) {
		logger(LOG_DEBUG, "unregister HA cluster resource %s", ve->ctid());
		runHaman(ve->ctid(), "del");
	} else {
		logger(LOG_DEBUG, "move HA cluster resource %s to node %s", ve->ctid(), sHaClusterNodeID);
		runHaman(ve->ctid(), "move-to", sHaClusterNodeID);
	}
	free(sHaClusterNodeID);
	return 0;
};

int MigrateStateDstRemote::clean_termPhaulSrv(const void * arg, const void *)
{
	const int TERM_TIMEOUT = 3;
	pid_t* phaulSrvPid = (pid_t*)arg;

	if (*phaulSrvPid > 0)
		term_clean(*phaulSrvPid, TERM_TIMEOUT);

	delete phaulSrvPid;
	return 0;
}

// on Freebsd: VE private overwriting doesn't supported now
// 'cause migrate knows nothing about uid/gidbase for this directory
#define PRIVATECHECK	0

int MigrateStateDstRemote::initVEMigration(VEObj * ve)
{
	int rc;

	START_STAGE();
	assert(ve && ve->priv && ve->root);

	if ((rc = checkDstIDFree(*ve)))
		return rc;

	ve->clean();
	ve->setLayout(option_to_vzlayout(m_initOptions));
	ve->veformat = option_to_veformat(m_initOptions);
	logger(LOG_INFO, "Start of CT %s migration (private %s [%s], root %s, opt=%d, version remote %d, local %d)",
		ve->ctid(), ve->priv,
		ve->priv_custom ? "custom" : "default",
		ve->root, m_initOptions,
		VZMoptions.remote_version, MIGRATE_VERSION);

	/* migration to 7.0 from versions lower than 612 is not supported */
	if (VZMoptions.remote_version < MIGRATE_VERSION_612)
		return putErr(MIG_ERR_SYSTEM, MIG_MSG_FROM_ELDER);

	/* online migration to 7.0 from lower version is not supported */
	if (!isOptSet(OPT_AGENT) && isOptSet(OPT_ONLINE) &&
		(VZMoptions.remote_version < MIGRATE_VERSION_700))
		return putErr(MIG_ERR_ONLINE_ELDER, MIG_MSG_ONLINE_ELDER);

	if (m_initOptions & MIGINIT_CONVERT_VZFS) {
		logger(LOG_DEBUG, "The file system of a Container will be converted to ext4.");
		setOpt(OPT_CONVERT_VZFS);
	}

	if ((rc = checkCommonDst(*ve)))
		return rc;

	/* check target private existance */
	if (access(ve->priv, F_OK) == 0) {
		int layout = vzctl2_env_layout_version(ve->priv);

		if (layout > 0 && layout != ve->layout)
			return putErr(MIG_ERR_SYSTEM, "Can't migrate: there is private area "
					"%s with different layout %d on destionation",
					ve->priv, layout);

		is_privdir_exist = 1;
	}

	/* check old migrated directory exist */
	string keepDir = string(ve->priv) + SUFFIX_MIGRATED;
	if (access(keepDir.c_str(), F_OK) == 0) {
		/* 1. Do not use keep dir for ploop based CT on vz6 and previous vz7 */
		/* 2. If private exist then keep dir is obsoleted */
		/* 3. Don's use on layout mismatch */
		/* 4. Don's use on vzfs conversion */
		if (((m_initOptions & MIGINIT_LAYOUT_5) &&
					(VZMoptions.remote_version < MIGRATE_VERSION_701)) ||
				access(ve->priv, F_OK) == 0 ||
				vzctl2_env_layout_version(keepDir.c_str()) != ve->layout ||
				isOptSet(OPT_CONVERT_VZFS)) {
			clean_removeDir(keepDir.c_str());
		} else {
			logger(LOG_INFO, "Use old .migrated folder");
			if (::rename(keepDir.c_str(), ve->priv) != 0)
				return putErr(MIG_ERR_SYSTEM, MIG_MSG_MOVE, keepDir.c_str(), ve->priv);
			addCleanerRename(ve->priv, keepDir.c_str(), 0);

			is_keepdir_exist = 1;
		}
	}

	// check VE root
	if ((rc = checkVEDir(ve->root)) < 0)
		return rc;
	else if (rc == 0)
		// add error remover only for created directory
		// not for existed
		// and will remove only empty root, to avoid remove CT data
		// due to 'vzctl stop/umount' failure
		// https://jira.sw.ru/browse/PSBM-20171
		addCleanerRemove(clean_rmDir, ve->root);

	// check VE private
	if ((rc = checkVEDir(ve->priv, PRIVATECHECK)) < 0)
		return rc;
	else if (rc == 0 && !(m_initOptions & MIGINIT_KEEP_DST))
		// add error remover only for created directory
		// not for existed
		addCleanerRemove(clean_removeDir, ve->priv);

	// do not use --sparse option for ploop image copy
	use_sparse_opt = (ve->layout < VZCTL_LAYOUT_5);

	END_STAGE();
	return 0;
}

int MigrateStateDstRemote::initMigration()
{
	return initVEMigration(dstVE);
}

int MigrateStateDstRemote::cmdCheckLicense()
{
	// obsoleted, licensing removed starting from Vz7
	return 0;
}

int MigrateStateDstRemote::cmdCheckDiskSpace(istringstream &is)
{
	unsigned long long bytes, inodes;

	if ((is >> bytes >> inodes) == NULL)
		return putErr(MIG_ERR_PROTOCOL, MIG_MSG_PROTOCOL);

	return check_free_space(dstVE->priv, bytes, inodes);
}

int MigrateStateDstRemote::cmdCheckTechnologies(istringstream &is, ostringstream & os)
{
	unsigned long technologies;
	if ((is >> technologies) == NULL)
		return putErr(MIG_ERR_PROTOCOL, MIG_MSG_PROTOCOL);
	logger(LOG_DEBUG, "cmdCheckTechnologies %u",  technologies);

	/* It is bad place to lock dstVE, but we can not do it for CT on shared FS
	 * _before_ CMD_CHECK_CLUSTER command (if private at really is shared)
	 * and we can not do it from CMD_CHECK_CLUSTER command handler (so src side
	 * will not send this command if private is not on shared FS on source
	 * https://jira.sw.ru/browse/PSBM-21615)
	 * CMD_CHECK_TECHNOLOGIES is suitable place:
	 * - src always will send this command
	 * - this command was added on VZ4.0 */
	if (!(m_nFlags & VZMSRC_SHARED_PRIV) && !dstVE->islocked()) {
		int rc;

		if ((rc = dstVE->lock()))
			return rc;
	}

	os << "checktechnologies " << dstVE->checkTechnologies(&technologies);
	return 0;
}

int MigrateStateDstRemote::cmdCheckRate()
{
	if (!vzcnf->shaping)
		return 0;
	return check_rate(&dstVE->ve_data.rate);
}

int MigrateStateDstRemote::cmdCheckName(istringstream &is)
{
	int rc;
	char buf[PATH_MAX+1];
	char *name;

	/* read name (and with spaces too) */
	is.read(buf, sizeof(buf));
	if (is.bad())
		return putErr(MIG_ERR_PROTOCOL, MIG_MSG_PROTOCOL);
	buf[is.gcount()] = '\0';

	/* now skip leading spaces */
	for (name = buf; *name == ' '; name++);
	if (strlen(name) == 0)
		return putErr(MIG_ERR_PROTOCOL, MIG_MSG_PROTOCOL);

	if ((rc = dstVE->checkName(name)))
		return rc;

	dst_name = strdup(name);
	return 0;
}

/* compare source cluster id and path with destination cluster id and path */
static int check_cluster_id(
		const char *path,
		const char *src_id,
		const char *src_lp,
		int *is_thesame_cluster,
		int *is_thesame_path)
{
	int rc;
	char dst_id[GFS_LOCKNAME_LEN+1];
	char dst_lp[PATH_MAX+1];
	char mpoint[PATH_MAX+1];

	if (is_thesame_cluster)
		*is_thesame_cluster = 0;
	*is_thesame_path = 0;

	if ((rc = split_path(path,
			mpoint, sizeof(mpoint), dst_lp, sizeof(dst_lp))))
		return rc;
	if (strlen(dst_lp) == 0)
		strcpy(dst_lp, ".");

	if (strcmp(src_id, dst_id) == 0) {
		if (is_thesame_cluster)
			*is_thesame_cluster = 1;
		*is_thesame_path = (strcmp(dst_lp, src_lp) == 0);
	}

	return 0;
}


/* process 'cluster id request': get cluster id of target VE private,
   compare in success, and send '1' if it the same cluster */
int MigrateStateDstRemote::cmdCheckClusterID(
			istringstream &is,
			ostringstream & os)
{
	int rc;
	string src_id, mpath;
	int is_thesame_cluster;

	if ((is >> src_id >> mpath) == NULL)
		return putErr(MIG_ERR_PROTOCOL, MIG_MSG_PROTOCOL);

	if ((rc = is_path_on_shared_storage(dstVE->priv, &is_priv_on_shared, NULL)))
		return rc;

	if (!is_priv_on_shared)
		return 0;

	/* check default (or custom) private area */
	if ((rc = check_cluster_id(dstVE->priv, src_id.c_str(), mpath.c_str(),
			&is_thesame_cluster, &is_thesame_private)))
		return rc;

	if (is_thesame_cluster) {
		if (is_thesame_private) {
			logger(LOG_DEBUG, MIG_MSG_THESAME_CLUSTER,
				"CT privates", src_id.c_str());
			/* and copy source VE config from original private */
			if ((rc = copy_file(dstVE->confPath().c_str(),
					dstVE->confRealPath().c_str())))
				return putErr(MIG_ERR_COPY, MIG_MSG_COPY_FILE,
					dstVE->confRealPath().c_str(),
					dstVE->confPath().c_str(),
					getError());
			addCleanerRemove(clean_removeFile, dstVE->confPath().c_str());

			/* update & load config here, so confset command will not send
			   by source side for shared private case
			   https://jira.sw.ru/browse/PCLIN-29435 */
			if ((rc = dstVE->prepareConfig()))
				return rc;
			if ((rc = dstVE->loadConfig()))
				return rc;

			os << "1";
			return 0;
		} else {
			/* the same cluster, but other path */
			os << "0";
			return 0;
		}
	}

	if (dstVE->isCustomPrivate()) {
		/* private specified by sender - will copy */
		os << "0";
		return 0;
	}

	os << "0";

	return 0;
}

int MigrateStateDstRemote::cmdCheckSharedFile(
		istringstream &is, ostringstream &os)
{
	struct stat st;
	std::string file;

	if (!(is >> file))
		return putErr(MIG_ERR_PROTOCOL, MIG_MSG_PROTOCOL);

	if (stat(file.c_str(), &st)) {
		if (errno != ENOENT)
			return putErr(MIG_ERR_SYSTEM,
				"Failed to stat %s: %m",
				file.c_str());
		os << "0";
	} else
		os << "1";

	return 0;
}

/* process 'private on shared FS request':
   seek file <name> in target private area */
int MigrateStateDstRemote::cmdCheckSharedPriv(
			istringstream &is,
			ostringstream & os)
{
	int rc;
	string name, path;
	struct stat st;

	if ((is >> name) == NULL)
		return putErr(MIG_ERR_PROTOCOL, MIG_MSG_PROTOCOL);

	if (!dstVE->priv_custom) {
		string src_priv;

		is >> src_priv;

		if (!src_priv.empty()) {
			path = src_priv + string("/") + name;
			if (stat(path.c_str(), &st) == 0) {
				logger(LOG_WARNING, "Update CT private %s -> %s",
					dstVE->priv, src_priv.c_str());
				dstVE->setPrivate(src_priv.c_str());
				is_thesame_private = 1;
			}
		}
	}

	if (!is_thesame_private) {
		path = dstVE->priv + string("/") + name;
		if (stat(path.c_str(), &st) == 0)
			is_thesame_private = 1;
	}

	if ((rc = is_path_on_shared_storage(dstVE->priv, &is_priv_on_shared, NULL)))
		return rc;

	if (!is_thesame_private) {
		/* and lock VE only after private creation
		   (vzctl will create lock file in private, #119945) */
		/* postpone lock for 'private on nfs' case until
		   'the same private' check (MigrateStateDstRemote::cmdCheckSharedPriv)
		   If it's the same private, it's already locked by source side (#476968) */
		/* do not lock for gfs/gfs2 too (https://jira.sw.ru/browse/PCLIN-29890) */
		if ((rc = dstVE->lock()))
			return rc;

		os << "0";
		return 0;
	}

	m_nFlags |= VZMSRC_SHARED_PRIV;
	logger(LOG_DEBUG, MIG_MSG_THESAME_SHARED, "CT private", dstVE->priv);

	/* and copy source VE config from original private */
	if ((rc = copy_file(dstVE->confPath().c_str(),
			dstVE->confRealPath().c_str())))
		return putErr(MIG_ERR_COPY, MIG_MSG_COPY_FILE,
			dstVE->confRealPath().c_str(),
			dstVE->confPath().c_str(),
			getError());

	addCleanerRemove(clean_removeFile, dstVE->confPath().c_str());

	/* update & load config here, so confset command will not send
	   by source side for shared private case
	   https://jira.sw.ru/browse/PCLIN-29435 */
	if ((rc = dstVE->prepareConfig()))
		return rc;
	if ((rc = dstVE->loadConfig()))
		return rc;
	os << "1";

	return 0;
}

int MigrateStateDstRemote::cmdCheckClusterTmpl(
			istringstream &is,
			ostringstream & os)
{
	int rc;
	string src_id, mpath;
	int is_thesame_path;

	if ((is >> src_id >> mpath) == NULL)
		return putErr(MIG_ERR_PROTOCOL, MIG_MSG_PROTOCOL);

	if ((rc = check_cluster_id(dstVE->tmplDir().c_str(),
			src_id.c_str(), mpath.c_str(), NULL, &is_thesame_path)))
		return rc;

	if (is_thesame_path) {
		logger(LOG_DEBUG, MIG_MSG_THESAME_CLUSTER,
				"template areas", src_id.c_str());
		os << "1";
	}
	else
		os << "0";

	return 0;
}

int MigrateStateDstRemote::cmdCheckSharedTmpl(
			istringstream &is,
			ostringstream & os)
{
	string name;
	char path[PATH_MAX+1];
	struct stat st;

	if ((is >> name) == NULL)
		return putErr(MIG_ERR_PROTOCOL, MIG_MSG_PROTOCOL);

	snprintf(path, sizeof(path), "%s/%s", dstVE->tmplDir().c_str(), name.c_str());
	if (stat(path, &st) == 0) {
		logger(LOG_DEBUG, MIG_MSG_THESAME_SHARED, "template areas", path);
		os << "1";
	} else {
		os << "0";
	}

	return 0;
}

/* is keep dir & can we use tar for VE private area copy? */
int MigrateStateDstRemote::cmdCheckKeepDir(
			ostringstream & os)
{
	if (!is_keepdir_exist && !is_privdir_exist) {
		os << "0";
		return 0;
	}

	if (is_privdir_exist && is_priv_on_shared && !is_thesame_private) {
		/* yes, it's a bad place for this check.
		   But this function will to call all mandatory for
		   vzmigrate >= 4 and after cluster check.
		   Target private area already exist, and exist on the cluster,
		   and this cluster is other then source.
		   vzmigrate can't rewrote this private (#89400) */
		return putErr(MIG_ERR_EXISTS,
			"Target private area %s already exists and "
			"resides on cluster", dstVE->priv);
	}

	/* will use rsync for privatre area */
	func_copyFirst = &MigrateStateDstRemote::h_copy_remote_rsync;
	os << "1";
	return 0;
}

/*
   To check options from source side. Sender wait acknowledgement for next options:
   OPT_WHOLE_FILE, OPT_USE_RSYNC.
   Will to check and to confirm only this options.
*/
int MigrateStateDstRemote::cmdCheckOptions(istringstream & is, ostringstream & os)
{
	int rc;
	string str;
	unsigned long long req_options;
	unsigned long long ack_options;

	if ((is >> str) == NULL)
		return putErr(MIG_ERR_PROTOCOL, MIG_MSG_PROTOCOL);

	req_options = atoll(str.c_str());
	ack_options = 0;
	if (req_options & OPT_WHOLE_FILE) {
		logger(LOG_DEBUG, "Switch on --whole-file option");
		setOpt(OPT_WHOLE_FILE);
		ack_options |= OPT_WHOLE_FILE;
	}
	if (req_options & OPT_USE_RSYNC) {
		logger(LOG_DEBUG, "Switch on OPT_USE_RSYNC option");
		func_copyFirst = &MigrateStateDstRemote::h_copy_remote_rsync;
		setOpt(OPT_USE_RSYNC);
		ack_options |= OPT_USE_RSYNC;
	}
 	if (req_options & OPT_SSH_FWD) {
 		logger(LOG_DEBUG, "Switch on OPT_SSH_FWD");
		// bind to ssh redirected port
		if ((rc = MigrateStateCommon::channel.fwdBind())) {
			return putErr(rc, "can bind to redirected port");
		} else {
			setOpt(OPT_SSH_FWD);
			ack_options |= OPT_SSH_FWD;
		}
 	}
	os << ack_options;

	return 0;
}

int MigrateStateDstRemote::cmdAdjustXxlTimeout(istringstream &is)
{
	if ((is >> m_nXxlTimeout) == NULL)
		return putErr(MIG_ERR_PROTOCOL, MIG_MSG_PROTOCOL);
	logger(LOG_DEBUG, "Set custom XXL timeout %ld sec", m_nXxlTimeout);
	return 0;
}

/* check and load kernel modules */
int MigrateStateDstRemote::cmdCheckKernelModules(istringstream &is)
{
	int rc;
	string module;
	char buf[BUFSIZ];
	char * const args[] = {(char *)BIN_SUDO, (char *)"/sbin/modprobe", buf, NULL };

	while (is >> module)
	{
		strncpy(buf, module.c_str(), sizeof(buf));
		if (isOptSet(OPT_SUDO))
			rc = vzm_execve(args, NULL, -1, -1, NULL);
		else
			/* do not call sudo if it is not need - https://jira.sw.ru/browse/PSBM-8694 */
			rc = vzm_execve(&(args[1]), NULL, -1, -1, NULL);
		if (rc)
			return putErr(MIG_ERR_SYSTEM, MIG_MSG_CHECK_KERNEL_MODULES, buf);
	}

	return 0;
}

int MigrateStateDstRemote::cmdTemplateSync(istringstream &)
{
	// obsoleted, template syncronization removed starting from Vz7
	return MIG_ERR_EXISTS;
}

int MigrateStateDstRemote::cmdHaClusterNodeID(istringstream &is, ostringstream &os)
{
	int rc;
	string id;

	rc = getHaClusterNodeID(id);
	if (rc)
		return rc;

	if (id.empty()) {
		// this node is not in ha cluster
		os << "0";
		return 0;
	}

	if ((is >> m_sHaClusterNodeID) == NULL)
		return putErr(MIG_ERR_PROTOCOL, MIG_MSG_PROTOCOL);
	logger(LOG_DEBUG, "Set HA cluster node ID %s", m_sHaClusterNodeID.c_str());
	os << "1";
	return 0;
}

std::string MigrateStateDstRemote::getCopyArea()
{
	std::string dst;

	if (isOptSet(OPT_CONVERT_VZFS))
		dst = dstVE->root;
	else
		dst = dstVE->getVEPrivateVZFS();

	return dst;
}

int MigrateStateDstRemote::copyStage(int stage)
{
	assert(dstVE && dstVE->priv);

	switch (stage) {
	case SIMPLECOPY:
		return (this->*func_copyFirst)(dstVE->priv);
	case FASTCOPY:
		return h_copy_remote_rsync_fast(getCopyArea().c_str(),
				isOptSet(OPT_CONVERT_VZFS) ? METHOD_CHECKSUM : METHOD_TRACKER);
	case FASTCOPY_TRACKER:
		return h_copy_remote_rsync_fast(getCopyArea().c_str(), METHOD_TRACKER);
	case FASTCOPY_BINDMOUNTS:
		return h_copy_remote_rsync_fast(dstVE->bindmountPath().c_str(), METHOD_CHECKSUM);
	}
	return 0;
}

int MigrateStateDstRemote::copySetConf()
{
	int rc;
	VEObj * ve = dstVE;
	assert(ve);

	/* copy from src node */
	if ((rc = (this->*func_copyFile)(ve->confPath().c_str())))
		return rc;

	/* update config */
	if ((rc = ve->prepareConfig()))
		return rc;

	/* load config */
	if ((rc = dstVE->loadConfig()))
		return rc;

	addCleaner(clean_destroy, dstVE);

	/* bugs #66577 and #95232 */
	if (m_initOptions & MIGINIT_KEEP_DST) {
		string keepDir = string(ve->priv) + SUFFIX_MIGRATED;
		addCleanerRename(ve->priv, keepDir.c_str(), 0);
	}
	END_STAGE();
	return rc;
}

int MigrateStateDstRemote::restore_dd_xml(const ct_disk &disks)
{
	for (ct_disk::const_iterator it = disks.begin();
			it != disks.end(); ++it)
	{
		std::string d = get_dd_xml(it->image.c_str());
		std::string s = d + ".mig";

		logger(LOG_INFO, "Restore %s", d.c_str());
		if (::rename(s.c_str(), d.c_str()) && errno != ENOENT)
			return putErr(MIG_ERR_SYSTEM, "rename(%s, %s) : %m",
					s.c_str(), d.c_str());
	}

	return 0;
}

/* final VE operation before start/mounting */
int MigrateStateDstRemote::finalVEtuning()
{
	int rc = 0;

	if (m_convertQuota2[0] != '\0') {
		if ((rc = applyPloopQuotaImpl(m_convertQuota2)))
			return rc;
	}

	if (m_initOptions & MIGINIT_KEEP_SRC) {
		rc = restore_dd_xml(dstVE->m_disks);
		if (rc)
			return rc;

		if (dstVE->mount() == 0) {
			regenerate_fs_uuid(dstVE->root);
			dstVE->umount();
		}
	
		rc = dstVE->renewMAC();
		if (rc)
			return rc;
	}

	logger(LOG_INFO, "End of CT %s migration", dstVE->ctid());
	return rc;
}

int MigrateStateDstRemote::finalStage(int action)
{
	int rc;

	if (isOptSet(OPT_CONVERT_VZFS)) {
		if ((rc = pfcache_set(dstVE->root, 0)))
			return rc;
	}

	if ((rc = registerOnHaCluster()))
		goto err;

	// Reread information about CT disks from config
	if ((rc = rereadVeDisksFromConfig()))
		goto err;

	if ((rc = deleteKeepDstSnapshots(*dstVE)))
		goto err;

	if (action == DSTACT_START_VE)
		rc = dstVE->start();
	else if (action == DSTACT_MOUNT_VE)
		rc = dstVE->mount();
	if (rc)
		goto err;

	/* rollback registration */
	if (is_priv_on_shared && !(m_initOptions & MIGINIT_KEEP_SRC)) {
		std::string f = dstVE->priv;
		f += "/.owner";
		h_backup(f.c_str());
	}

	if (dst_name)
		dstVE->setNameData(dst_name);
	/* vzctl register for new layout VE */
	if ((rc = dstVE->veRegister()))
		goto err;
	addCleaner(clean_unregister, dstVE);

	if ((rc = finalVEtuning()))
		goto err1;

	dstVE->unlock();

	return 0;

err1:
	if (action == DSTACT_START_VE)
		dstVE->stop();
	else if (action == DSTACT_MOUNT_VE)
		dstVE->umount();

err:
	if (isOptSet(OPT_ONLINE))
		dstVE->kill();

	dstVE->unlock();

	return rc;
}


int MigrateStateDstRemote::resume(void)
{
// need to adjust to new c/r technology
#if 0
	int rc;

	if ((rc = dstVE->resume_restore(isOptSet(OPT_NOCONTEXT))) != 0)
		return rc;

	if ((rc = finalVEtuning()))
		return rc;

	return 0;
#endif
	return -1;
}

int MigrateStateDstRemote::registerOnHaCluster()
{
	int rc;

	if (!dstVE->ve_data.ha_enable)
		return 0;
	if (!is_priv_on_shared) {
		int shared = 0;
		if ((rc = is_path_on_shared_storage(dstVE->priv, &shared, NULL)))
			return rc;
		if (!shared)
			return 0;
	
		string id;
		rc = getHaClusterNodeID(id);
		if (rc)
			return rc;
		if (id.empty())
			return 0;
	}

	if (m_sHaClusterNodeID.empty()) {
		logger(LOG_INFO, "register HA cluster resource %s", dstVE->ctid());
		rc = runHaman(dstVE->ctid(), "add", dstVE->ve_data.ha_prio, dstVE->priv);
	} else {
		logger(LOG_INFO, "move HA cluster resource %s from node %s",
			dstVE->ctid(), m_sHaClusterNodeID.c_str());
		rc = runHaman(dstVE->ctid(), "move-from", m_sHaClusterNodeID.c_str());
	}
	if (rc)
		return putErr(rc, "Can't register resource %s at HA cluster", dstVE->ctid());

	addCleaner(clean_unregisterOnHaCluster, dstVE, strdup(m_sHaClusterNodeID.c_str()));
	return 0;
}

/*
 * Information about CT disks is missing after initial read of CT config due
 * to some peculiarity of libvzctl. Need to reread disks information later as
 * workaround.
 */
int MigrateStateDstRemote::rereadVeDisksFromConfig()
{
	ve_data veData;

	int rc = ve_data_load(dstVE->ctid(), &veData);
	if (rc)
		return rc;

	dstVE->init_disks(veData);
	return 0;
}

/*
 * Return vector of command line arguments for p.haul-service exec.
 */
std::vector<std::string> MigrateStateDstRemote::getPhaulSrvArgs(
	const PhaulChannels& channels)
{
	std::vector<std::string> args;
	args.push_back(BIN_PHAUL_SRV);

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

	// Specify path to phaul-service log
	args.push_back("--log-file");
	args.push_back(PHAUL_SRV_LOG_FILE);

	return args;
}

pid_t MigrateStateDstRemote::execPhaulSrv(const std::vector<std::string>& args)
{
	ExecveArrayWrapper argsArray(args);
	pid_t pid;

	if (vzm_execve_quiet_nowait(argsArray.getArray(), NULL, -1, &pid) != 0)
		return -1;

	return pid;
}

/******************************
 * Data transfer functionality
 ******************************/

int MigrateStateDstRemote::h_copy_remote_rsync_file(const char * dst)
{
	return remoteRsyncDst(getRsyncArgs(), "--delete", "--server", ".", dst, (void *)NULL);
}

int MigrateStateDstRemote::h_copy_remote_rsync_dir(const char * dst)
{
	string dst_dir = string(dst) + "/";
	return remoteRsyncDst(getRsyncArgs(), "--delete", "--server", ".",
			dst_dir.c_str(), (void *)NULL);
}

int MigrateStateDstRemote::h_copy_remote_rsync(const char * dst)
{
	int rc;
	char *str = NULL;
	if (m_nXxlTimeout) {
		if ((str = strdup(VZMoptions.tmo.str)))
			snprintf(VZMoptions.tmo.str, sizeof(VZMoptions.tmo.str),
				"%ld", m_nXxlTimeout);
	}
	rc = h_copy_remote_rsync_dir(dst);
	if (str) {
		strncpy(VZMoptions.tmo.str, str, sizeof(VZMoptions.tmo.str));
		free((void *)str);
	}
	return rc;
}

int MigrateStateDstRemote::h_copy_remote_rsync_fast(const char * dst, enum mig_method mth)
{
	int rc = 0;
	char tmpdir[PATH_MAX+1];
	const char *dir;

	dir = dst;
	if (isOptSet(OPT_CONVERT_VZFS)) {
		if ((rc = bind_mount(dst, 0, tmpdir, sizeof(tmpdir))))
			return rc;
		dir = tmpdir;
	}

	switch (mth) {
	case METHOD_CHECKSUM:
		rc = remoteRsyncDst(getRsyncArgs(), "--delete", "--server", "-c",
			".", dir, (void *)NULL);
		break;
	case METHOD_TRACKER:
		rc = remoteRsyncDst(getRsyncArgs(), "--delete", "--server", "--ignore-times", "-R",
			".", dir, (void *)NULL);
		break;
	default:
		rc = MIG_ERR_INVALID_ARG;
		break;
	}

	if (isOptSet(OPT_CONVERT_VZFS))
		bind_umount(tmpdir);

	return rc;
}

int MigrateStateDstRemote::h_copy_remote_tar(const char *dst)
{
	int rc = 0;
	char *opt = NULL;
	const char *rdst;
	char tmpdir[PATH_MAX+1];

	if (isOptSet(OPT_CONVERT_VZFS))
	{
		if ((rc = bind_mount(dst, 0, tmpdir, sizeof(tmpdir))))
			return rc;
		rdst = tmpdir;
	}
	else
	{
		rdst = dst;
	}

	char * const args[] =
		{ (char *)BIN_TAR, (char *)"-p",
			(char *)"--same-owner", (char *)"-x", (char *)"-C", (char *) rdst, opt, NULL };

	if (isOptSet(OPT_CONVERT_VZFS)) {
		// ploop image can not be sparse file
		// but on vzfs->ploop convertation we copy files from root to mounted ploop
		// so we can use --sparse option
		opt = (char *)"-S";
	}

	if (isOptSet(OPT_AGENT)) {
		rc = vza_recv_data(&channel.ctx, channel.conn, args);
	} else if (isOptSet(OPT_PS_MODE)) {
		int sock = PSMode::get_socket();
		if (sock < 0) {
			rc = putErr(MIG_ERR_VZSOCK, "data_sock and tmpl_data_sock are closed");
			goto cleanup;
		}
		do_block(sock);
		rc = vzm_execve(args, NULL, sock, sock, NULL);
		PSMode::finish_socket();
	} else if (isOptSet(OPT_SOCKET)) {
		if ((rc = vzsock_recv_data(&channel.ctx, channel.conn, (char * const *)args)))
			rc = putErr(MIG_ERR_VZSOCK, "vzsock_recv_data() return %d", rc);
	} else if (isOptSet(OPT_SSH_FWD)) {
		rc = channel.fwdRecvData(args);
	} else {
		rc = ssh_recv_data(&channel.ctx, channel.conn, args,
				rdst, VZMoptions.tmo.val);
	}

cleanup:
	if (isOptSet(OPT_CONVERT_VZFS))
		bind_umount(tmpdir);

	return rc;
}

/*
  Handle initial migration of image of ploop-based CT
*/
int MigrateStateDstRemote::cmdCopyPloopImageOnline1(size_t blksize, const std::string &fname)
{
	int rc = 0;
	int fds[2];
	size_t size;
	int ret;
	char image[PATH_MAX + 1];

	assert(channel.isConnected());

	size = sizeof(fds);
	if ((ret = vzsock_get_conn(&channel.ctx, channel.conn,
			VZSOCK_DATA_FDPAIR, fds, &size)))
	{
		rc = putErr(MIG_ERR_VZSOCK,
			"vzsock_get_conn() return %d\n", ret);
		return rc;
	}

	if (fname.empty()) {
		/* compatibility */
		rc = vzctl2_get_top_image_fname((char *)dstVE->priv, image, sizeof(image));
		if (rc)
			return rc;
	} else
		get_full_path(dstVE->priv, fname.c_str(), image, sizeof(image));

	// send readiness reply
	if ((rc = channel.sendPkt("|0|")))
		return rc;

	rc = ploop_dst_online_copy_image_1(image, fds[0], VZMoptions.tmo.val, blksize);
	if (rc)
		return putErr(MIG_ERR_PLOOP,
			"Online copy of ploop image failed on stage 1, retcode %d", rc);
	return 0;
}

/*
  Handle migration of dirty blocks of image of ploop-based CT after suspending
*/
int MigrateStateDstRemote::cmdCopyPloopImageOnline2(istringstream &is)
{
	int rc = 0;
	size_t blksize;
	std::string image;

	// send readiness reply
	if ((rc = channel.sendPkt("|0|")))
		return rc;

	if ((is >> blksize) == NULL)
		/* use data from stage1 */
		blksize = 0;
	else {
		char fname[PATH_MAX];
		is >> image;
		image = get_full_path(dstVE->priv, image.c_str(), fname, sizeof(fname));
	}

	rc = ploop_dst_online_copy_image_2(image.empty() ? NULL : image.c_str(), blksize);
	if (rc)
		return putErr(MIG_ERR_PLOOP,
			"Online copy of ploop image failed on stage 2, retcode %d", rc);
	return 0;
}

int MigrateStateDstRemote::cmdCheckPloopFormat(istringstream &is)
{
	int fmt;

	if ((is >> fmt) == NULL)
		return putErr(MIG_ERR_PROTOCOL, MIG_MSG_PROTOCOL);

	if ((fmt == 2) &&  !ploop_is_large_disk_supported())
		return putErr(MIG_ERR_PLOOP_FORMAT, MIG_MSG_PLOOP_FORMAT, fmt);

	return 0;
}

/*
 * Prepare data structures needed for phaul connections multiplexing on
 * destination side.
 *
 * Command CMD_PREPARE_PHAUL_CONN has following format:
 * %count%\n[%delta_path1%\n[%delta_path2%\n[...]]] (count of active ploop
 * deltas and list of deltas paths separated by '\n').
 */
int MigrateStateDstRemote::cmdPreparePhaulConn(istringstream &is)
{
	// Read active deltas count
	std::string bufStr;
	if (!std::getline(is, bufStr))
		return putErr(MIG_ERR_PROTOCOL, MIG_MSG_PROTOCOL);

	std::istringstream bufIs(bufStr);
	int deltasCount;
	if (!(bufIs >> deltasCount))
		return putErr(MIG_ERR_PROTOCOL, MIG_MSG_PROTOCOL);

	// Read active deltas paths
	std::vector<std::string> activeDeltas;
	for (int i = 0; i < deltasCount; ++i) {
		std::string delta;
		if (!std::getline(is, delta)) {
			return putErr(MIG_ERR_PROTOCOL, MIG_MSG_PROTOCOL);
		}
		activeDeltas.push_back(delta);
	}

	// Check that channels not already created
	if (m_phaulChannels.get() != NULL)
		return putErr(-1, MIG_MSG_PREP_DST_PHAUL_CONN);

	// Create and initialize phaul channels
	std::auto_ptr<PhaulChannels> channels(new PhaulChannels(activeDeltas));
	if (channels->init() != 0)
		return putErr(-1, MIG_MSG_PREP_DST_PHAUL_CONN);

	// Transfer channels ownership from local object to class object
	m_phaulChannels = channels;
	return 0;
}

/*
 * Exec p.haul-service and handle connections multiplexing.
 */
int MigrateStateDstRemote::cmdRunPhaulMigration()
{
	assert(m_phaulChannels.get() != NULL);

	// Mute logger output to protect master connection of io multiplexer
	quiet_log(1);

	// Transfer channels ownership from class object to local object
	std::auto_ptr<PhaulChannels> channels = m_phaulChannels;

	// Exec phaul-service
	std::vector<std::string> phaulArgs = getPhaulSrvArgs(*channels);
	pid_t phaulServicePid = execPhaulSrv(phaulArgs);

	// Close phaul-service channels ends
	channels->closePhaulChannelFds();

	// Backward compatibility for migration with compression on pre-7.0.9 hosts
	// In agent mode we get incorrect remote version on start. Proper one
	// is sent later, hence we check version right before the channel is created.
	if (VZMoptions.remote_version < MIGRATE_VERSION_709 && !isOptSet(OPT_NOCOMPRESS))
	{
		logger(LOG_INFO, "Remote version %d. Disabling ZSTD compression.", VZMoptions.remote_version);
		setOpt(OPT_NOCOMPRESS);
	}

	// Create io multiplexer
	multiplexer::IoMultiplexer ioMultiplexer(channel,
		channels->getVzmigrateChannelFds(), phaulServicePid, false, !isOptSet(OPT_NOCOMPRESS));

	int rc;
	if (phaulServicePid != -1) {

		// Run phaul-service io multiplexing
		rc = ioMultiplexer.runMultiplexing();
		if (!ioMultiplexer.isChildTerminated()) {
			addCleaner(clean_termPhaulSrv, (new pid_t(phaulServicePid)), NULL,
				ANY_CLEANER);
		}

	} else {

		// Run io multiplexing abort if failed to start phaul-service
		ioMultiplexer.runMultiplexingAbort();
		rc = -1;
	}

	// Unmute logger output
	quiet_log(0);

	if (phaulServicePid == -1)
		logger(LOG_ERR, MIG_MSG_EXEC_PHAUL_SERVICE, BIN_PHAUL_SRV);

	if (rc != 0)
		return putErr(MIG_ERR_PHAUL, MIG_MSG_RUN_PHAUL_SERVICE);

	return 0;
}

int MigrateStateDstRemote::clean_umountImage(const void *arg, const void *)
{
	VEObj * ve = (VEObj *) arg;
	assert(ve);

	logger(LOG_DEBUG, "Umount image");
	ve->umount();
	return 0;
};

int isJquotaSupported(const char *ostemplate, bool &supported)
{
	FILE *fd;
	char buf[4096];
	char *p;
	int status;

	snprintf(buf, sizeof(buf), BIN_VZPKG " info %s -q jquota 2>/dev/null",
		ostemplate);
	logger(LOG_DEBUG, buf);
	if ((fd = popen(buf, "r")) == NULL)
		return putErr(MIG_ERR_SYSTEM, "popen('%s') error: %m", buf);

	*buf = 0;
	while((p = fgets(buf, sizeof(buf), fd)));

	status = pclose(fd);
	if ((WIFEXITED(status) && WEXITSTATUS(status)) || WIFSIGNALED(status))
		return MIG_ERR_SYSTEM;

	logger(LOG_DEBUG, "jquota=%s", buf);

	supported = (strncmp(buf, "yes", 3) == 0);

	return 0;
} 

static int fix_conf(VEObj *ve,  unsigned long size)
{
	char buf[10+1+10+1]; // Unsigned long + : delim + \0
	struct vzctl_config *cfg = NULL;
	int err, rc;
	bool jquota;

	cfg = vzctl2_conf_open(ve->confPath().c_str(), VZCTL_CONF_SKIP_GLOBAL, &err);
	if (err)
		return putErr(MIG_ERR_VZCTL, "vzctl2_conf_open(%s) error: %s",
			ve->confPath().c_str(), vzctl2_get_last_error());

	/* Update DISKSPACE in config */
	snprintf(buf, sizeof(buf), "%lu:%lu", size, size);
	if ((rc = vzctl2_conf_set_param(cfg, VE_CONF_DISKSPACE, buf)))
	{
		rc = putErr(MIG_ERR_VZCTL, "vzctl2_conf_set_param(%s) error: %s",
			VE_CONF_DISKSPACE, vzctl2_get_last_error());
		goto cleanup;
	}

	/* All std ez-templates doesn't support jquota */
	if (! ve->isNewTemOS() || \
		(isJquotaSupported(ve->ve_data.ostemplate, jquota) == 0 && !jquota))
	{
		if ((rc = vzctl2_conf_set_param(cfg, VE_CONF_JOURNALED_QUOTA, "no"))) {
			rc = putErr(MIG_ERR_VZCTL, "vzctl2_conf_set_param(%s) error: %s",
					VE_CONF_JOURNALED_QUOTA, vzctl2_get_last_error());
			goto cleanup;
		}
	}

	/* Std template with conversion */
	if (! ve->isNewTemOS())
	{
		/* Clean OSTEMPLATE */
		if ((rc = vzctl2_conf_set_param(cfg, VE_CONF_OSTEMPLATE, ""))) {
			rc = putErr(MIG_ERR_VZCTL, "vzctl2_conf_set_param(%s) error: %s",
					VE_CONF_OSTEMPLATE, vzctl2_get_last_error());
			goto cleanup;
		}

		/* Clean VEFORMAT */
		if ((rc = vzctl2_conf_set_param(cfg, VE_CONF_VEFORMAT, 0))) {
			rc = putErr(MIG_ERR_VZCTL, "vzctl2_conf_set_param(%s) error: %s",
					VE_CONF_VEFORMAT, vzctl2_get_last_error());
			goto cleanup;
		}
	}

	if ((rc = vzctl2_conf_save(cfg, ve->confPath().c_str())))
		rc = putErr(MIG_ERR_VZCTL, "vzctl2_conf_save() error: %s",
			vzctl2_get_last_error());

cleanup:
	vzctl2_conf_close(cfg);

	return rc;
}

/* mount ploop for migration with convert vzfs4 to ext4 */
int MigrateStateDstRemote::cmdMountPloop(unsigned long ploop_size,
		unsigned long create_size, int lmounted)
{
	int rc;
	struct vzctl_create_image_param param;

	dstVE->layout = VZCTL_LAYOUT_5;

	bzero(&param, sizeof(param));
	param.mode = PLOOP_EXPANDED_MODE;
	param.size = create_size ? : ploop_size;
	if (vzctl2_create_image(dstVE->priv, &param))
		return putErr(MIG_ERR_VZCTL, "vzctl2_create_image(%s) error: %s",
				dstVE->priv, vzctl2_get_last_error());

	if ((ploop_size < create_size) && vzctl2_resize_image(dstVE->priv, ploop_size, 0))
		return putErr(MIG_ERR_VZCTL, "vzctl2_resize_image(%s) error: %s",
				dstVE->priv, vzctl2_get_last_error());

	rc = dstVE->createLayout();
	if (rc)
		return rc;

	rc = fix_conf(dstVE, ploop_size);
	if (rc)
		return rc;

	rc = dstVE->mount();
	if (rc)
		return rc;
	addCleaner(clean_umountImage, dstVE, NULL, lmounted ? SUCCESS_CLEANER : ERROR_CLEANER);

	return pfcache_set(dstVE->root, 1);
}

int MigrateStateDstRemote::cmdCopyExternalDisk(istringstream &is)
{
	std::string path;

	is >> path;

	logger(LOG_DEBUG, "cmdCopyExternalDisk '%s'", path.c_str());
	addCleanerRemove(clean_removeDir, path.c_str());

	/* absolute path is used */
	return h_copy_remote_tar("/");
}

// vzfs -> ploop conversion
int MigrateStateDstRemote::cmdCopyVzPackages()
{
	char path[PATH_MAX+1];
	snprintf(path, sizeof(path), "%s/templates", dstVE->priv);
	return h_copy_remote_tar(path);
}

// vzfs -> ploop conversion
int MigrateStateDstRemote::copySetNativeQuota(istringstream &is)
{
	string fname;
	char tmpdir[PATH_MAX];
	int rc;

	if ((is >> fname) == NULL)
		return putErr(MIG_ERR_PROTOCOL, MIG_MSG_PROTOCOL);

	// load and apply 2-level quota limits
	if (get_tmp_dir(tmpdir, sizeof(tmpdir)))
		strncpy(tmpdir, "/tmp", sizeof(tmpdir)-1);
	snprintf(m_convertQuota2, sizeof(m_convertQuota2), "%s/%s", tmpdir, fname.c_str());

	rc = h_copy_remote_tar(tmpdir);
	if (rc == 0)
		addCleanerRemove(clean_removeFile, m_convertQuota2);
	return rc;
}
