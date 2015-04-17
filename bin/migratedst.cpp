/* $Id$
 *
 * Copyright (c) SWsoft, 2006-2007
 *
 */
#include <sys/wait.h>
#include <sys/vfs.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <fcntl.h>

#include <vzctl/libvzctl.h>
#include <ploop/libploop.h>

#include "util.h"
#include "migratedst.h"
#include "migssh.h"
#include "common.h"
#include "veentry.h"
#include "vzacompat.h"
#include "channel.h"

extern struct vz_data *vzcnf;
extern void *istorage_ctx;

MigrateStateDstRemote::MigrateStateDstRemote(VEObj * ve, int options)
		: MigrateStateCommon(), dstVE(ve), m_initOptions(options)
{
	assert(dstVE != NULL);

	addCleaner(clean_delEntry, dstVE, NULL, ANY_CLEANER);

	func_copyFirst = &MigrateStateDstRemote::h_copy_remote_tar;
	func_copyFile = &MigrateStateDstRemote::h_copy_remote_rsync_file;

	is_thesame_private = 0;
	is_privdir_exist = 0;
	is_priv_on_shared = 0;
	m_nVziterindPid = -1;
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
	logger(LOG_DEBUG, MIG_MSG_RST "destroy CT#%d", ve->veid());
	ve->destroy();
	return 0;
};

int MigrateStateDstRemote::clean_unregister(const void * arg, const void *)
{
	VEObj * ve = (VEObj *) arg;
	assert(ve);
	logger(LOG_DEBUG, MIG_MSG_RST "unregister CT#%d", ve->veid());
	ve->unregister();
	return 0;
};

int MigrateStateDstRemote::clean_restoreKill(const void * arg, const void *)
{
	VEObj * ve = (VEObj *) arg;
	assert(ve);
	logger(LOG_DEBUG, MIG_MSG_RST "restore kill CT#%d", ve->veid());
	ve->kill_restore();
	return 0;
};

int MigrateStateDstRemote::clean_umount(const void * arg, const void *)
{
	VEObj * ve = (VEObj *) arg;
	assert(ve);
	logger(LOG_DEBUG, MIG_MSG_RST "umount CT#%d", ve->veid());
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
		logger(LOG_DEBUG, "unregister HA cluster resource %u", ve->veid());
		runHaman(ve->veid(), "del");
	} else {
		logger(LOG_DEBUG, "move HA cluster resource %u to node %s", ve->veid(), sHaClusterNodeID);
		runHaman(ve->veid(), "move-to", sHaClusterNodeID);
	}
	free(sHaClusterNodeID);
	return 0;
};

/* check ip addresses list from in for running and offline_man VE */
int check_ipaddr(char *in)
{
	char *str, *addr;
	char out[BUFSIZ+1];

	if (in == NULL)
		return 0;

	out[0] = '\0';
	for (str = in; ;str = NULL) {
		if ((addr = strtok(str, "  ")) == NULL)
			break;
		if (vzctl2_get_envid_by_ip(addr) == -1) {
			if (errno == EADDRNOTAVAIL) {
				/* no such ip */
				continue;
			} else {
				return putErr(MIG_ERR_SYSTEM,
					"vzctl2_get_envid_by_ip(%s) error: %s",
					addr, vzctl2_get_last_error());
			}
		} else {
			/* address is in pool (VE is running or in offline_man) */
			strncat(out, " ", sizeof(out)-strlen(out)-1);
			strncat(out, addr, sizeof(out)-strlen(out)-1);
		}
	}
	if (strlen(out))
		return putErr(MIG_ERR_IP_IN_USE, out);
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

	ve->clean();
	ve->setLayout(option_to_vzlayout(m_initOptions));
	ve->veformat = option_to_veformat(m_initOptions);

	logger(LOG_INFO, "Start of CT %d migration (private %s, root %s, opt=%d)",
			ve->veid(), ve->priv, ve->root, m_initOptions);

	if (!isOptSet(OPT_AGENT) && isOptSet(OPT_ONLINE) &&
				(VZMoptions.remote_version < MIGRATE_VERSION_400))
		return putErr(MIG_ERR_ONLINE_ELDER, MIG_MSG_ONLINE_ELDER);

	if (!isOptSet(OPT_AGENT) &&
		VZMoptions.remote_version < MIGRATE_VERSION_400)
		/* vzmigrate-3.0 use only rsync for private area coping
		   (https://jira.sw.ru/browse/PSBM-9143) */
		func_copyFirst = &MigrateStateDstRemote::h_copy_remote_rsync;

	if (m_initOptions & MIGINIT_CONVERT_VZFS) {
		logger(LOG_DEBUG, "The file system of a Container will be converted to ext4.");
		setOpt(OPT_CONVERT_VZFS);
	}

	if ((rc = checkDstIDFree(*ve)))
		return rc;

	if ((rc = checkCommonDst(*ve)))
		return rc;

	if ((rc = is_path_on_shared_storage(ve->priv, &is_priv_on_shared, NULL)))
		return rc;

	if (!isOptSet(OPT_AGENT) &&
		(VZMoptions.remote_version < MIGRATE_VERSION_400)) {
		if (is_priv_on_shared) {
			/* shoo old layout from our ... private area */
			return putErr(MIG_ERR_SYSTEM, "Can't migrate this private area "
				"on shared FS (old layout)\n"
				"You can use the 'vzctl convert' "
				"command to convert the Container to the new layout.\n");
		}
	}

	/* check target private existance */
	if (access(ve->priv, F_OK) == 0) {
		int layout = vzctl2_env_layout_version(ve->priv);

		if (layout > 0 && layout != ve->layout)
			return putErr(MIG_ERR_SYSTEM, "Can't migrate: there is private area "
					"%s with different layout %d on destionation",
					ve->priv, layout);

		is_privdir_exist = 1;
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

	/* and lock VE only after private creation
	   (vzctl will create lock file in private, #119945) */
	/* postpone lock for 'private on nfs' case until
	   'the same private' check (MigrateStateDstRemote::cmdCheckSharedPriv)
	   If it's the same private, it's already locked by source side (#476968) */
	/* do not lock for gfs/gfs2 too (https://jira.sw.ru/browse/PCLIN-29890) */
	if (!is_priv_on_shared) {
		if ((rc = ve->lock()))
			return rc;
	}

	// do not use --sparse option for ploop image copy
	use_sparse_opt = (ve->layout < VZCTL_LAYOUT_5);

	END_STAGE();
	return 0;
}

int MigrateStateDstRemote::initMigration()
{
	return initVEMigration(dstVE);
}

/* check vzlicense ve_total parameter on destination node */
int MigrateStateDstRemote::cmdCheckLicense()
{
	char cmd[MAX_CMD_SIZE+1];
	char buf[BUFSIZ];
	FILE *fd;
	int status;
	char *p;
	char *token = (char *)"ct_total=";
	char *out = NULL;
	char *binary = (char *)"vzlicview";
	int retcode;

	snprintf(cmd, sizeof(cmd), "%s --active --class VZSRV", binary);
	logger(LOG_DEBUG, cmd);
	if ((fd = popen(cmd, "r")) == NULL)
		return putErr(MIG_ERR_LICENSE, "popen('%s') : %m", cmd);

	while(fgets(buf, sizeof(buf), fd)) {
		if ((p = strchr(buf, '\n')))
			*p = '\0';
		for (p = buf; isblank(*p); p++) ;
		if (strncmp(p, token, strlen(token)) == 0) {
			out = p + strlen(token);
			break;
		}
	}
	status = pclose(fd);
	if (WIFEXITED(status)) {
		retcode = WEXITSTATUS(status);
		if (retcode) {
			return putErr(MIG_ERR_LICENSE,
				"%s exit with retcode %d", binary, retcode);
		}
	} else if (WIFSIGNALED(status)) {
		return putErr(MIG_ERR_LICENSE,
			"%s got signal %d", binary, WTERMSIG(status));
	} else {
		return putErr(MIG_ERR_LICENSE,
			"%s exited with status %d", binary, status);
	}
	if (out == NULL)
		return putErr(MIG_ERR_LICENSE,
			"Can't get ct_total from active license");

	char *unlimited = (char *)"\"unlimited\"";
	if (strncasecmp(out, unlimited, strlen(unlimited)) == 0) {
		logger(LOG_DEBUG, "checkLicense: unlimited");
		return 0;
	}

	unsigned long limit, used;
	retcode = sscanf(out, "%lu (%lu)", &limit, &used);
	if (retcode != 2)
		return putErr(MIG_ERR_LICENSE,
			"Can't get ct_total limit and current value from active license : '%s'",
			buf);

	logger(LOG_DEBUG, "checkLicense: limit=%lu use=%lu", limit, used);
	if (used >= limit)
		return putErr(MIG_ERR_LICENSE,
			"The destination node license does not "
			"allow to increase the number of Containers: "
			"limit=%lu, use=%lu", limit, used);
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

	if ((rc = gfs_cluster_getid(mpoint, dst_id, sizeof(dst_id))))
		return rc;

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
			addCleaner(clean_unregister, dstVE);

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
#if 0
	/* try to get shared partition list and find mount point
	   with cluster id == source cluster id */
	/* get shared partition list */
	if ((shared = vzctl_get_storage()) == NULL) {
		/* error */
		os << "0";
		return 0;
	}
	found = 0;
	for (i = 0; shared[i]; i++) {
		if ((rc = gfs_cluster_getid(shared[i], dst_id, sizeof(dst_id))))
			continue;

		if (strcmp(src_id.c_str(), dst_id))
			continue;
		/* yes, it is the same cluster */

		/* check this private */
		snprintf(path, sizeof(path), "%s/%s", shared[i], mpath.c_str());
		if (stat(path, &st))
			continue;
		if (!S_ISDIR(st.st_mode))
			continue;
		found = 1;
		break;
	}
	for (i = 0; shared[i]; i++)
		free((void *)shared[i]);
	free((void *)shared);
	if (found) {
		/* yes, shared part with src cluster id was found, but it is not
		   equal to target private. Will change target private */
		if ((rc = dstVE->setPrivate(path)))
			return rc;
		is_thesame_private = 1;
		logger(LOG_DEBUG, MIG_MSG_THESAME_CLUSTER,
				"CT privates", src_id.c_str());
		/* and copy source VE config from original private */
		if ((rc = copy_file(dstVE->confPath().c_str(),
				dstVE->confRealPath().c_str())))
			return putErr(MIG_ERR_COPY, MIG_MSG_COPY_FILE,
				dstVE->confRealPath().c_str(),
				dstVE->confPath().c_str(),
				getError());
		addCleaner(clean_unregister, dstVE);

		if ((rc = dstVE->prepareConfig()))
			return rc;
		if ((rc = dstVE->loadConfig()))
			return rc;
		os << "1";
	} else

#endif
		os << "0";

	return 0;
}

/* For dumpdir */
int MigrateStateDstRemote::cmdCheckClusterDump(
			istringstream &is,
			ostringstream & os)
{
	int rc;
	string src_id, mpath;
	int is_thesame_path;

	if ((is >> src_id >> mpath) == NULL)
		return putErr(MIG_ERR_PROTOCOL, MIG_MSG_PROTOCOL);

	if ((rc = check_cluster_id(dstVE->dumpDir().c_str(),
			src_id.c_str(), mpath.c_str(), NULL, &is_thesame_path)))
		return rc;

	if (is_thesame_path) {
		logger(LOG_DEBUG, MIG_MSG_THESAME_CLUSTER,
				"dumpdirs", src_id.c_str());
		os << "1";
	}
	else
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
	string name;
	char path[PATH_MAX+1];
	struct stat st;

	if (!is_priv_on_shared)
		return 0;

	if ((is >> name) == NULL)
		return putErr(MIG_ERR_PROTOCOL, MIG_MSG_PROTOCOL);

	snprintf(path, sizeof(path), "%s/%s", dstVE->priv, name.c_str());
	if (stat(path, &st)) {
		os << "0";
		return 0;
	}
	m_nFlags |= VZMSRC_SHARED_PRIV;
	logger(LOG_DEBUG, MIG_MSG_THESAME_SHARED, "CT privates");

	/* and copy source VE config from original private */
	if ((rc = copy_file(dstVE->confPath().c_str(),
			dstVE->confRealPath().c_str())))
		return putErr(MIG_ERR_COPY, MIG_MSG_COPY_FILE,
			dstVE->confRealPath().c_str(),
			dstVE->confPath().c_str(),
			getError());

	/* update & load config here, so confset command will not send
	   by source side for shared private case
	   https://jira.sw.ru/browse/PCLIN-29435 */
	if ((rc = dstVE->prepareConfig()))
		return rc;
	if ((rc = dstVE->loadConfig()))
		return rc;

	addCleaner(clean_unregister, dstVE);
	os << "1";

	return 0;
}

/* the same for shared dumpdir */
int MigrateStateDstRemote::cmdCheckSharedDump(
			istringstream &is,
			ostringstream & os)
{
	string name;
	char path[PATH_MAX+1];
	struct stat st;

	if ((is >> name) == NULL)
		return putErr(MIG_ERR_PROTOCOL, MIG_MSG_PROTOCOL);

	snprintf(path, sizeof(path), "%s/%s",
		dstVE->dumpDir().c_str(), name.c_str());
	if (stat(path, &st) == 0) {
		logger(LOG_DEBUG, MIG_MSG_THESAME_SHARED, "dumpdirs");
		os << "1";
	} else {
		os << "0";
	}
	return 0;
}

/* source and target nodes dumpdirs are onn the same cluster:
   do not copy via ssh dumpfile - get from dumpdir */
int MigrateStateDstRemote::cmdClusterDumpCopy(
			istringstream &is)
{
	string dumpfile, fname;

	if ((is >> fname) == NULL)
		return putErr(MIG_ERR_PROTOCOL, MIG_MSG_PROTOCOL);

	dumpfile = dstVE->dumpDir() + "/" + fname;
	if (access(dumpfile.c_str(), R_OK))
		return putErr(MIG_ERR_PROTOCOL, MIG_MSG_PROTOCOL);

	if ((dstVE->dumpfile = strdup(dumpfile.c_str())) == NULL)
		return putErr(MIG_ERR_SYSTEM, MIG_MSG_SYSTEM);

	logger(LOG_DEBUG, "Use %s dumpfile from cluster",
			dstVE->dumpfile);
	addCleanerRemove(clean_removeFile, dstVE->dumpfile, ANY_CLEANER);

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

/* test CPT image version */
int MigrateStateDstRemote::cmdCheckCPTVersion(istringstream & is)
{
	string version;
	if ((is >> version) == NULL)
		return putErr(MIG_ERR_PROTOCOL, MIG_MSG_PROTOCOL);

	char * const args[] = {(char *)BIN_VZTESTVER, (char *)version.c_str(), NULL };
	int rc, retcode;

	rc = vzm_execve(args, NULL, -1, -1, &retcode);
	if (rc == MIG_ERR_TASK_FAILED) {
		if (retcode == 1) {
			return putErr(MIG_ERR_INCOMPAT_CPT_VER, MIG_MSG_INCOMPAT_CPT_VER);
		} else {
			return putErr(MIG_ERR_SYSTEM, MIG_MSG_CHECK_CPT_VER);
		}
	} else if (rc) {
		return putErr(MIG_ERR_SYSTEM, MIG_MSG_CHECK_CPT_VER);
	}
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
	int rc = 0;
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
	// above are for vzfs -> ploop conversion
	case DUMPCOPY:
		if ((rc = dstVE->createDumpFile()))
			return rc;
		addCleanerRemove(clean_removeFile, dstVE->dumpfile, SUCCESS_CLEANER);
		return (this->*func_copyFile)(dstVE->dumpfile);
	case SUSPENDCOPY:
		if (dstVE->suspendPath().empty())
			return putErr(MIG_ERR_SYSTEM, "can't get path for suspend file");
		addCleanerRemove(clean_removeFile, dstVE->suspendPath().c_str());
		return (this->*func_copyFile)(dstVE->suspendPath().c_str());
	}
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

/* final VE operation before start/mounting */
int MigrateStateDstRemote::finalVEtuning()
{
	int rc = 0;

	if (m_convertQuota2[0] != '\0') {
		if ((rc = applyPloopQuotaImpl(m_convertQuota2)))
			return rc;
	}

	logger(LOG_INFO, "End of CT %d migration", dstVE->veid());
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
		return rc;

	if (action == DSTACT_START_VE)
		rc = dstVE->start();
	else if (action == DSTACT_MOUNT_VE)
		rc = dstVE->mount();
	if (rc)
		return rc;

	/* vzctl register for new layout VE */
	if ((rc = dstVE->veRegister()))
		goto cleanup;
	addCleaner(clean_unregister, dstVE);

	/* set ve name */
	if ((rc = dstVE->setName(dst_name)))
		goto cleanup;

	if ((rc = finalVEtuning()))
		goto cleanup;

	return 0;

cleanup:
	if (action == DSTACT_START_VE)
		dstVE->stop();
	else if (action == DSTACT_MOUNT_VE)
		dstVE->umount();
	return rc;
}

int MigrateStateDstRemote::undump(void)
{
	int rc;

	if (	(isOptSet(OPT_PS_MODE) || isOptSet(OPT_AGENT)) &&
		!isOptSet(OPT_NOCONTEXT) && (m_nVziterindPid != -1))
	{
		// If iterative migration failed (context does not exist) but
		// vziterind already running, for agent and ps modes
		// will terminate vziterind directly
		// (https://jira.sw.ru/browse/PSBM-18868)
		// And it's looks as OPT_NOCONTEXT options is upend
		kill(m_nVziterindPid, SIGTERM);
		for (int i = 0; i < 3; i++) {
			pid_t pid = waitpid(m_nVziterindPid, NULL, WNOHANG);
			if (pid < 0) {
				logger(LOG_ERR, "waitpid() return %d : %m", pid);
				break;
			} else if (pid == m_nVziterindPid) {
				break;
			}
			sleep(1);
		}
	}
	if ((rc = dstVE->undump(isOptSet(OPT_NOCONTEXT))) != 0)
		return rc;

	/* will register resource on HA cluster just before
	   register CT on node : better to have a broken resource than
	   losing a valid */
	if ((rc = registerOnHaCluster()))
		goto err;

	/* vzctl register for new layout VE */
	if ((rc = dstVE->veRegister()))
		goto err;
	addCleaner(clean_unregister, dstVE);

	/* set ve name */
	if ((rc = dstVE->setName(dst_name)))
		goto err;
err:
	addCleaner(clean_umount, dstVE);
	addCleaner(clean_restoreKill, dstVE);

	return rc;
}

int MigrateStateDstRemote::resume(void)
{
	int rc;

	if ((rc = dstVE->resume_restore(isOptSet(OPT_NOCONTEXT))) != 0)
		return rc;

	if ((rc = finalVEtuning()))
		return rc;

	return 0;
}

int MigrateStateDstRemote::resume_non_fatal(void)
{
	return dstVE->resume_restore(isOptSet(OPT_NOCONTEXT));
}

int MigrateStateDstRemote::createSwapChannel(string veid_str)
{
	char *argv[] = { (char *)BIN_VZITERIND, (char *)veid_str.c_str(), NULL };

	if (isOptSet(OPT_AGENT)) {
		return vza_start_swap_srv(&channel.ctx, channel.conn, argv, &m_nVziterindPid);
	} else if (isOptSet(OPT_PS_MODE)) {
		pid_t pid, chpid;
		int status;

		/* ignore veid_str from source: source known nothing about
		   --new_id option on dst side (https://jira.sw.ru/browse/PSBM-9045) */
		char str[100];
		snprintf(str, sizeof(str)-1, "%u", dstVE->veid());
		argv[1] = str;
		logger(LOG_DEBUG, "%s %s", argv[0], argv[1]);

		do_block(VZMoptions.swap_sock);
		if ((chpid = fork()) < 0) {
			return putErr(MIG_ERR_SYSTEM, "fork() : %m");
		} else if (chpid == 0) {
			for (int fd = 0; fd < 1024; fd++) {
				if (fd != VZMoptions.swap_sock)
					close(fd);
			}
			dup2(VZMoptions.swap_sock, STDIN_FILENO);
			dup2(VZMoptions.swap_sock, STDOUT_FILENO);
			dup2(VZMoptions.swap_sock, STDERR_FILENO);
			close(VZMoptions.swap_sock);
			execvp(argv[0], argv);
			exit(-1);
		}
		/* One socket is on the Dispatcher side, the other - is passed to
		 * vziterind, we don't need it anymore (see #PSBM-20615). */
		close(VZMoptions.swap_sock);

		while ((pid = waitpid(chpid, &status, WNOHANG)) == -1)
			if (errno != EINTR)
				break;

		if (pid < 0)
			return putErr(MIG_ERR_SYSTEM, "fork() : %m");
		if (pid == chpid) {
			check_exit_status(argv[0], status);
			return putErr(MIG_ERR_SYSTEM, MIG_MSG_PAGEIN_EXEC);
		}
		m_nVziterindPid = chpid;
	} else if (isOptSet(OPT_SSH_FWD)) {
		return channel.fwdStartSwapSrv(argv);
	} else {
		return ssh_start_swap_srv(&channel.ctx, argv);
	}
	return 0;
}

int MigrateStateDstRemote::registerOnHaCluster()
{
	int rc;

	if (!is_priv_on_shared || !dstVE->ve_data.ha_enable)
		return 0;

	if (m_sHaClusterNodeID.empty()) {
		logger(LOG_DEBUG, "register HA cluster resource %u", dstVE->veid());
		rc = runHaman(dstVE->veid(), "add", dstVE->ve_data.ha_prio, dstVE->priv);
	} else {
		logger(LOG_DEBUG, "move HA cluster resource %u from node %s",
					dstVE->veid(), m_sHaClusterNodeID.c_str());
		rc = runHaman(dstVE->veid(), "move-from", m_sHaClusterNodeID.c_str());
	}
	if (rc)
		return putErr(rc, "Can't register resource %u at HA cluster", dstVE->veid());

	addCleaner(clean_unregisterOnHaCluster, dstVE, strdup(m_sHaClusterNodeID.c_str()));
	return 0;
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
	return h_copy_remote_rsync_dir(dst);
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

	if ((dstVE->layout < VZCTL_LAYOUT_5) || isOptSet(OPT_CONVERT_VZFS)) {
		// ploop image can not be sparse file
		// but on vzfs->ploop convertation we copy files from root to mounted ploop
		// so we can use --sparse option
		opt = (char *)"-S";
	}

	if (isOptSet(OPT_AGENT)) {
		rc = vza_recv_data(&channel.ctx, channel.conn, args);
	} else if (isOptSet(OPT_PS_MODE)) {
		int *sock;
		if (VZMoptions.data_sock == -1) {
			if (VZMoptions.tmpl_data_sock == -1) {
				rc = putErr(MIG_ERR_VZSOCK, "data_sock and tmpl_data_sock are closed");
				goto cleanup;
			} else {
				sock = &VZMoptions.tmpl_data_sock;
			}
		} else {
			sock = &VZMoptions.data_sock;
		}
		do_block(*sock);
		rc = vzm_execve(args, NULL, *sock, *sock, NULL);
		close(*sock);
		*sock = -1;
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

int MigrateStateDstRemote::clean_umountImage(const void *arg, const void *)
{
	VEObj * ve = (VEObj *) arg;
	assert(ve);

	logger(LOG_DEBUG, "Umount image");
	ve->umount();
	return 0;
};

int MigrateStateDstRemote::cmdCreatePloopSnapshot(istringstream &is, bool rollback)
{
	int rc;
	char path[PATH_MAX+1];
	string guid;

	is >> guid;

	GET_DISKDESCRIPTOR_XML(dstVE->priv, path)
	if (!guid.empty()) {
		char fname[PATH_MAX];
		std::string image;

		is >> image;
		if (!image.empty())
			snprintf(path, sizeof(path), "%s",
				get_dd_xml(get_full_path(dstVE->priv, image.c_str(), fname, sizeof(fname))).c_str()
				);

		logger(LOG_DEBUG, "create snapshot '%s' '%s'",
				guid.c_str(), path);
		rc = MigrateStateCommon::ploopCreateSnapshot(path, guid.c_str());
	} else {
		logger(LOG_DEBUG, "create tsnapshot '%s'", guid.c_str());

		guid = dstVE->gen_snap_guid();

		rc = MigrateStateCommon::ploopCreateTSnapshot(path, guid.c_str());
	}
	if (rc)
		return rc;

	if (rollback)
		addCleanerRemove(clean_deletePloopSnapshot, path,
				guid.c_str());
	return 0;
}

int MigrateStateDstRemote::cmdCreatePloopSnapshotNoRollback(istringstream &is)
{
	return cmdCreatePloopSnapshot(is, false);
}

int MigrateStateDstRemote::cmdDeletePloopSnapshot(istringstream &is)
{
	char path[PATH_MAX+1];
	string guid;

	is >> guid;

	GET_DISKDESCRIPTOR_XML(dstVE->priv, path)
	if (guid.empty()) {
		logger(LOG_DEBUG, "merge top delta '%s'", guid.c_str());
		return MigrateStateCommon::ploopMergeTopDelta(path);
	} else {
		char fname[PATH_MAX];
		std::string image;

		is >> image;
		if (!image.empty())
			snprintf(path, sizeof(path), "%s",
				get_dd_xml(get_full_path(dstVE->priv, image.c_str(), fname, sizeof(fname))).c_str()
				);

		logger(LOG_DEBUG, "delete snapshot '%s' '%s'",
				guid.c_str(), path);

		return MigrateStateCommon::ploopDeleteSnapshot(path,
				guid.c_str());
	}
}

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
        if ((WIFEXITED(status) && WEXITSTATUS(status)) ||
                        WIFSIGNALED(status))
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
