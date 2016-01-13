/* $Id$
 *
 * Copyright (c) SWsoft, 2006-2007
 *
 */
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mount.h>

#include "migratesrc.h"
#include "migssh.h"
#include "bincom.h"
#include "remotecmd.h"

#ifdef FIU_ENABLE
#include <fiu.h>
#endif

extern struct vz_data *vzcnf;

MigrateStateSrc::MigrateStateSrc(unsigned src_ve, unsigned dst_ve,
                                 const char * priv, const char * root,
				const char *name)
		: MigrateStateCommon()
{
	keepVE = NULL;
	srcVE = new VEObj(src_ve);
	dstVE = new VEObj(dst_ve);
	dstVE->setPrivate(priv);
	dstVE->setRoot(root);
	dstVE->setNameData(name);

	// We should destroy VEs in cleaner, not in destructor,
	// 'cause in some cleaner actions on MigrateCommon destructor MigrateStateSrc doesn't
	// exist already
	addCleaner(clean_delEntry, dstVE, NULL, ANY_CLEANER);
	addCleaner(clean_delEntry, srcVE, NULL, ANY_CLEANER);

	offlineTurned = false;
	m_convertQuota2[0] = '\0';
}

MigrateStateSrc::~MigrateStateSrc()
{
	if (m_convertQuota2[0] != '\0')
		unlink(m_convertQuota2);
}

int MigrateStateSrc::suspendVE_Ploop()
{
	int rc;

	if ((rc = srcVE->suspend()))
		return putErr(rc, MIG_MSG_SUSPEND, srcVE->veid(), getError());
	addCleaner(clean_resumeVE, srcVE);

	return 0;
}

int MigrateStateSrc::suspendVE_VZFS()
{
	bool support = is_cpt_stop_tracker_supported();
	int rc;

	// stop tracker too if is is possible
	if ((rc = srcVE->suspend(0, false, support)))
		return putErr(rc, MIG_MSG_SUSPEND, srcVE->veid(), getError());
	addCleaner(clean_resumeVE, srcVE);

	// use workaround to stop tracker
	if (!support) {
		if ((rc = srcVE->dump()))
			return putErr(rc, MIG_MSG_DUMP, srcVE->veid(), getError());
	}

	return 0;
}

// suspend with workaround to stop tracker
int MigrateStateSrc::suspendVE()
{
	if (srcVE->layout < VZCTL_LAYOUT_5)
		return suspendVE_VZFS();
	else
		return suspendVE_Ploop();
}

int MigrateStateSrc::stopVE()
{
	// Stop source VE
	// checking is needed on case of stopping VE during migration
	// by kernel license verification

	int rc = 0;
	// Turn off offline management
	// to correctly replace IP to keeper VE
	rc = srcVE->offlineManagement(false);
	if (rc != 0)
		return rc;
	addCleaner(clean_restoreOfflineManagement, srcVE);
	offlineTurned = true;

	// We transfer VE ip addresses to some 'keeper' VE
	if (isOptSet(OPT_KEEPER))
	{
		assert(keepVE);
		rc = exchangeIPs(*keepVE, *srcVE);
		if (rc != 0)
			return rc;
		addCleaner(clean_restoreVE, keepVE, srcVE);
	}

	if (isOptSet(OPT_ONLINE))
	{
		if ((rc = srcVE->stopVpsd()))
			return rc;


		if (!isOptSet(OPT_COPY)) {
			if ((rc = srcVE->createDumpFile()))
				return rc;
			addCleanerRemove(clean_removeFile, srcVE->dumpfile, ERROR_CLEANER);

			if ((rc = suspendVEOnline()))
				return rc;

			rc = copyDumpFile();
		} else {
			if ((rc = suspendVE()))
				return rc;
			addCleaner(clean_resumeVE, srcVE);
		}
	}
	else if (srcVE->isrun())
	{
		if (isOptSet(OPT_CONVERT_VZFS)) {
			if ((rc = suspendVEOffline()))
				return rc;
		} else {
			if ((rc = srcVE->stop(isOptSet(OPT_SKIP_UMOUNT))))
				return rc;
			addCleaner(clean_startVE, srcVE);
		}
	}

	return rc;
}

int MigrateStateSrc::startVEStage()
{
	int rc = 0;
	// Now we should restore (before dst VE starting) VEs IP from keeperVE
	if (isOptSet(OPT_KEEPER))
	{
		assert(keepVE);
		if ((rc = restoreIPs(*keepVE, *srcVE)))
			return rc;
	}

	if (!offlineTurned)
	{
		// Turn off offline management
		// to turn it on on destination
		rc = srcVE->offlineManagement(false);
		if (rc != 0)
			return rc;
		addCleaner(clean_restoreOfflineManagement, srcVE);
		offlineTurned = true;
	}

	// VE starting
	rc = startVE();
	if (rc != 0)
		return rc;

	return rc;
}

int MigrateStateSrc::doMigration()
{
	int rc;

	if ((rc = srcVE->getStatus(ENV_STATUS_MOUNTED | ENV_STATUS_RUNNING, &m_srcInitStatus)))
		return rc;

	rc = doCtMigration();
	if (rc)
		return rc;

	// clean MigrateState Cleaners
	erase();
	// final cleaning
	doCleaning(SUCCESS_CLEANER);
	return 0;
}

int MigrateStateSrc::clean_mountVE(const void * arg, const void *)
{
	VEObj * ve = (VEObj *) arg;
	assert(ve);
	logger(LOG_DEBUG, MIG_MSG_RST_MOUNT, ve->veid());
	// Mount source VE
	if ((ve->ismount() ? 0 : ve->mount()) != 0)
		return putErr(MIG_ERR_STARTVE, MIG_MSG_START,
		              ve->veid(), getError());
	return 0;
};

// Clean functions
int MigrateStateSrc::clean_startVE(const void * arg, const void *)
{
	VEObj * ve = (VEObj *) arg;
	assert(ve);

	logger(LOG_DEBUG, MIG_MSG_RST_START, ve->veid());
	ve->start();
	return 0;
};

int MigrateStateSrc::clean_closeSocket(const void * arg, const void *)
{
	int * sockfd = (int *) arg;
	// Close socket
	close(*sockfd);
	delete sockfd;
	return 0;
};

// Clean functions
int MigrateStateSrc::clean_restoreVE(const void * arg1, const void *arg2)
{
	VEObj * k = (VEObj *) arg1;
	VEObj * v = (VEObj *) arg2;
	rollbackIPs(*k, *v);
	return 0;
};

int MigrateStateSrc::clean_restoreOfflineManagement(const void * arg, const void *)
{
	VEObj * ve = (VEObj *) arg;
	assert(ve);
	logger(LOG_DEBUG, MIG_MSG_RST_OFFLINE, ve->veid());
	if (!ve->ve_data.offlm)
		return 0;
	return ve->offlineManagement(true);
};

int MigrateStateSrc::clean_deleteSnapshot(const void * arg1, const void * arg2)
{
	VEObj * ve = (VEObj *) arg1;
	const char *guid = (const char *)arg2;

	assert(ve);

	return ve->snapshot_delete(guid);
}

int MigrateStateSrc::getRelativePath(
		const char *directory,
		const char *path,
		char *rpath,
		size_t size)
{
	char real_path[PATH_MAX+1];
	char real_dir[PATH_MAX+1];
	char *p;

	if (realpath(path, real_path) == NULL)
		return putErr(MIG_ERR_SYSTEM, "realpath(%s) : %m", path);
	if (realpath(directory, real_dir) == NULL)
		return putErr(MIG_ERR_SYSTEM, "realpath(%s) : %m", directory);
	if (strncmp(real_path, real_dir, strlen(real_dir))) {
		snprintf(rpath, size, "%s", real_path);
	} else {
		for (p = (char *)real_path + strlen(real_dir); *p && *p == '/'; p++);
		strncpy(rpath, p, size-1);
		rpath[size-1] = '\0';
	}
	return 0;
}

/* merge ploop snapshot */
int MigrateStateSrc::clean_deletePloopSnapshot(const void * arg1, const void * arg2)
{
	return MigrateStateCommon::ploopDeleteSnapshot((const char *)arg1, (const char *) arg2);
};

/* register VE and restore name from config */
int MigrateStateSrc::clean_registerVE(const void * arg1, const void *)
{
	const char * opts[] = {"--applyconfig_map", "name", NULL };
	VEObj *ve = (VEObj *)arg1;
	assert(ve);

	logger(LOG_DEBUG, "Register CT %d", ve->veid());
	if (ve->registration())
		return 0;
	ve->operateVE("set", NULL, opts, 0);
	return 0;
}

int MigrateStateSrc::clean_resumeVE(const void * arg1, const void *)
{
	VEObj * ve = (VEObj *) arg1;

	assert(ve);
	logger(LOG_DEBUG, MIG_MSG_RST_RESUME, ve->veid());
	// Resume source VE
	if (ve->isfrozen())
		ve->resume_chkpnt();
	return 0;
}

/* exclude active delta */
int MigrateStateSrc::excludeActiveDelta(const char *dd_xml, char *path,
		size_t size)
{
	int rc;
	char delta[PATH_MAX + 1];

	if ((rc = MigrateStateCommon::ploopGetTopImageFileName(dd_xml, delta, sizeof(delta))) ||
			(rc = getRelativePath(srcVE->priv, delta, path, size)))
		return rc;

	return 0;
}

int MigrateStateSrc::getActivePloopDelta(const ct_disk &disk, struct string_list *list)
{
	int rc;
	char path[PATH_MAX];

	for (ct_disk::const_iterator it = disk.begin();
			it != disk.end(); ++it)
	{
		/* exclude active delta */
		rc = excludeActiveDelta(get_dd_xml(it->image).c_str(), path, sizeof(path));
		if (rc)
			return rc;

		string_list_add(list, path);
	}

	return 0;
}

int MigrateStateSrc::getActivePloopDelta(struct string_list *list)
{
	return getActivePloopDelta(srcVE->m_disks, list);
}

void MigrateStateSrc::cleanExternalDisk()
{
	for (ct_disk::const_iterator it = srcVE->m_disks.begin();
			it != srcVE->m_disks.end(); ++it)
	{
		if (!it->is_external() || it->is_shared())
			continue;

		logger(LOG_WARNING, "Clean external disk '%s'", it->image.c_str());
		/* FIXME: umount ploop */
		clean_removeDir(it->image.c_str(), NULL);
	}
}

void MigrateStateSrc::removeSrcPrivate()
{
	char path[PATH_MAX+1];

	// remove old existed .migrated directory
	// and move private to .migrated directory
	snprintf(path, sizeof(path), "%s" SUFFIX_MIGRATED,
		srcVE->priv);
	if (access(path, F_OK) == 0)
		clean_removeDir(path, NULL);

	if (clean_rename(srcVE->priv, path))
		logger(LOG_WARNING, getError());
}

static bool disk_is_not_persistent(const struct disk_entry &d)
{
	return !d.persistent;
}

int MigrateStateSrc::checkDisks()
{
	/* deny CT migration with attached backup #PSBM-29134 */
	if (!isOptSet(OPT_FORCE) && !isOptSet(OPT_IGNORE_BACKUP_DISK))
	{
		if (srcVE->m_disks.has(disk_is_not_persistent)) {
			return putErr(MIG_ERR_VZCTL,
					"Cannot migrate a Container with backup(s) attached.");
		}
	}

	return 0;
}

int MigrateStateSrc::checkCommonSrc()
{
	int rc;

	if ((rc = checkDisks()))
		return rc;

	if (!srcVE->isrun() && isOptSet(OPT_ONLINE))
		return putErr(MIG_ERR_USAGE, "Source Container must be running for online migration");

	// do not migrate temporary VE for template cache
	if (srcVE->ve_data.ve_type && strcasecmp(srcVE->ve_data.ve_type, "temporary") == 0)
			return putErr(MIG_ERR_SPECIALVE, MIG_MSG_SPECIAL, srcVE->veid(), srcVE->ve_data.ve_type);

	return 0;
}

int MigrateStateSrc::checkDiskSpace()
{
	int rc;
	unsigned long long bytes;

	if (isSameLocation())
		return 0;

	if ((rc = get_disk_usage_ploop(srcVE->priv, &bytes)))
		return rc;

	return checkDiskSpaceValues(bytes, 0);
}

int MigrateStateSrc::checkDiskSpaceRC(int rc)
{
	if (rc != MIG_ERR_DISKSPACE)
		return rc;

	if (!isOptSet(OPT_SKIP_DISKSPACE) && !isOptSet(OPT_FORCE)) {
		logger(LOG_ERR, MIG_MSG_DISKSPACE, getError());
		return rc;
	} else {
		logger(LOG_WARNING, MIG_MSG_DISKSPACE, getError());
		return 0;
	}
}

void add_excludes(std::list<std::string> &args, const std::list<std::string> *exclude)
{
	if (!exclude)
		return;

	for (list<string>::const_iterator i = exclude->begin(); i != exclude->end(); ++i) {
		args.push_back("--exclude");
		args.push_back(*i);
	}
}
