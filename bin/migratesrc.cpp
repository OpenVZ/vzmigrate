/* $Id$
 *
 * Copyright (c) 2006-2017, Parallels International GmbH
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

MigrateStateSrc::MigrateStateSrc(const char * src_ctid, const char * dst_ctid,
				const char * priv, const char * root,
				const char *name)
		: MigrateStateCommon()
{
	keepVE = NULL;
	srcVE = new VEObj(src_ctid);
	dstVE = new VEObj(dst_ctid);
	dstVE->setPrivate(priv);
	dstVE->setRoot(root);
	dstVE->setNameData(name);

	// We should destroy VEs in cleaner, not in destructor,
	// 'cause in some cleaner actions on MigrateCommon destructor MigrateStateSrc doesn't
	// exist already
	addCleaner(clean_delVeobj, dstVE, NULL, ANY_CLEANER);
	addCleaner(clean_delVeobj, srcVE, NULL, ANY_CLEANER);

	m_convertQuota2[0] = '\0';
}

MigrateStateSrc::~MigrateStateSrc()
{
	if (m_convertQuota2[0] != '\0')
		unlink(m_convertQuota2);
}

/*
 * Transfer ip addresses of CT to some 'keeper' CT.
 */
int MigrateStateSrc::exchangeKeeperIPs()
{
	assert(keepVE);

	int rc = exchangeIPs(*keepVE, *srcVE);
	if (rc != 0)
		return rc;

	addCleaner(clean_rollbackIPs, keepVE, srcVE, ERROR_CLEANER);
	return 0;
}

/*
 * Restore ip addresses of CT from 'keeper' CT.
 */
int MigrateStateSrc::restoreKeeperIPs()
{
	assert(keepVE);
	return restoreIPs(*keepVE, *srcVE);
}

int MigrateStateSrc::startVEStage()
{
	int rc = 0;

	if (isOptSet(OPT_KEEPER))
		if ((rc = restoreKeeperIPs()))
			return rc;

	// VE starting
	rc = startVE();
	if (rc != 0)
		return rc;

	return rc;
}

int MigrateStateSrc::doMigration()
{
	// Get status of container
	int rc = srcVE->getStatus(ENV_STATUS_MOUNTED | ENV_STATUS_RUNNING, &m_srcInitStatus);
	if (rc)
		return rc;

	// Migrate container
	rc = doCtMigration();
	if (rc)
		return rc;

	// Handle final cleanup
	erase();
	doCleaning(SUCCESS_CLEANER);
	return 0;
}

int MigrateStateSrc::clean_mountVE(const void * arg, const void *)
{
	VEObj * ve = (VEObj *) arg;
	assert(ve);
	logger(LOG_DEBUG, MIG_MSG_RST_MOUNT, ve->ctid());
	// Mount source VE
	if ((ve->ismount() ? 0 : ve->mount()) != 0)
		return putErr(MIG_ERR_STARTVE, MIG_MSG_START,
			ve->ctid(), getError());
	return 0;
};

// Clean functions
int MigrateStateSrc::clean_startVE(const void * arg, const void *)
{
	VEObj * ve = (VEObj *) arg;
	assert(ve);

	logger(LOG_DEBUG, MIG_MSG_RST_START, ve->ctid());
	ve->start();
	return 0;
};

// Clean functions
int MigrateStateSrc::clean_rollbackIPs(const void * arg1, const void *arg2)
{
	VEObj * k = (VEObj *) arg1;
	VEObj * v = (VEObj *) arg2;
	rollbackIPs(*k, *v);
	return 0;
};

int MigrateStateSrc::clean_deleteSnapshot(const void * arg1, const void * arg2)
{
	VEObj * ve = (VEObj *) arg1;
	const char *guid = (const char *)arg2;

	assert(ve);

	return ve->tsnapshot_delete(guid);
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

	logger(LOG_DEBUG, "Register CT %s", ve->ctid());
	if (ve->registration())
		return 0;
	ve->operateVE("set", NULL, opts, 0);
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
		return putErr(MIG_ERR_SPECIALVE, MIG_MSG_SPECIAL,
			srcVE->ctid(), srcVE->ve_data.ve_type);

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
