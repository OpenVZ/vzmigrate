/*
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
#include <sys/vfs.h>
#include <libgen.h>
#include <sstream>
#include <map>
#include <mntent.h>
#include <sys/mount.h>
#include <uuid/uuid.h>

#include <vzctl/libvzctl.h>

#include "util.h"
#include "migsrclocal.h"

extern struct vz_data *vzcnf;
extern const char * actionScripts[];

int string_list_add_str(struct string_list *ls, const std::string &str)
{
	return string_list_add(ls, str.c_str());
}

std::string slashed_dir(const std::string dir)
{
	if (*(dir.end() - 1) == '/')
		return dir;
	else
		return dir + '/';
}

std::string basename_str(const std::string filename)
{
	char tmp[PATH_MAX];

	copy_cstr(filename.c_str(), tmp, sizeof(tmp));
	return basename(tmp);
}

std::string combine_path(const std::string &dir1, const std::string &dir2, const std::string &name)
{
	std::ostringstream os;

	os << slashed_dir(dir1) << slashed_dir(dir2) << name;

	return os.str();
}

std::string combine_path(const std::string &dir, const std::string &name)
{
	std::ostringstream os;

	os << slashed_dir(dir) << name;

	return os.str();
}

MigrateStateLocal::MigrateStateLocal(
		const char * src_ctid, const char * dst_ctid,
		const char * src_priv, const char * priv, const char * root,
		const char * dst_name, const char * uuid)
		: MigrateStateSrc(src_ctid, dst_ctid, src_priv, priv, root, dst_name)
{
	is_thesame_ctid = 0;
	is_thesame_private = 0;
	is_thesame_root = 0;
	is_thesame_location = 0;
	is_priv_on_shared = 0;
	m_uuid = uuid;
};

MigrateStateLocal::~MigrateStateLocal()
{
}

static int find_mount_point(const char *path, char *buf, int buf_size);

/* is both path on one device and one mount point */
static int cmp_locations(const char *src, const char *dst, int *is_thesame)
{
	char mount_src[PATH_MAX], mount_dst[PATH_MAX];
	int rc;

	if ((rc = find_mount_point(src, mount_src, sizeof(mount_src))))
		return rc;
	if ((rc = find_mount_point(dst, mount_dst, sizeof(mount_dst))))
		return rc;

	*is_thesame = strcmp(mount_src, mount_dst) == 0;
	return 0;
}

static int find_mount_point(const char *path, char *buf, int buf_size)
{
	FILE *fp;
	char rpath[PATH_MAX], read_buf[PATH_MAX];

	if (realpath(path, rpath) == NULL) {
		logger(LOG_ERR, "realpath(%s) : %m", path);
		return MIG_ERR_SYSTEM;
	}

	fp = fopen("/proc/self/mountinfo", "r");
	if (fp == NULL) {
		logger(LOG_ERR, "Can't open /proc/self/mountinfo");
		return MIG_ERR_SYSTEM;
	}

	buf[0] = '/';
	while (fgets(read_buf, sizeof(read_buf), fp)) {
		unsigned int u, n, l;
		char mnt_dir[4096];

		n = sscanf(read_buf, "%u %u %u:%u %*s %4095s", &u, &u, &u, &u, mnt_dir);
		if (n != 5)
			continue;
		l = strlen(mnt_dir);
		// root is a special case which handled by default value
		if (strncmp(rpath, mnt_dir, l) == 0 && (rpath[l] == '/' || rpath[l] == '\0'))
			snprintf(buf, buf_size, "%s", mnt_dir);
	}
	fclose(fp);

	return 0;
}

int MigrateStateLocal::doCtMigration()
{
	int rc;

	if ((rc = preMigrateStage()))
		return rc;

	if (isOptSet(OPT_COPY)) {
		if ((rc = ploopCtClone()))
			return rc;

		if ((rc = preFinalStage()))
			return rc;
	} else {
		if ((rc = ploopCtMove()))
			return rc;

		if ((rc = preFinalStage()))
			return rc;

		if ((rc = startVEStage()))
			return rc;
	}

	return postFinalStage();
}

int MigrateStateLocal::checkBundleMix()
{
	std::vector<external_disk_path>::const_iterator it;

	for (it = unb_disks.begin(); it != unb_disks.end(); ++it) {
		if (bundles.find(it->src_bundle()) != bundles.end()) {
			return putErr(MIG_ERR_EXTERNAL_DISKS_MIXED, "Clone operation is not supported for "\
				"containers with mixed bundled and unbundled external disks"\
				"in the same directory. Check directory %s", it->location.c_str());
		}
	}

	return 0;
}

int MigrateStateLocal::createBundle(const std::string &p)
{
	logger(LOG_DEBUG, "create bundle %s", p.c_str());
	if (mkdir(p.c_str(), 0755)) {
		if (errno == EEXIST)
			return putErr(MIG_ERR_DST_BUNDLE_EXIST,
				"destination bundle '%s' exists.", p.c_str());
		else
			return putErr(MIG_ERR_SYSTEM, "mkdir(%s) : %m", p.c_str());
	}
	addCleanerRemove(clean_removeDir, p.c_str());
	return 0;
}

int MigrateStateLocal::createDstBundles()
{
	std::map<std::string, bundle>::const_iterator it;
	int rc;

	for (it = bundles.begin(); it != bundles.end(); ++it) {
		if (is_thesame_ctid)
			continue;
		if (strcmp(it->second.src.c_str(), srcVE->priv) == 0)
			continue;
		rc = createBundle(it->second.dst);
		if (rc)
			return rc;
	}

	return 0;
}

int MigrateStateLocal::createDstBundlesUnbundledDisks()
{
	std::vector<external_disk_path>::const_iterator it;
	int rc;

	for (it = unb_disks.begin(); it != unb_disks.end(); ++it) {
		rc = createBundle(it->dst_bundle());
		if (rc)
			return rc;
	}

	return 0;
}

static void update_disk_path(std::string &str, const std::string &src_image,
		const std::string &dst_image)
{
	std::string::size_type n;

	for (n = 0; ; n += src_image.length()) {
		n = str.find(src_image, n);
		if (n == std::string::npos)
			break;

		char e = str[n + src_image.length()];
		if (e == ',' || e == ';' || e == '\0') {
			logger(LOG_INFO, "Update image path %s -> %s",
					src_image.c_str(), dst_image.c_str());
			str.replace(n, src_image.length(), dst_image);
		}
	}
}

int MigrateStateLocal::updateDiskPath()
{
	if (srcVE->ve_data.disk_raw_str == NULL)
		return 0;

	std::string disk_str(srcVE->ve_data.disk_raw_str);

	std::map<std::string, bundle>::const_iterator it;
	for (it = bundles.begin(); it != bundles.end(); ++it) {
		std::vector<std::string>::const_iterator d;
		const struct bundle &b = it->second;
		for (d = b.disks.begin(); d != b.disks.end(); ++d)
			update_disk_path(disk_str, combine_path(b.src, *d),
						combine_path(b.dst, *d));
	}
	if (isOptSet(OPT_COPY)) {
		std::vector<external_disk_path>::const_iterator it2;
		for (it2 = unb_disks.begin(); it2 != unb_disks.end(); ++it2)
			update_disk_path(disk_str, it2->src_path(), it2->dst_path());
	}

	return dstVE->updateConfig(VE_CONF_DISK, disk_str.c_str());
}

int MigrateStateLocal::preMigrateStage()
{
	int rc;
	long fstype;

	START_STAGE();

	if (CMP_CTID(srcVE->ctid(), dstVE->ctid()) == 0)
		is_thesame_ctid = 1;

	if ((rc = srcVE->init_existed()))
		return rc;

	if (!isOptSet(OPT_READONLY)) {
		if ((rc = srcVE->lock()))
			return rc;
	}

	if ((rc = checkCommonSrc()))
		return rc;

	if (!is_thesame_ctid)
		if ((rc = checkDstIDFree(*dstVE)))
			return rc;

	if (CMP_CTID(srcVE->ctid(), dstVE->ctid()) == 0) {
		/* for move-root/private-mode: if target private or root is not defined
		   will use private/root of source CT */
		if (!dstVE->priv)
			dstVE->setPrivate(srcVE->priv);
		if (!dstVE->root)
			dstVE->setRoot(srcVE->root);
	}
	if ((rc = dstVE->init_empty()))
		return rc;

	/* set src layout and veformat for dst VE */
	dstVE->setLayout(srcVE->layout);
	dstVE->veformat = srcVE->veformat;

	if ((rc = checkCommonDst(*dstVE)))
		return rc;

	if ((rc = is_path_on_shared_storage(dstVE->priv, &is_priv_on_shared,
					&fstype)))
		return rc;

	/* check private/root */
	if (strcmp(srcVE->priv, dstVE->priv) == 0) {
		/* it's possible, as sample, when VE_PRIVATE in
		   VE config does not content $VEID and
		   ve_private does specified in command line */
		if (isOptSet(OPT_COPY)) {
			return putErr(MIG_ERR_SYSTEM, MIG_MSG_PRIV_EQUALS,
				srcVE->priv);
		}
		logger(LOG_DEBUG,  MIG_MSG_PRIV_EQUALS, srcVE->priv);
		is_thesame_private = 1;
	}
	if (strcmp(srcVE->root, dstVE->root) == 0) {
		if (isOptSet(OPT_COPY))
			return putErr(MIG_ERR_SYSTEM, MIG_MSG_ROOT_EQUALS);
		logger(LOG_DEBUG,  MIG_MSG_ROOT_EQUALS);
		is_thesame_root = 1;
	}

	buildBundles();

	if (isOptSet(OPT_COPY)) {
		if ((rc = checkBundleMix()))
			return rc;
	}

	if (is_thesame_ctid && is_thesame_private && is_thesame_root)
		return putErr(MIG_ERR_EQUALS, MIG_MSG_EQUALS);

	// clean destination
	if (!is_thesame_ctid)
		dstVE->clean();

	// check VE private
	if (!is_thesame_private) {
		// check uniquely
		if ((rc = checkVEDir(dstVE->priv, 1)))
			return rc;
		addCleanerRemove(clean_removeDir, dstVE->priv);
	}

	if ((rc = cmp_locations(srcVE->priv, dstVE->priv, &is_thesame_location)))
		return rc;

	if (fstype == PCS_SUPER_MAGIC && is_thesame_location) {
		logger(LOG_ERR, "CT on shared storage, switching to copy mode");
		is_thesame_location = 0;
	}

	logger(LOG_DEBUG, "location '%s' & '%s' are %s", srcVE->priv, dstVE->priv,
			is_thesame_location ? "equal" : "differ" );

	// check no bundles with new CT names
	if ((rc = createDstBundles()))
		return rc;

	if (isOptSet(OPT_COPY)) {
		if ((rc = createDstBundlesUnbundledDisks()))
			return rc;
	}

	/* and lock new VE only after private creation
	   (vzctl will create lock file in private, #119945) */
	if (!is_thesame_ctid && !is_thesame_private) {
		if ((rc = dstVE->lock()))
			return rc;
	}

	if (isOptSet(OPT_COPY))
		rc = checkDiskSpaceClone();
	else
		rc = checkDiskSpace();
	if ((rc = checkDiskSpaceRC(rc)))
		return rc;

	/* check target VE name if it was specified in command line */
	if ((rc = dstVE->checkName(dstVE->ve_data.name)))
		return rc;

	if (!is_thesame_ctid) {
		std::string s = EMPTY_CTID(srcVE->ctid()) ?
				srcVE->confRealPath() : srcVE->confPath();
		if ((rc = h_copy(s.c_str(), dstVE->confPath().c_str())))
			return rc;

		if ((rc = dstVE->prepareConfig()))
			return rc;
	}

	/* load config data of destination VE */
	if ((rc = dstVE->loadConfig()))
		return rc;

	if (isOptSet(OPT_COPY))
		dstVE->renewMAC();
	else if (dst_name == NULL && srcVE->ve_data.name != NULL)
		/* preserve name from source on move */
		dstVE->setNameData(srcVE->ve_data.name);

	END_STAGE();
	return 0;
};

int MigrateStateLocal::preFinalStage()
{
	char u[39] = "";
	const char *uuid = m_uuid;
	int rc;
	START_STAGE();

	/* Try to get source VE name if target VE name is not defined.
	if (dstVE->ve_data.name == NULL && srcVE->ve_data.name != NULL&&
			(!isOptSet(OPT_COPY))) 
		dstVE->ve_data.name = strdup(srcVE->ve_data.name);
	*/
	if (NULL == uuid && (isOptSet(OPT_COPY) || !is_thesame_ctid)) {
		uuid_t x;
		if (uuid_parse(dstVE->ctid(), x) == 0) {
			uuid = dstVE->ctid();
		} else {
			gen_uuid(u);
			uuid = u;
		}
	}

	if (isOptSet(OPT_SKIP_REGISTER)) {
		if (srcVE->ve_data.name != NULL) {
			std::string f("/etc/vz/names/");
			f += srcVE->ve_data.name;
			unlink(f.c_str());
		}
		return 0;
	}

	if (is_thesame_ctid) {
		/* create config backup */
		if ((rc = h_backup(dstVE->confRealPath().c_str())))
			return rc;
		/* modify original config */
		unlink(dstVE->confPath().c_str());
		if ((rc = copy_file(dstVE->confPath().c_str(),
			dstVE->confRealPath().c_str())))
			return rc;
		if ((rc = dstVE->updateConfig(VE_CONF_PRIV, dstVE->getPrivateConf().c_str())))
			return rc;
		if ((rc = dstVE->updateConfig(VE_CONF_ROOT, dstVE->getRootConf().c_str())))
			return rc;
	}

	logger(LOG_INFO, "Copying/modifying config scripts of CT %s ...",
			srcVE->ctid());
	rc = updateDiskPath();
	if (rc)
		return rc;

	if (!isOptSet(OPT_COPY) && strcmp(srcVE->ctid(), dstVE->ctid()))
		vzctl2_send_state_evt(srcVE->ctid(), VZCTL_ENV_UNREGISTERED);
	logger(LOG_INFO, "Register CT %s uuid=%s", dstVE->ctid(), uuid ?: "");
	if ((rc = dstVE->veRegister(uuid)))
		return rc;

        if (!is_thesame_location)
                addCleaner(clean_register, srcVE);

	if (srcVE->ve_data.ha_enable) {
		if (isOptSet(OPT_COPY)) {
			// target CT private
			if (is_priv_on_shared) {
				rc = runHaman(dstVE->ctid(), "add", srcVE->ve_data.ha_prio, dstVE->priv);
				if (rc)
					return putErr(rc,
						"Can't add resource %s at HA cluster", dstVE->ctid());
				addCleaner(clean_unitaryHaClusterResouce, dstVE, "del");
			}
		} else if (!is_thesame_private) {
			// private was moved
			int is_src_priv_on_shared;
			if ((rc = is_path_on_shared_storage(srcVE->priv, &is_src_priv_on_shared, NULL)))
				return rc;

			// Pay attention that 'rename' operation is not atomic now
			// and we use consistently 'shaman add $newCTID'
			// and 'shaman del $oldCTID' for renamed resource.

			if (is_priv_on_shared) {
				// target private was moved to shared
				rc = runHaman(dstVE->ctid(), "add", srcVE->ve_data.ha_prio, dstVE->priv);
				if (rc)
					return putErr(rc,
						"Can't add resource %s at HA cluster", dstVE->ctid());
				addCleaner(clean_unitaryHaClusterResouce, dstVE, "del");
			}

			if (is_src_priv_on_shared) {
				// source private was removed from shared
				rc = runHaman(srcVE->ctid(), "del");
				if (rc)
					return putErr(rc,
						"Can't remove resource %s from HA cluster", srcVE->ctid());
				addCleaner(clean_unitaryHaClusterResouce, dstVE, "add");
			}
		}
	}

	if (isOptSet(OPT_COPY)) {
	/*
	 * Update MAC-addresses for all network interfaces in cloned VE (#PSBM-15447).
	 * XXX: do it after veRegister(), otherwize vzctl fails to update MACs.
	 */
		if ((rc = dstVE->renewMAC()))
			return rc;
	} else if (NULL == dstVE->ve_data.name && srcVE->ve_data.name != NULL) {
		// New name for the target VE is undefined.
		// Try to get name of the source one.
		dstVE->ve_data.name = strdup(srcVE->ve_data.name);
		if ((rc = dstVE->updateConfig(VE_CONF_NAME, dstVE->ve_data.name)))
			return rc;
	}

	END_STAGE();
	return 0;
}

const char* const vzaEnvEIDPath = "/.vza/eid.conf";

int MigrateStateLocal::postFinalStage()
{
	int rc;

	START_STAGE();

	if (!isOptSet(OPT_COPY)) {
		if (isOptSet(OPT_SKIP_REGISTER))
			unlink(srcVE->confPath().c_str());
		else if (!is_thesame_ctid) {
			srcVE->unregister();
			unlink(srcVE->confPath().c_str());
		}
		srcVE->unlock();
		if (!is_thesame_private && access(srcVE->priv, F_OK) == 0)
			rmdir_recursively(srcVE->priv);
		if (!is_thesame_root)
			rmdir(srcVE->root);
	} else {
		// clone mode
		/* remove dst_PRIVATE/.vza/eid.conf agent_specific */
		string strbuf = dstVE->priv;
		strbuf.append(vzaEnvEIDPath);
		clean_removeFile(strbuf.c_str(), NULL);
		/* remove dst_PRIVATE/.uptime - we are creating new CT, reset
		 * uptime to zero */
		strbuf = dstVE->priv;
		strbuf.append("/.uptime");
		clean_removeFile(strbuf.c_str(), NULL);

		/* to execute /etc/sysconfig/vz-scripts/vps.clone
		for local clone (#427065) */
		char script[PATH_MAX+1];
		strncpy(script, VE_OLD_CONF_DIR "vps.clone", sizeof(script));
		if (access(script, X_OK) == 0) {
			char env[100];
			char * const args[] = {script, NULL};
			char * const envp[] = {env, NULL};
			snprintf(env, sizeof(env), "VEID=%s", dstVE->ctid());
			vzm_execve(args, envp, -1, -1, NULL);
		}

		/* exec VE postinstall script (to randomize cron,
		   https://jira.sw.ru/browse/PCLIN-8821.
		   vzctl execaction will mount CT, run script and umount CT */
		if ((rc = dstVE->ExecPostCreate()))
			logger(LOG_ERR, "post create action failed for CT %s", dstVE->ctid());

		/* change FS uuid for cloned CT (https://jira.sw.ru/browse/PSBM-11961) */
		if (dstVE->mount() == 0) {
			MigrateStateCommon::regenerate_fs_uuid(dstVE->root);
			dstVE->umount();
		} else {
			logger(LOG_ERR, "CT mount failed, can not change disk uuid");
		}

	}
	END_STAGE();
	return 0;
}

/*
 * Stage of src VE stopping.
 */
int MigrateStateLocal::stopVE()
{
	int rc = 0;

	assert(!isOptSet(OPT_COPY));

	if (isOptSet(OPT_KEEPER))
		if ((rc = exchangeKeeperIPs()))
			return rc;

	if (isOptSet(OPT_ONLINE))
	{
		if ((rc = srcVE->stopVpsd()))
			return rc;

		if ((rc = srcVE->cmd_suspend()))
			return putErr(rc, MIG_MSG_CMD_SUSPEND, srcVE->ctid(), getError());

		addCleaner(clean_restoreVE, srcVE, NULL, ERROR_CLEANER);
	}
	else if (srcVE->isrun())
	{
		if ((rc = srcVE->stop(isOptSet(OPT_SKIP_UMOUNT))))
			return rc;

		addCleaner(clean_startVE, srcVE, NULL, ERROR_CLEANER);
	}

	return rc;
}

/*
 * Stage of dst VE starting.
 */
int MigrateStateLocal::startVE()
{
	int rc = 0;

	assert(!isOptSet(OPT_COPY));

	if (isOptSet(OPT_ONLINE)) {
		if ((rc = dstVE->cmd_restore()))
			return putErr(rc, MIG_MSG_CMD_RESTORE, dstVE->ctid(), getError());

	} else {
		if (isOptSet(OPT_NOSTART))
			return 0;

		if (m_srcInitStatus & ENV_STATUS_RUNNING)
			rc = dstVE->start();
		else if (m_srcInitStatus & ENV_STATUS_MOUNTED)
			rc = dstVE->mount();

		if (rc)
			return rc;
	}

	return 0;
}

struct dev_space {

	std::string path;
	unsigned long long bytes;
};

static int accumulate_space(std::map<dev_t, struct dev_space> &dev2space, const std::string &src_str,
		const std::string &dst_str)
{
	struct stat st;
	dev_t dev_dst;
	unsigned long long bytes;
	const char *dst, *src;
	int rc;

	dst = dst_str.c_str();
	src = src_str.c_str();

	logger(LOG_DEBUG, "accumulate space for %s -> %s", src, dst);

	if (stat(dst, &st))
		return putErr(MIG_ERR_SYSTEM, "stat(%s)", dst);
	dev_dst = st.st_dev;

	if ((rc = get_disk_usage_ploop(src, &bytes)))
		return rc;

	if (dev2space.find(dev_dst) == dev2space.end()) {
		dev2space[dev_dst].path = dst;
		dev2space[dev_dst].bytes = bytes;
	} else {
		dev2space[dev_dst].bytes += bytes;
	}

	return 0;
}

int MigrateStateLocal::checkDiskSpaceClone()
{
	int rc;
	std::map<dev_t, struct dev_space> dev2space;
	std::map<std::string, bundle>::const_iterator itb;
	std::vector<external_disk_path>::const_iterator itu;
	std::map<dev_t, struct dev_space>::const_iterator its;

	for (itb = bundles.begin(); itb != bundles.end(); ++itb) {
		const struct bundle &b = itb->second;
		if ((rc = accumulate_space(dev2space, b.src, b.dst)))
			return rc;
	}

	// unbundled external disk are copied too on clone
	for (itu = unb_disks.begin(); itu != unb_disks.end(); ++itu) {
		if ((rc = accumulate_space(dev2space, itu->src_path(), itu->dst_bundle())))
			return rc;
	}

	logger(LOG_DEBUG, "check spaces per device");
	// now check that there is enough space for every device
	for (its = dev2space.begin(); its != dev2space.end(); ++its) {
		const struct dev_space &s = its->second;
		if ((rc = check_free_space(s.path.c_str(), s.bytes, 0)))
			return rc;
	}

	return 0;
}

int MigrateStateLocal::checkDiskSpaceValues(
		unsigned long long bytes, unsigned long long inodes)
{
	return check_free_space(dstVE->priv, bytes, inodes);
}

/* unused function */
#if 0
static int doCopy(const char * const args[], ...)
{
	int rc;
	const char * prog_args[MAX_ARGS];
	va_list pvar;

	va_start(pvar, args);
	arrangeArgs(prog_args, sizeof(prog_args)/sizeof(char *), args, pvar);
	va_end(pvar);

	logger(LOG_DEBUG, "copy call: %s", getProgArgs(prog_args).c_str());
	if ((rc = vzm_execve((char* const *)prog_args, NULL, -1, -1, NULL)))
		return putErr(MIG_ERR_COPY, MIG_MSG_COPY,
			prog_args[0], getError());

	return 0;
}
#endif

int MigrateStateLocal::clean_restoreVE(const void * arg1, const void *)
{
	VEObj * ve = (VEObj *) arg1;
	assert(ve);
	logger(LOG_DEBUG, MIG_MSG_RST_RESUME, ve->ctid());

	// Resume source VE
	if (!ve->issuspended())
		return 0;

	if (ve->cmd_restore())
		return putErr(MIG_ERR_STARTVE, MIG_MSG_CMD_RESTORE,
			ve->ctid(), getError());
	return 0;
}

int MigrateStateLocal::clean_unitaryHaClusterResouce(const void * arg1, const void * arg2)
{
	VEObj * ve = (VEObj *) arg1;
	const char *cmd = (const char *)arg2;
	assert(ve);
	runHaman(ve->ctid(), cmd, ve->ve_data.ha_prio);
	return 0;
}

int MigrateStateLocal::clean_moveHaClusterResource(const void * arg1, const void * arg2)
{
	VEObj * srcVE = (VEObj *) arg1;
	VEObj * dstVE = (VEObj *) arg2;
	assert(srcVE);
	assert(dstVE);
	runHaman(srcVE->ctid(), "rename", dstVE->ctid());
	return 0;
}

static int copy_local(const char *src, const char *dst,
		struct string_list *exclude)
{
	struct string_list args;
	int rc;

	if (src == NULL || dst == NULL)
		return MIG_ERR_SYSTEM;

	logger(LOG_ERR, "Copy %s %s", src, dst);
	string_list_init(&args);
	string_list_add(&args, (char *)"rsync");
	string_list_add(&args, (char *)"-aH");
	if (exclude) {
		struct string_list_el *elem;

		string_list_for_each(exclude, elem) {
			if ((rc = string_list_add(&args, "--exclude")) ||
					(rc = string_list_add(&args, elem->s)))
				goto err;
		}
	}

	string_list_add(&args, src);
	string_list_add(&args, dst);
	rc = vzml_execve(&args, NULL, -1, -1, 0);
	if (rc)
		rc = putErr(MIG_ERR_COPY, "%s to %s copy error", src, dst);

err:
	string_list_clean(&args);

	return rc;
}

static int copy_local(const std::string &src, const std::string &dst,
		struct string_list *exclude)
{
	return copy_local(src.c_str(), dst.c_str(), exclude);
}

static void split_path(const std::string &path, std::string &dir, std::string &base)
{
	char buf[PATH_MAX + 1];

	strcpy(buf, path.c_str());
	dir = dirname(buf);

	strcpy(buf, path.c_str());
	base = basename(buf);
}

static std::string get_rel_path(const std::string &basedir, const std::string &dir)
{
	return dir.compare(0, basedir.length(), basedir) ? dir :
				dir.substr(basedir.length() + 1);
}

external_disk_path::external_disk_path(const char *path, const std::string &a_src_id, const std::string &a_dst_id)
	: has_bundle(false), dst_id(a_dst_id), src_id(a_src_id)
{
	std::string d;

	split_path(path, d, name);
	if (d == "/") {
		location = d;
		return;
	}

	std::string b, l;

	split_path(d, l, b);
	if (b == src_id) {
		has_bundle = true;
		location = l;
	} else {
		location = d;
	}
}

std::string external_disk_path::dst_bundle() const
{
	return combine_path(location, dst_id);
}

std::string external_disk_path::src_bundle() const
{
	return combine_path(location, src_id);
}

std::string external_disk_path::src_path() const
{
	if (has_bundle)
		return combine_path(location, src_id, name);
	else
		return combine_path(location, name);
}

std::string external_disk_path::dst_path() const
{
	return combine_path(location, dst_id, name);
}

void MigrateStateLocal::buildBundles()
{
	struct bundle &b = bundles[srcVE->priv];
	// add main bundle
	b.src = srcVE->priv;
	b.dst = dstVE->priv;

	for (ct_disk::const_iterator it = srcVE->m_disks.begin();
				it != srcVE->m_disks.end(); ++it)
	{
		if (!it->is_external()) {
			b.disks.push_back(get_rel_path(b.src, it->image));
		} else {
			// find bundles and unbundled disks in external disks
			struct external_disk_path p(it->image.c_str(),
				std::string(srcVE->ctid()), std::string(dstVE->ctid()));
			if (p.has_bundle) {
				struct bundle &b = bundles[p.src_bundle()];
				if (b.disks.empty()) {
					logger(LOG_DEBUG, "Found ext disk bundle %s", p.src_bundle().c_str());
					b.src = p.src_bundle();
					b.dst = p.dst_bundle();
				}
				b.disks.push_back(p.name);
			} else {
				unb_disks.push_back(p);
			}
		}
	}
}

int copy_disk_descriptor(const std::string &src, const std::string &dst)
{
	return copy_local(get_dd_xml(src), rsync_dir(dst), NULL);
}

int MigrateStateLocal::copyDiskDescriptors()
{
	std::map<std::string, bundle>::const_iterator itb;
	int rc;

	START_STAGE();
	// copy descriptors in bundles
	for (itb = bundles.begin(); itb != bundles.end(); ++itb) {
		std::vector<std::string>::const_iterator it;
		const struct bundle &b = itb->second;
		for (it = b.disks.begin(); it != b.disks.end(); ++it) {
			rc = copy_disk_descriptor(combine_path(b.src, *it),
					combine_path(b.dst, *it));
			if (rc)
				return rc;
		}
	}

	std::vector<external_disk_path>::const_iterator itu;
	// copy unbundled disks descriptors
	for (itu = unb_disks.begin(); itu != unb_disks.end(); ++itu) {
		rc = copy_disk_descriptor(itu->src_path(), itu->dst_path());
		if (rc)
			return rc;
	}
	END_STAGE();

	return 0;
}

int get_active_delta(const std::string &disk, const std::string &base, std::string &d)
{
	char delta[PATH_MAX + 1];
	char delta_r[PATH_MAX + 1];
	int rc;

	if ((rc = MigrateStateCommon::ploopGetTopImageFileName(get_dd_xml(disk).c_str(), delta, sizeof(delta))) ||
			(rc = MigrateStateSrc::getRelativePath(base.c_str(), delta, delta_r, sizeof(delta_r))))
		return rc;

	d = std::string(delta_r);

	return 0;
}


int MigrateStateLocal::copyBundles()
{
	std::map<std::string, bundle>::const_iterator itb;
	struct string_list exclude;
	int rc = 0;

	START_STAGE();
	string_list_init(&exclude);

	// copy bundles
	for (itb = bundles.begin(); itb != bundles.end(); ++itb) {
		const struct bundle &b = itb->second;
		std::vector<std::string>::const_iterator it;

		for (it = b.disks.begin(); it != b.disks.end(); ++it) {
			std::string delta;
			// add descriptor
			string_list_add_str(&exclude, get_dd_xml(*it));
			// add delta
			if (srcVE->isrun()) {
				// get delta relative to bundle
				rc = get_active_delta(combine_path(b.src, *it), b.src, delta);
				if (rc)
					goto exit;
				string_list_add_str(&exclude, delta);
			}
		}
		// Add .running file to list of excludes
		string_list_add_str(&exclude, VE_RUNNING_FILE);
		rc = copy_local(rsync_dir(b.src), b.dst, &exclude);
		if (rc)
			goto exit;
		string_list_clean(&exclude);
	}

exit:
	string_list_clean(&exclude);
	END_STAGE();
	return rc;
}

int MigrateStateLocal::copyUnbundledDisks()
{
	std::vector<external_disk_path>::const_iterator i;
	struct string_list exclude;
	int rc = 0;

	START_STAGE();
	string_list_init(&exclude);

	// copy unbundled disks
	for (i = unb_disks.begin(); i != unb_disks.end(); ++i) {
		std::string delta;
		// add descriptor
		string_list_add_str(&exclude, DISKDESCRIPTOR_XML);
		// add delta
		if (srcVE->isrun()) {
			// get delta relative to disk
			rc = get_active_delta(i->src_path(), i->src_path(), delta);
			if (rc)
				goto exit;
			string_list_add_str(&exclude, delta);
		}
		rc = copy_local(rsync_dir(i->src_path()), i->dst_path(), &exclude);
		if (rc)
			goto exit;
		string_list_clean(&exclude);
	}


exit:
	string_list_clean(&exclude);
	END_STAGE();
	return rc;
}

/*
   clone of running ploop-based ct
   - copy DiskDescriptor.xml to target
   - create snapshot on source
   - copy private exclude DiskDescriptor.xml, active delta and link to base image
   - register target ct
   - merge snapshot on source
*/
int MigrateStateLocal::ploopCtClone()
{
	int rc = 0;

	rc = copyDiskDescriptors();
	if (rc)
		goto err;

	if (srcVE->isrun()) {
		rc = srcVE->tsnapshot(srcVE->gen_snap_guid());
		if (rc)
			goto err;

		addCleaner(clean_deleteSnapshot, srcVE,	srcVE->snap_guid(), ANY_CLEANER);
	}

	rc = copyBundles();
	if (rc)
		goto err;
	rc = copyUnbundledDisks();
err:
	return rc;
}

static bool disk_is_internal(const struct disk_entry &d)
{
	return !d.is_external();
}

/*
create snapshot
copy private area exclude active delta and link to base image
vzctl suspend 5002
copy active delta
vzctl2_env_register(/vz/private/test5002, 5002, 1)
vzctl restore 5002
merge snapshot
*/
int MigrateStateLocal::ploopCtMove()
{
	int rc = 0;
	struct string_list exclude;
	char path[PATH_MAX];
	std::map<std::string, bundle>::const_iterator itb;
	bool run = srcVE->isrun();

	string_list_init(&exclude);

	if (is_thesame_private) {
		if (run)
			rc = stopVE();
		return rc;
	}

	if (!is_thesame_location) {
		if (run) {
			/* suspend CT on SRC */
			srcVE->dumpfile = dstVE->dumpfile =
				std::string(srcVE->priv) + std::string("/dump/Dump");
			// #TODO snapshot only internal disks
			rc = srcVE->tsnapshot(srcVE->gen_snap_guid());
			if (rc)
				goto err;
			addCleaner(clean_deleteSnapshot, srcVE,
					srcVE->snap_guid(), ERROR_CLEANER);

			rc = getActivePloopDelta(srcVE->m_disks.
					get(disk_is_internal), &exclude);
			if (rc)
				goto err;
		}

		rc = copy_local(rsync_dir(srcVE->priv).c_str(),
				dstVE->priv, &exclude);
		if (rc)
			goto err;
	}

	/* suspend CT */
	if (run && (rc = stopVE()))
		goto err;

	if ((rc = h_backup(srcVE->confRealPath().c_str())))
		goto err;

	if (is_thesame_location) {
		logger(LOG_ERR, "Move %s %s", srcVE->priv, dstVE->priv);
		addCleaner(clean_register, srcVE);
		rc = h_rename(srcVE->priv, dstVE->priv);
		if (rc)
			goto err;
	} else if (run) {
		struct string_list_el *e;
		char dst[PATH_MAX];

		/* copy active delta */
		string_list_for_each(&exclude, e) {
			char *tmp = strdupa(e->s);

			snprintf(path, sizeof(path), "%s/%s", srcVE->priv, e->s);
			snprintf(dst, sizeof(dst), "%s/%s", dstVE->priv, dirname(tmp));

			rc = copy_local(path, dst, NULL);
			if (rc)
				goto err;
		}

		// #TODO umount instead
		srcVE->tsnapshot_delete(srcVE->snap_guid());
	}

	// rename bundles
	for (itb = bundles.begin(); itb != bundles.end(); ++itb) {
		const struct bundle &b = itb->second;
		// main bundle is handled above
		if (b.src == srcVE->priv)
			continue;
		rc = h_rename(b.src.c_str(), b.dst.c_str());
		if (rc)
			goto err;
	}

err:
	return rc;
}

bool MigrateStateLocal::isSameLocation()
{
	return is_thesame_location;
}

/* unused function */
#if 0
static int vzml_execve2(const std::list<std::string> &args)
{
	string_list a;
	int rc;

	string_list_init(&a);
	for (std::list<std::string>::const_iterator i = args.begin(); i != args.end(); ++i)
		string_list_add(&a, i->c_str());

	rc = vzml_execve(&a, NULL, -1, -1, 0);

	string_list_clean(&a);
	return rc;
}
#endif
