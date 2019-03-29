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
#include <libio.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <libgen.h>
#include <sstream>

#include <vzctl/libvzctl.h>
#include <ploop/libploop.h>

#ifdef FIU_ENABLE
#include <fiu.h>
#endif

#include "bincom.h"
#include "migratecom.h"
#include "util.h"
#include "veentry.h"

extern struct vz_data *vzcnf;

// VE action scripts to copy
const char * actionScripts[] =
    {"mount", "umount", "start", "stop", NULL
    };

bool disk_is_shared(const disk_entry &d)
{
	return d.is_shared();
}

bool disk_is_shared_not_device(const disk_entry &d)
{
	return d.is_shared() && !d.is_device();
}

bool disk_is_secondary(const disk_entry &d)
{
	return d.is_secondary();
}

bool disk_is_secondary_or_device(const disk_entry &d)
{
	return d.is_device() || d.is_secondary();
}

VEObj::VEObj(const char *ctid) :
	lock_fd(-1), root(NULL), priv(NULL),
	priv_custom(false), layout(VZCTL_LAYOUT_5)
{
	SET_CTID(m_ctid, ctid);
}

VEObj::~VEObj()
{
	unlock();
}

#define SUSPEND_DIR "dump"

int VEObj::init_existed()
{
	int rc;

	if (EMPTY_CTID(ctid())) {
		rc = ve_data_load_by_conf(confRealPath().c_str(), &ve_data);
		if (rc)
			return rc;
	} else {
		vzctl_env_status_t env_status;

		if (vzctl2_get_env_status(ctid(), &env_status, ENV_STATUS_ALL))
			return putErr(MIG_ERR_SYSTEM, MIG_MSG_NOSTATUS);

		if (!(env_status.mask & ENV_STATUS_EXISTS))
			return putErr(MIG_ERR_NOEXIST, MIG_MSG_NOEXIST, ctid());

		/* TODO: move to upper level */
		if (isOptSet(OPT_COPY) && (env_status.mask & ENV_STATUS_SUSPENDED))
			return putErr(MIG_ERR_SUSPEND, MIG_MSG_CLONE_FORBIDDEN_FOR_SUSPENDED);
		rc = ve_data_load(ctid(), &ve_data);
		if (rc)
			return rc;
	}

	root = ve_data.root;
	priv = ve_data.priv;

	/* get VELAYOUT version */
	layout = vzctl2_env_layout_version((char *)priv);

	if (layout >= VZCTL_LAYOUT_5) {
		init_disks(ve_data);
	}

	/* get veformat */
	if ((veformat = vzctl2_get_veformat(priv)) == -1) {
		return putErr(MIG_ERR_VZCTL, "vzctl2_get_veformat(%s): %s",
			priv, vzctl2_get_last_error());
	}

	return 0;
}

/* get real VE config file path */
string VEObj::confRealPath() const
{
	std::ostringstream os;

	if (layout < VZCTL_LAYOUT_4)
		os << VE_CONF_DIR << ctid() << ".conf";
	else
		os << priv << "/ve.conf";

	return os.str();
}

/* get VE VZFS directory */
const string VEObj::getVEPrivateVZFS()
{
	string vzfs_dir;

	if (!priv)
		return "";
	vzfs_dir = priv;
	if (layout >= VZCTL_LAYOUT_4)
		vzfs_dir += "/fs";

	return vzfs_dir;
}

string VEObj::confPath() const
{
	std::ostringstream os;

	os << VE_CONF_DIR << ctid() << ".conf";
	return os.str();
}

string VEObj::dumpDir() const
{
	return vzcnf->dumpdir;
}

string VEObj::tmplDir() const
{
	return std::string(vzcnf->tmpldir);
}

void VEObj::setPrivate(const char *p)
{
	free((void*)priv);
	priv = subst_CTID(ctid(), p);
}

bool VEObj::isCustomPrivate() const
{
	return strcmp(priv, vzcnf->priv_orig) != 0;
}

void VEObj::setRoot(const char *p)
{
	free((void*)root);
	root = subst_CTID(ctid(), p);
}

std::string VEObj::getPrivateConf()
{
	return subst_VEID_back(ctid(), priv);
}

std::string VEObj::getRootConf()
{
	return subst_VEID_back(ctid(), root);
}

int VEObj::prepareConfig()
{
	int rc;

	if ((rc = updateConfig(VE_CONF_NAME, NULL)))
		return rc;
	if ((rc = updateConfig(VE_CONF_PRIV, getPrivateConf().c_str())))
		return rc;
	if ((rc = updateConfig(VE_CONF_ROOT, getRootConf().c_str())))
		return rc;

	return 0;
}

static bool isExternalBindmount(const std::string &bstr)
{
	return bstr.find(":") != std::string::npos;
}

bool VEObj::findInBindmounts(bool (*func)(const std::string &bstr))
{
	if (ve_data.bindmount == NULL)
		return false;

	istringstream is(ve_data.bindmount, istringstream::in);

	string b;
	while (getline(is, b, ' ')) {
		if (func(b))
			return true;
	}
	return false;
}

int VEObj::hasExternalBindmounts()
{
	return findInBindmounts(isExternalBindmount);
}

std::string VEObj::templatePath() const
{
	std::ostringstream os;

	os << priv << "/templates";

	return os.str();
}

std::string VEObj::bindmountPath() const
{
	std::ostringstream os;

	os << root << VE_PLOOP_BINDMOUNT_DIR;

	return os.str();
}

/* get file name for VE script */
const string VEObj::scriptPath(const char * action)
{
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s/scripts/%s", priv, action);

	return path;
}

unsigned long VEObj::checkTechnologies(unsigned long *tech_mask)
{
	return vzctl2_check_tech(*tech_mask);
}

const char *VEObj::gen_snap_guid()
{
	char guid[39];

	ploop_uuid_generate(guid, sizeof(guid));

	m_snap_guid = guid;

	return snap_guid();
}

/* read interfaces list */
static int read_iflist(struct string_list *iflist)
{
	char buf[BUFSIZ];
	const char *cmd = "netstat -i";
	FILE *fd;
	int rc, status, retcode;
	char *p;
	const char *header = "Iface";

	logger(LOG_DEBUG, cmd);
	if ((fd = popen(cmd, "r")) == NULL)
		return putErr(MIG_ERR_SYSTEM, "popen('%s') : %m", cmd);

	/* skip header till 'Iface' */
	while(fgets(buf, sizeof(buf), fd)) {
		if (strncasecmp(header, buf, strlen(header)) == 0)
			break;
	}
	while(fgets(buf, sizeof(buf), fd)) {
		if ((p = strchr(buf, ' ')) == NULL)
			continue;
		*p = '\0';
		if ((rc = string_list_add(iflist, buf)))
			break;
	}
	status = pclose(fd);
	if (rc)
		return rc;
	if (WIFEXITED(status)) {
		if ((retcode = WEXITSTATUS(status))) {
			return putErr(MIG_ERR_SYSTEM,
				"'%s' return %d", cmd, retcode);
		}
	} else if (WIFSIGNALED(status)) {
		return putErr(MIG_ERR_SYSTEM,
			"'%s' got signal %d", cmd, WTERMSIG(status));
	} else {
		return putErr(MIG_ERR_SYSTEM,
			"'%s' exited with status %d", cmd, status);
	}

	return 0;
}

/* read network class id list */
static int read_idlist(struct string_list *idlist)
{
	int rc;
	char buf[BUFSIZ];
	const char *fname = "/etc/vz/conf/networks_classes";
	FILE *fd;
	char *p, *str;

	if ((fd = fopen(fname, "r")) == NULL)
		return putErr(MIG_ERR_SYSTEM, "fopen('%s') : %m", fname);

	while(fgets(buf, sizeof(buf), fd)) {
		/* remove leading spaces */
		p = buf;
		while (*p && isspace(*p))
			p++;
		str = p;
		/* skip comments */
	        if (*str == '#')
			continue;
		if ((p = strchr(str, ' ')) == NULL)
			continue;
		*p = '\0';
		if ((rc = string_list_add(idlist, str)))
			break;
	}
	fclose(fd);
	return rc;
}

/* check target VE RATE on destination node */
int check_rate(struct string_list *rate)
{
	int rc = 0;
	struct string_list_el *r;
	char *str, *p, *dev, *id;
	struct string_list iflist;
	struct string_list idlist;

	logger(LOG_DEBUG, "check rate");

	string_list_init(&iflist);
	string_list_init(&idlist);
	if ((rc = read_iflist(&iflist)))
		return rc;
	if ((rc = read_idlist(&idlist)))
		return rc;

	string_list_for_each(rate, r) {
		/* parse rate record */
		if ((str = strdup(r->s)) == NULL)
			return putErr(MIG_ERR_SYSTEM, MIG_MSG_SYSTEM);
		dev = str;
		if ((p = strchr(str, ':')) == NULL) {
			rc = putErr(MIG_ERR_RATE, "invalid rate : %s", r->s);
			goto cleanup;
		}
		*p = '\0';
		id = p + 1;
		if ((p = strchr(id, ':')) == NULL) {
			rc = putErr(MIG_ERR_RATE, "invalid rate : %s", r->s);
			goto cleanup;
		}
		*p = '\0';

		/* check interface */
		if (strcmp(dev, "*")) {
			if (string_list_find(&iflist, dev) == NULL) {
				rc = putErr(MIG_ERR_RATE,
					"rate device %s not found", dev);
				goto cleanup;
			}
		}

		/* check class id */
		if (strcmp(id, "*")) {
			if (string_list_find(&idlist, id) == NULL) {
				rc = putErr(MIG_ERR_RATE,
					"rate class %s not found", id);
				goto cleanup;
			}
		}
cleanup:
		free((void *)str);
		if (rc)
			break;
	}
	string_list_clean(&idlist);
	string_list_clean(&iflist);
	return rc;
}

/* get VE status */
int VEObj::getStatus(int status, int *out)
{
	vzctl_env_status_t ve_status;

	if (EMPTY_CTID(ctid()))
		return 0;

	if (vzctl2_get_env_status(m_ctid, &ve_status, status | ENV_SKIP_OWNER))
		return putErr(MIG_ERR_VZCTL,
			"vzctl2_get_env_status(%s) : %s", m_ctid, vzctl2_get_last_error());

	*out = ve_status.mask;
	return 0;
}

int VEObj::isexist()
{
	int status;

	if (getStatus(ENV_STATUS_EXISTS, &status))
		return 0;
	return status & ENV_STATUS_EXISTS;
}

int VEObj::isrun()
{
	int status;

	if (EMPTY_CTID(ctid()))
		return 0;

	if (getStatus(ENV_STATUS_RUNNING, &status))
		return 0;
	return status & ENV_STATUS_RUNNING;
}

int VEObj::ismount()
{
	int status;

	if (getStatus(ENV_STATUS_MOUNTED, &status))
		return 0;
	return status & ENV_STATUS_MOUNTED;
}

int VEObj::issuspended()
{
	int status;

	if (getStatus(ENV_STATUS_SUSPENDED, &status))
		return 0;
	return status & ENV_STATUS_SUSPENDED;
}

static const char *get_lock_status()
{
	if (VZMoptions.bintype != BIN_LOCAL)
		return VZCTL_TRANSITION_MIGRATING;

	return isOptSet(OPT_COPY) ? "cloning" : "moving";
}

int VEObj::lock()
{
	if (isOptSet(OPT_SKIP_LOCKVE))
		return 0;

	logger(LOG_ERR, "locking %s", ctid());

	lock_fd = vzctl2_env_lock_prvt(ctid(), priv, get_lock_status());
	if (lock_fd  == -2)
		return putErr(MIG_ERR_LOCK, MIG_MSG_LOCK,
			ctid(), "CT locked");
	else if (lock_fd < 0)
		return putErr(MIG_ERR_LOCK, MIG_MSG_LOCK,
			ctid(), vzctl2_get_last_error());

	return 0;
}

void VEObj::unlock()
{
	if (!islocked())
		return;

	logger(LOG_ERR, "unlocking %s", ctid());
	vzctl2_env_unlock_prvt(ctid(), lock_fd, priv);
	lock_fd = -1;
}

int VEObj::islocked()
{
	return lock_fd >= 0;
}

int VEObj::start()
{
	return operateVE("start", "Starting", NULL, 0);
}

int VEObj::stop(bool skip_umount)
{
	/* will use --force option with --skip-umount only
	   https://jira.sw.ru/browse/PSBM-23178 */
	const char * opt[] = { "--skip-umount", "--force", NULL };
	return operateVE("stop", "Stopping", skip_umount ? opt : NULL, 0);
}

int VEObj::kill()
{
	const char * opt[] = { "--fast", NULL };

	return operateVE("stop", "Stopping", opt, 0);
}
int VEObj::mount()
{
	return operateVE("mount", "Mounting", NULL, 0);
}

int VEObj::umount()
{
	if (!ismount())
		return 0;
	return operateVE("umount", "Umounting", NULL, 0);
}

/* to destroy VE */
int VEObj::destroy()
{
	int rc;
	vzctl_env_status_t ve_status;

	/* get VE status */
	if (vzctl2_get_env_status(ctid(), &ve_status, ENV_STATUS_ALL))
		putErr(MIG_ERR_VZCTL, "Cannot get status for CT %s", ctid());

	if (ve_status.mask & ENV_STATUS_RUNNING) {
		if ((rc = operateVE("stop", NULL, NULL, 0)))
			return rc;
	} else if (ve_status.mask & ENV_STATUS_MOUNTED) {
		if ((rc = operateVE("umount", NULL, NULL, 0)))
			return rc;
	}

	return operateVE("destroy", NULL, NULL, 1);
}

int VEObj::tsnapshot(const char *guid)
{
	const char *opt[] = {
		"--uuid", guid, "--component-name", VZMIGRATE_COMPONENT_NAME, NULL
	};
	logger(LOG_DEBUG, "Createing tsnapshot %s", guid);
	return operateVE("tsnapshot", "Snapshoting", opt, 0);
}

int VEObj::tsnapshot_delete(const char *guid)
{
	const char *opt[] = {"--uuid", guid, NULL};

	return operateVE("tsnapshot-delete", "Deleting snapshot", opt, 0);
}

int VEObj::cmd_suspend()
{
	return operateVE("suspend", "Suspending", NULL, 0);
}

int VEObj::cmd_restore()
{
	const char *opt[] = {!dumpfile.empty() ? "--dumpfile" : NULL,
		dumpfile.c_str(), NULL};

	return operateVE("restore", "Restoring", opt, 0);
}

int VEObj::unSet(const char *param)
{
	char buf[PATH_MAX];
	const char * opt[] = { buf, "--save", NULL };

	snprintf(buf, sizeof(buf), "--%s", param);
	return operateVE("unset", "Unset", opt, 0);
}

int VEObj::operateVE(const char * func, const char * action,
		const char ** options, int quiet)
{
	int rc, i;
	string_list argv;

	if (action && !quiet)
		logger(LOG_INFO, "%s CT %s ...", action, ctid());

	string_list_init(&argv);
	string_list_add(&argv, BIN_VZCTL);
	if (quiet)
		string_list_add(&argv, "--quiet");
	string_list_add(&argv, "--skiplock");
	string_list_add(&argv, "--skipowner");
	string_list_add(&argv, "--ignore-ha-cluster");
	string_list_add(&argv, (char *)func);
	string_list_add(&argv, ctid());
	if (options) {
		for (i = 0; options[i]; i++)
			string_list_add(&argv, (char *)options[i]);
	}

	rc = vzml_execve(&argv, NULL, -1, -1, quiet);

	string_list_clean(&argv);

	if (action && (rc == 0) && !quiet)
		logger(LOG_INFO, "done");

	return rc;
}

void VEObj::clean()
{
	int i;
	string path;
	for (i = 0; actionScripts[i]; i++) {
		path = scriptPath(actionScripts[i]);
		unlink(path.c_str());
	}

	// clean config
	::unlink(confPath().c_str());
}

/* For new layout only
   After rsync we have 2 config on destination node:
   valid, in /etc/ and invalid (rsynced), in private area.
   Rewrote config in private by valid config content, remove
   config from etc and 'register' VE.
*/
int VEObj::veRegister(const char *uuid)
{
	int rc;
	char tmpfile[PATH_MAX + 1];
	struct stat st;

	tmpfile[0] = 0;
	if (stat(confRealPath().c_str(), &st) == 0) {
		/* to save origin config (https://jira.sw.ru/browse/PSBM-10260) */
		snprintf(tmpfile, sizeof(tmpfile), "%s.XXXXXX", confRealPath().c_str());
		mktemp(tmpfile);
		if (rename(confRealPath().c_str(), tmpfile))
			return putErr(MIG_ERR_SYSTEM, "rename(%s, %s) : %m", confRealPath().c_str(), tmpfile);
	}

	/* rewrite private config */
	if ((rc = move_file(confRealPath().c_str(), confPath().c_str()))) {
		if (tmpfile[0])
			rename(tmpfile, confRealPath().c_str());
		return rc;
	}
	if (tmpfile[0])
		unlink(tmpfile);

	/* vzctl register for new layout VE */
	return registration(uuid);
}

int VEObj::registration(const char *uuid)
{
	// will rewrite old owner on force registration
	// vzmigrate will itself to register CT on HA cluster
	int flags = VZ_REG_RENEW | VZ_REG_FORCE | VZ_REG_SKIP_HA_CLUSTER |
			VZ_REG_RENEW_NETIF_IFNAME;

	struct vzctl_reg_param reg;
	memset(&reg, 0, sizeof(struct vzctl_reg_param));
	SET_CTID(reg.ctid, ctid());
	reg.uuid = uuid;
	reg.name = ve_data.name;

	logger(LOG_DEBUG, "vzctl2_env_register(%s ctid='%s' uuid='%s' name='%s' %d)",
			priv, ctid(), uuid?: "", ve_data.name ?: "", flags);

	if (vzctl2_env_register((char *)priv, &reg, flags) == -1)
		return putErr(MIG_ERR_VZCTL,
			"vzctl2_env_register(%s, %s, %d) error: %s",
			priv, ctid(), flags, vzctl2_get_last_error());
	return 0;
}

int VEObj::unregister()
{
	// do not remove VEID on force unregister
	// vzmigrate will itself to unregister CT on HA cluster
	int flags = VZ_REG_FORCE | VZ_UNREG_PRESERVE | VZ_REG_SKIP_HA_CLUSTER;
	logger(LOG_DEBUG, "vzctl2_env_unregister(%s, %s, %d)",
			priv, ctid(), VZ_REG_FORCE);
	if (vzctl2_env_unregister((char *)priv, ctid(), flags) == -1)
		return putErr(MIG_ERR_VZCTL,
			"vzctl2_env_unregister(%s, %s, %d) error: %s",
			priv, ctid(), VZ_REG_FORCE, vzctl2_get_last_error());
	return 0;
}

int VEObj::createDevmap()
{
	const char *opt[] = { "--create-devmap", NULL };
	if (operateVE("suspend", "Create devmap", opt, 1))
		return putErr(MIG_ERR_VZCTL, MIG_MSG_CREATE_DEVMAP, ctid());
	return 0;
}

/* exec post create VE action: randomize cron too */
int VEObj::ExecPostCreate()
{
	const char * args[] = { "POST_CREATE", NULL };
	return operateVE("execaction", "ExecAction", args, 0);
}

/* vpsd is PVA process, executes in CT context via 'vzctl exec'
 * will kill */
int VEObj::stopVpsd()
{
	char path[PATH_MAX + 1];
	FILE *fp;
	pid_t pid;
	char buf[PATH_MAX + 1];
	char *p;
	const char * args[] = { buf, NULL };
	int tries;

	if (!isrun())
		return 0;

	snprintf(path, sizeof(path), "%s/var/run/vpsd.pid", root);
	if ((fp = fopen(path, "r")) == NULL)
		return 0;
	if (fgets(buf, sizeof(buf), fp) == NULL) {
		fclose(fp);
		return 0;
	}
	fclose(fp);
	if ((p = strchr(buf, '\n')))
		*p = '\0';
	pid = atol(buf);
	snprintf(path, sizeof(path), "%s/proc/%d", root, pid);
	if (access(path, F_OK))
		return 0;

	snprintf(buf, sizeof(buf), "kill -TERM %d", pid);
	for (tries = 0; tries < 10; ++tries) {
		operateVE("exec", "Exec", args, 0);
		sleep(1);
		if (access(path, F_OK))
			return 0;
	}
	return putErr(MIG_ERR_SYSTEM, "Can't stop vpsd in CT %s", ctid());
}

int VEObj::createLayout()
{
	char path[PATH_MAX];
	char lnk[PATH_MAX];
	struct stat st;

	if (layout == VZCTL_LAYOUT_3) {
		return putErr(MIG_ERR_SYSTEM, "Can't create layout 3");

	} else if (layout == VZCTL_LAYOUT_4) {
		return putErr(MIG_ERR_SYSTEM, "Can't create layout 4");

	} else if (layout == VZCTL_LAYOUT_5) {
		snprintf(path, sizeof(path), "%s/fs", priv);
		if (access(path, F_OK))
			if (mkdir(path, 0755))
				return putErr(MIG_ERR_SYSTEM, "mkdir(%s) : %m", path);
		snprintf(path, sizeof(path), "%s/root.hdd", priv);
		if (access(path, F_OK))
			if (mkdir(path, 0755))
				return putErr(MIG_ERR_SYSTEM, "mkdir(%s) : %m", path);
		snprintf(path, sizeof(path), "%s/root.hdd/templates", priv);
		if (access(path, F_OK))
			if (mkdir(path, 0755))
				return putErr(MIG_ERR_SYSTEM, "mkdir(%s) : %m", path);
		/* Create compatible symlink templates -> root.hdd/templates */
		snprintf(path, sizeof(path), "%s/templates", priv);
		snprintf(lnk, sizeof(lnk), "root.hdd/templates");
		if (lstat(path, &st))
			if (symlink(lnk, path))
				return putErr(MIG_ERR_SYSTEM, "symlink(%s, %s) : %m", lnk, path);
		snprintf(path, sizeof(path), "%s/" SUSPEND_DIR, priv);
		if (access(path, F_OK))
			if (mkdir(path, 0755))
				return putErr(MIG_ERR_SYSTEM, "mkdir(%s) : %m", path);
	}

	snprintf(path, sizeof(path), "%s/.ve.layout", priv);
	snprintf(lnk, sizeof(lnk), "%d", layout);

	if (symlink(lnk, path) && errno != EEXIST)
		return putErr(MIG_ERR_SYSTEM, "symlink(%s, %s) : %m", lnk, path);

	/* also create dump subdirectory (https://jira.sw.ru/browse/PCLIN-29204) */
	snprintf(path, sizeof(path), "%s/dump", priv);
	if (access(path, F_OK))
		if (mkdir(path, 0755))
			return putErr(MIG_ERR_SYSTEM, "mkdir(%s) : %m", path);
	return 0;
}

bool VEObj::isNewTemOS()
{
	if (ve_data.ostemplate && *ve_data.ostemplate == '.')
		return true;
	return false;
}

void VEObj::setNameData(const char *name)
{
	free(ve_data.name);
	if (name)
		ve_data.name = strdup(name);
	else
		ve_data.name = NULL;
}

/* vzmdest.cpp and vzmlocal.cpp */
int VEObj::init_empty()
{
	if (!priv)
		setPrivate(vzcnf->priv_orig);
	if (!root)
		setRoot(vzcnf->root_orig);

	if (priv == NULL && root == NULL)
		return putErr(MIG_ERR_SYSTEM, MIG_MSG_SYSTEM);

	return 0;
}

void VEObj::init_disks(const struct ve_data& data)
{
	this->ve_data.disks = data.disks;
	this->ve_data.ext_disks = data.ext_disks;
	this->ve_data.np_disks = data.np_disks;

	m_disks.clear();

	for (std::list<ve_disk_data>::const_iterator it = data.disks.begin();
		it != data.disks.end(); ++it) {
		m_disks.push_back(disk_entry(*it));
	}

	for (std::list<ve_disk_data>::const_iterator it = data.ext_disks.begin();
		it != data.ext_disks.end(); ++it) {
		m_disks.push_back(disk_entry(*it, true));
	}

	for (std::list<ve_disk_data>::const_iterator it = data.np_disks.begin();
		it != data.np_disks.end(); ++it) {
		m_disks.push_back(disk_entry(*it, true, false));
	}

	for (std::list<ve_disk_data>::const_iterator it = data.dev_disks.begin();
			it != data.dev_disks.end(); ++it) {
		m_disks.push_back(disk_entry(*it, true, true, true));
	}
}

/* set layout for new VE */
void VEObj::setLayout(int new_layout)
{
	layout = new_layout;
}

int VEObj::loadConfig()
{
	return ve_data_load(m_ctid, &ve_data);
}

/* save new ve_private & ve_root in config */
int VEObj::updateConfig(const char *param, const char *data)
{
	int err, rc = 0;
	struct vzctl_config *cfg;

	cfg = vzctl2_conf_open(confPath().c_str(), VZCTL_CONF_SKIP_GLOBAL, &err);
	if (err)
		return putErr(MIG_ERR_VZCTL, "vzctl2_conf_open(%s) error: %s",
			confPath().c_str(), vzctl2_get_last_error());

	if (vzctl2_conf_set_param(cfg, param, data)){
		rc = putErr(MIG_ERR_VZCTL, "vzctl2_conf_set_param(%s) error: %s",
				param, vzctl2_get_last_error());
		goto cleanup;
	}

	if (vzctl2_conf_save(cfg, confPath().c_str())) {
		rc = putErr(MIG_ERR_VZCTL, "vzctl2_conf_save() error: %s",
			vzctl2_get_last_error());
		goto cleanup;
	}
cleanup:
	vzctl2_conf_close(cfg);

	return rc;
}

/* check that this name does not used by other VE */
int VEObj::checkName(const char *name)
{
	ctid_t tmpCtid;
	int rc;

	if (name == NULL)
		return 0;

	rc = vzctl2_get_envid_by_name(name, tmpCtid);
	/* it may be our name */
	if ((rc == 0) && (CMP_CTID(tmpCtid, ctid()) != 0))
		return putErr(MIG_ERR_NAME_CONFLICT,
			MIG_MSG_NAME_CONFLICT, name, tmpCtid);
	return 0;
}

/* set VE name */
int VEObj::setName(char const *name)
{
	char * const envp[] =
		{(char *)"LANG=en_US.UTF-8", NULL
		};
	char * const args[] =
		{
		(char *)BIN_VZCTL, (char *)"--skiplock", (char *)"set", m_ctid,
		(char *)"--name", (char *)name, (char *)"--save", NULL
		};

	if (name == NULL)
		return 0;

	logger(LOG_DEBUG, "change dst CT NAME");
	return vzm_execve(args, envp, -1, -1, NULL);
}

int VEObj::renewMAC()
{
	char * const args[] =
		{(char *)BIN_VZCTL, (char *)"--skiplock", (char *)"set",
		m_ctid, (char *)"--netif_mac_renew", (char *)"--save", NULL};
	return vzm_execve(args, NULL, -1, -1, NULL);
}

static
int ploop_get_spec_path(const char *dd_path, struct ploop_spec *spec)
{
	struct ploop_disk_images_data *di;
	int rc;

	if ((rc = ploop_open_dd(&di, dd_path))) {
		return putErr(MIG_ERR_PLOOP, "ploop_read_diskdescriptor(%s) : %s [%d]",
				dd_path, ploop_get_last_error(), rc);
	;
	}
	memset((void *)spec, 0, sizeof(*spec));
	if ((rc = ploop_get_spec(di, spec))) {
		rc = putErr(MIG_ERR_PLOOP,
			"ploop_get_spec() : %s [%d]", ploop_get_last_error(), rc);
		goto cleanup;
	}

cleanup:
	if (di != NULL)
		ploop_close_dd(di);

	return rc;
}

int VEObj::getPloopMaxVersion(int &version)
{
	int rc = 0;
	struct ploop_spec spec;

	version = 0;
	for (ct_disk::const_iterator it = m_disks.begin(); it != m_disks.end(); ++it) {
		if (it->is_device())
			continue;

		if ((rc = ploop_get_spec_path(get_dd_xml(it->image.c_str()).c_str(), &spec)))
			break;

		if (spec.fmt_version > version)
			version = spec.fmt_version;
	}

	return rc;
}

static string & chomp(string & str, const char * dlm)
{
	string::size_type it = str.find_last_not_of(dlm);
	if (it == str.npos)
		str.erase();
	else
		str.erase(it+1);
	return str;
}

static int isConcurrentDirs(const string & dirA, const string & dirB)
{
	string A = dirA;
	string B = dirB;
	chomp(A, "/");
	chomp(B, "/");
	return A == B
	       || (!strncmp(A.c_str(), B.c_str(), A.length()) && B[A.length()] == '/')
	       || (!strncmp(A.c_str(), B.c_str(), B.length()) && A[B.length()] == '/');
}

// < 0 - some errors
// 0 - directory was created
// 1 - directory exists
int checkVEDir(const char * vedir, int unique)
{
	int rc = 0;
	int cnt, i;
	vzctl_ids_t *ctids;
	char path[PATH_MAX + 1];

	if (access(vedir, F_OK) == 0) {
		if (unique)
			return putErr(MIG_ERR_EXISTS, MIG_MSG_AREA_EXISTS, vedir);
	} else {
		return make_dir(vedir, DEF_DIR_MODE);
	}

	/* check that another VE, doesn't use this dir */
	if ((ctids = vzctl2_alloc_env_ids()) == NULL)
		return putErr(MIG_ERR_VZCTL, "vzctl2_alloc_env_ids(): %s",
			vzctl2_get_last_error());

	if ((cnt = vzctl2_get_env_ids_by_state(ctids, ENV_STATUS_EXISTS)) < 0)
		return putErr(MIG_ERR_VZCTL, "vzctl2_get_env_ids_by_state(): %s",
			vzctl2_get_last_error());

	for (i = 0; i < cnt; i++) {
		struct vzctl_env_handle *h;
		int err;
		const char *data;

		if (EMPTY_CTID(ctids->ids[i]))
			continue;

		vzctl2_get_env_conf_path(ctids->ids[i], path, sizeof(path));
		h = vzctl2_env_open(ctids->ids[i],
			VZCTL_CONF_SKIP_GLOBAL | VZCTL_CONF_BASE_SET | VZCTL_CONF_SKIP_PARAM_ERRORS, &err);
		if (err) {
			logger(LOG_ERR, "vzctl2_env_open(%s) error: %s",
				path, vzctl2_get_last_error());
			continue;
		}

		// check that existed directories is not parent or equal
		// directories for VE
		if (vzctl2_env_get_ve_root_path(vzctl2_get_env_param(h), &data) == 0 &&
				isConcurrentDirs(vedir, data))
			rc = putErr(MIG_ERR_EXISTS, MIG_MSG_AREA_USED, vedir, ctids->ids[i]);

		if (vzctl2_env_get_ve_private_path(vzctl2_get_env_param(h), &data) == 0 &&
				isConcurrentDirs(vedir, data))
			rc = putErr(MIG_ERR_EXISTS, MIG_MSG_AREA_USED, vedir, ctids->ids[i]);

		vzctl2_env_close(h);
		if (rc)
			break;
	}
	vzctl2_free_env_ids(ctids);
	if (rc)
		return rc;
	return 1;
}

/* 0 - ipadd, 1 - ipdel*/
static int ipset(const char *ctid, const char *cmd, struct string_list *iplist)
{
	int rc;
	struct string_list argv;
	struct string_list_el *p;

	if (string_list_empty(iplist))
		return 0;

	string_list_init(&argv);

	string_list_add(&argv, BIN_VZCTL);
	string_list_add(&argv, "--skiplock");
	string_list_add(&argv, "--skipowner");
	string_list_add(&argv, "set");
	string_list_add(&argv, ctid);

	string_list_for_each(iplist, p) {
		string_list_add(&argv, cmd);
		string_list_add(&argv, p->s);
	}

	logger(LOG_DEBUG, "Set CT IP addresses");
	if ((rc = vzml_execve(&argv, NULL, -1, -1, 0)))
		logger(LOG_ERR, "Can't set IPs for CT %s", ctid);

	string_list_clean(&argv);

	return rc;
}

int exchangeIPs(VEObj &k, VEObj &v)
{
	int rc;

	if ((rc = ipset(v.ctid(), "--ipdel", &v.ve_data.ipaddr)))
		return rc;

	if ((rc = ipset(k.ctid(), "--ipadd", &v.ve_data.ipaddr))) {
		// attempt to restore
		if (ipset(v.ctid(), "--ipadd", &v.ve_data.ipaddr))
			logger(LOG_WARNING, "can't restore CT %s IP addresses", v.ctid());
		return rc;
	}

	return 0;
}

int restoreIPs(VEObj &k, VEObj &v)
{
	// we only should delete IPs from keeper VE
	// 'cause adding IPs to srcVE will happen on the stage of VE start
	return ipset(k.ctid(), "--ipdel", &v.ve_data.ipaddr);
}

int rollbackIPs(VEObj &k, VEObj &v)
{
	int rc;

	rc = ipset(k.ctid(), "--ipdel", &v.ve_data.ipaddr);
	if (rc != 0)
		return rc;

	rc = ipset(v.ctid(), "--ipadd", &v.ve_data.ipaddr);
	if (rc != 0)
		return rc;

	return 0;
}

/* replace $VEID to ctid in string */
char *subst_CTID(const char *ctid, const char *src)
{
	const char *VEID_STR1 = "$VEID";
	const char *VEID_STR2 = "${VEID}";

	if (src == NULL)
		return NULL;

	std::string res(src);
	size_t pos;
	if ((pos = res.find(VEID_STR1)) != std::string::npos) {
		res.replace(pos, strlen(VEID_STR1), ctid);
	} else if ((pos = res.find(VEID_STR2)) != std::string::npos) {
		res.replace(pos, strlen(VEID_STR2), ctid);
	}

	return strdup(res.c_str());
}

std::string subst_VEID_back(const char *ctid, const char *path)
{
	char buffer[PATH_MAX];
	char *bdir, *bname;

	strncpy(buffer, path, sizeof(buffer));
	remove_trail_slashes(buffer);
	bname = basename(buffer);
	bdir = dirname(buffer);
	if (strcmp(bname, ctid) == 0)
		return string(bdir) + "/$VEID";
	else
		return path;
}

void remove_trail_slashes(char *path)
{
	char *p;

	for (p = path + strlen(path) - 1; p != path && *p == '/'; p--) *p = '\0';
}

std::string remove_trail_slashes(const char *path)
{
	char buf[PATH_MAX];

	snprintf(buf, sizeof(buf), "%s", path);

	remove_trail_slashes(buf);

	return buf;
}
