/* $Id$
 *
 * Copyright (c) SWsoft, 2006-2007
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

void VEObj::priv_init()
{
	root = priv = NULL;
	dumpfile = NULL;
	ve_data_init(&ve_data);

	lock_fd = -1;
	layout = VZCTL_LAYOUT_3;
	is_frozen = false;
}

VEObj::VEObj(const char *ctid)
{
	priv_init();

	SET_CTID(m_ctid, ctid);
}

VEObj::~VEObj()
{
	unlock();
	free((void *)dumpfile);
	ve_data_clean(&ve_data);
}

#define SUSPEND_FILE "Dump"
#define SUSPEND_DIR "dump"

int VEObj::init_existed()
{
	int rc;
	vzctl_env_status_t env_status;

	if (vzctl2_get_env_status(ctid(), &env_status, ENV_STATUS_ALL))
		return putErr(MIG_ERR_SYSTEM, MIG_MSG_NOSTATUS);

	if (!(env_status.mask & ENV_STATUS_EXISTS))
		return putErr(MIG_ERR_NOEXIST, MIG_MSG_NOEXIST, ctid());

	/* TODO: move to upper level */
	if (isOptSet(OPT_COPY) && (env_status.mask & ENV_STATUS_SUSPENDED))
		return putErr(MIG_ERR_SUSPEND, MIG_MSG_CLONE_FORBIDDEN_FOR_SUSPENDED);

	if ((rc = ve_data_load(m_ctid, &ve_data)))
		return rc;

	root = ve_data.root;
	priv = ve_data.priv;

	/* get VELAYOUT version */
	layout = vzctl2_env_layout_version((char *)priv);

	if (layout >= VZCTL_LAYOUT_5) {
		struct string_list_el *e;

		string_list_for_each(&ve_data._disk, e)
			m_disks.push_back(disk_entry(e->s));

		string_list_for_each(&ve_data._ext_disk, e)
			m_disks.push_back(disk_entry(e->s, true));

		string_list_for_each(&ve_data._np_disk, e)
			m_disks.push_back(disk_entry(e->s, true, false));
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
	std::ostringstream os;

	// for layout=4 for compatibility only
	if (layout < VZCTL_LAYOUT_4)
		os << vzcnf->dumpdir;
	else
		os << priv << "/" SUSPEND_DIR;

	return os.str();
}

string VEObj::suspendPath() const
{
	std::ostringstream os;

	os << dumpDir() << "/" SUSPEND_FILE;

	if (layout < VZCTL_LAYOUT_4)
		os << "." << ctid();

	return os.str();
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

static bool isInternalBindmount(const std::string &bstr)
{
	return !isExternalBindmount(bstr);
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

int VEObj::hasInternalBindmounts()
{
	return findInBindmounts(isInternalBindmount);
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

	if (layout < VZCTL_LAYOUT_5)
		os << priv << VE_VZFS_BINDMOUNT_DIR;
	else
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

int VEObj::createDumpFile()
{
	char path[PATH_MAX];
	int fd;

	/* create dir */
	if (make_dir(dumpDir().c_str(), 0755) != 0)
		return putErr(MIG_ERR_SYSTEM, MIG_MSG_SYSTEM);
	snprintf(path, sizeof(path), "%s/dumpfile.XXXXXX", dumpDir().c_str());
	if ((fd = mkstemp(path)) == -1)
		return putErr(MIG_ERR_SYSTEM, MIG_MSG_SYSTEM);
	close(fd);
	if ((dumpfile = strdup(path)) == NULL)
		return putErr(MIG_ERR_SYSTEM, MIG_MSG_SYSTEM);
	logger(LOG_DEBUG, "DUMPFILE: %s", dumpfile);
	return 0;
}

/* get VE status */
int VEObj::getStatus(int status, int *out)
{
	vzctl_env_status_t ve_status;

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

bool VEObj::isfrozen()
{
	return is_frozen;
}

static const char *get_lock_status()
{
	if (VZMoptions.bintype != BIN_LOCAL)
		return "migrating";

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

int VEObj::suspend(unsigned int flags, bool use_context, bool stop_tracker)
{
// obsolete, c/r support removed from vzctl
#if 0
	int rc;
	char buf[ITOA_BUF_SIZE];
	char veid_hex[10];
	const char * opt[MAX_ARGS] = {"--suspend", "--flags", buf, NULL};

 	snprintf(buf, sizeof(buf), "%u", flags);
	snprintf(veid_hex, sizeof(veid_hex), "%x", veid());
	if (use_context)
		arrangeArgs(opt, sizeof(opt)/sizeof(char *), opt, "--context", veid_hex, (void *)NULL);
	if (stop_tracker)
		arrangeArgs(opt, sizeof(opt)/sizeof(char *), opt, "--stop-tracker", (void *)NULL);
	if ((rc = operateVE("chkpnt", "Suspending", opt, 0)))
		return rc;
	is_frozen = true;
	return 0;
#endif
	return -1;
}

int VEObj::tsnapshot(const char *guid)
{
	const char *opt[] = {
		"--uuid", guid, "--component-name", VZMIGRATE_COMPONENT_NAME, NULL
	};
	logger(LOG_DEBUG, "Createing tsnapshot %s", guid);
	return operateVE("tsnapshot", "Snapshoting", opt, 0);
}

int VEObj::snapshot_delete(const char *guid)
{
	const char *opt[] = {"--uuid", guid, NULL};

	return operateVE("tsnapshot-delete", "Deleting snapshot", opt, 0);
}

int VEObj::cmd_suspend()
{
// obsolete, c/r support removed from vzctl
#if 0
	const char * opts[] = {"--dumpfile", dumpfile, NULL };

	if (dumpfile == NULL)
		 opts[0] = NULL;

	return operateVE("suspend", "Suspending", opts, 0);
#endif
	return -1;
}

int VEObj::cmd_restore()
{
// obsolete, c/r support removed from vzctl
#if 0
	const char * opts[] = {"--dumpfile", dumpfile, NULL };

	if (dumpfile == NULL)
		 opts[0] = NULL;

	return operateVE("restore", "Restoring", opts, 0);
#endif
	return -1;
}

int VEObj::dump()
{
// obsolete, c/r support removed from vzctl
#if 0
	const char * opt[] =
		{"--dump", "--dumpfile", dumpfile, NULL
		};
	int rc;

	rc = operateVE("chkpnt", "Dumping", opt, 0);
#ifdef FIU_ENABLE
	fiu_do_on("veentry/VEObj/dump", rc = MIG_ERR_SYSTEM);
#endif
	return rc;
#endif
	return -1;
}

int VEObj::undump(int use_context)
{
// obsolete, c/r support removed from vzctl
#if 0
	int rc, rcode;
	int i = 0;
	int count = 0;
	char veid_hex[10];
	const char *args[7];

	args[i++] = "--undump";
	args[i++] = "--skip_arpdetect";
	if (dumpfile) {
		args[i++] = "--dumpfile";
		args[i++] = dumpfile;
	}

	if (use_context) {

		snprintf(veid_hex, sizeof(veid_hex), "%x", veid());
		args[i++] = "--context";
		args[i++] = veid_hex;
	}

	args[i] = NULL;

	rc = operateVE("restore", "Undumping", args, 0);
#ifdef FIU_ENABLE
	fiu_do_on("veentry/VEObj/undump", rc = MIG_ERR_SYSTEM);
#endif
	if (rc != 0)
	{
		char buf[BUFSIZ];
		strncpy(buf, getError(), sizeof(buf));
		const char * args2[] = {"--kill", NULL};
		operateVE("restore", "Restore", args2, 1);
		do
		{
			rcode = operateVE("umount", "Umount", NULL, 1);
			usleep(500000);
		}
		while (rcode !=0 && count++ < 5);
		putErr(MIG_ERR_SYSTEM, "%s", buf);
	}
	return rc;
#endif
	return -1;
}

int VEObj::resume_chkpnt()
{
// obsolete, c/r support removed from vzctl
#if 0
	const char * opt[] =
		{"--resume", NULL
		};
	int rc = operateVE("chkpnt", "Resuming", opt, 0);
	return rc;
#endif
	return -1;
}

int VEObj::resume_restore(int use_context)
{
// obsolete, c/r support removed from vzctl
#if 0
	char veid_hex[10];
	const char * args[] = { "--resume", NULL, NULL, NULL };

	if (use_context) {
		snprintf(veid_hex, sizeof(veid_hex), "%x", veid());
		args[1] = "--context";
		args[2] = veid_hex;
	}

	return operateVE("restore", "Resuming", args, 0);
#endif
	return -1;
}

int VEObj::kill_chkpnt()
{
// obsolete, c/r support removed from vzctl
#if 0
	const char * opt[] =
		{"--kill", NULL
		};
	return operateVE("chkpnt", "Killing", opt, 0);
#endif
	return -1;
}

int VEObj::kill_restore()
{
// obsolete, c/r support removed from vzctl
#if 0
	const char * opt[] =
		{"--kill", NULL
		};
	return operateVE("restore", "Killing", opt, 0);
#endif
	return -1;
}

int VEObj::unSet(const char *param)
{
	char buf[PATH_MAX];
	const char * opt[] = { buf, "--save", NULL };

	snprintf(buf, sizeof(buf), "--%s", param);
	return operateVE("unset", "Unset", opt, 0);
}

int VEObj::vm_prepare()
{
	char * const args[] =
		{(char *)"/usr/libexec/vzvmprep", m_ctid, NULL};

	logger(LOG_DEBUG, "preparing vm");
	return vzm_execve(args, NULL, -1, -1, NULL);
}

int VEObj::vm_iteration(int fd_in, int fd_out)
{
	char in[ITOA_BUF_SIZE];
	char out[ITOA_BUF_SIZE];
	char * const args[] =
		{(char *)BIN_VZITER, m_ctid, in, out, NULL};

#ifdef FIU_ENABLE
	fiu_return_on("veentry/VEObj/vm_iteration", MIG_ERR_SYSTEM);
#endif

	snprintf(in, sizeof(in), "%u", fd_in);
	snprintf(out, sizeof(out), "%u", fd_out);
	logger(LOG_DEBUG, "preparing vm");
	return vzm_execve(args, NULL, -1, -1, NULL);
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
int VEObj::veRegister()
{
	int rc;
	char tmpfile[PATH_MAX + 1];
	struct stat st;

	if (layout < VZCTL_LAYOUT_4)
		return 0;

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
	return registration();
}

int VEObj::registration()
{
	// will rewrite old owner on force registration
	// vzmigrate will itself to register CT on HA cluster
	int flags = VZ_REG_RENEW | VZ_REG_FORCE | VZ_REG_SKIP_HA_CLUSTER;

	struct vzctl_reg_param reg;
	memset(&reg, 0, sizeof(struct vzctl_reg_param));
	SET_CTID(reg.ctid, ctid());

	logger(LOG_DEBUG, "vzctl2_env_register(%s, %s, %d)",
			priv, ctid(), flags);

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
	int rc;

	if (layout == VZCTL_LAYOUT_3) {
		return putErr(MIG_ERR_SYSTEM, "Can't create layout 3");
	} else if (layout == VZCTL_LAYOUT_4) {
		/* for new layout: create fs/root directory
		   and .ve.layout symlink for valid quotainit */
		snprintf(path, sizeof(path), "%s/fs", priv);
		if (access(path, F_OK))
			if (mkdir(path, 0700))
				return putErr(MIG_ERR_SYSTEM, "mkdir(%s) : %m", path);
		snprintf(path, sizeof(path), "%s/fs/root", priv);
		if (access(path, F_OK))
			if (mkdir(path, 0755))
				return putErr(MIG_ERR_SYSTEM, "mkdir(%s) : %m", path);
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

int VEObj::setNameData(const char *name)
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

/* set layout for new VE */
void VEObj::setLayout(int new_layout)
{
	layout = new_layout;
}

int VEObj::loadConfig()
{
	return ve_data_load(m_ctid, &ve_data);
}

int VEObj::updateMAC()
{
	const char *args[] = {"--netif_mac_renew", "--save", NULL};
	return operateVE("set", "Update MAC", args, 0);
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

	for (p = path + strlen(path); p != path && *p == '/'; p--) *p = '\0';
}

std::string remove_trail_slashes(const char *path)
{
	char buf[PATH_MAX];

	snprintf(buf, sizeof(buf), "%s", path);

	remove_trail_slashes(buf);

	return buf;
}
