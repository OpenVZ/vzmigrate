/* $Id$
 *
 * Copyright (c) SWsoft, 2006-2007
 *
 */
#ifndef __VEENTRY_H__
#define __VEENTRY_H__

#include <sys/stat.h>
#include <string>
#include <list>
#include <stdlib.h>

#include "util.h"

#define VZMIGRATE_COMPONENT_NAME	"vzmigrate"

using std::string;

enum {
    DSTACT_NOTHING = 0,
    DSTACT_START_VE,
    DSTACT_MOUNT_VE
};

extern const char * actionScripts[];

// IP list processing
typedef std::vector<string> IPList;

struct disk_entry {
	std::string image;
	bool ext;
	bool persistent;
	bool shared;

	disk_entry(const std::string &_image, bool _ext = false, bool _persistent = true) :
		image(_image), ext(_ext), persistent(_persistent), shared(false)
	{}

	bool is_external() const { return ext; }
	bool is_shared() const { return shared; }
};

inline bool disk_is_shared(const struct disk_entry &d)
{
	return d.is_shared();
}

class ct_disk : public std::list<disk_entry> {
public:
	bool is_shared() const
	{
		return has(disk_is_shared);
	}

	bool has(bool (*predicate)(const struct disk_entry&)) const
	{
		for (ct_disk::const_iterator it = begin(); it != end(); ++it)
			if (predicate(*it))
				return true;
		return false;
	}

	ct_disk get(bool (*predicate)(const struct disk_entry&)) const
	{
		ct_disk disks;

		for (ct_disk::const_iterator it = begin(); it != end(); ++it)
			if (predicate(*it))
				disks.push_back(*it);

		return disks;
	}
};

class VEObj
{
private:
	string m_snap_guid;
	/* VE is frozen or not */
	bool is_frozen;

	ctid_t m_ctid;

	int lock_fd;

	void priv_init();

public:
	const char* ctid() const
	{
		return m_ctid;
	}

	const char * root;
	const char * priv;
	const char * dumpfile;
	/* from VE config */
	struct ve_data ve_data;
	ct_disk m_disks;
	/* = 1 if private specified by sender */

	/* version of VE layout */
	int layout;
	/* ve format */
	int veformat;

	VEObj(const char *ctid);
	virtual ~VEObj();
	int init_existed();
	int init_empty();
	int lock ();
	void unlock();
	int islocked();
	void clean();

	int operateVE(const char * func, const char * action,
			const char ** option, int quiet);

	/* VE actions */
	int start();
	int stop(bool skip_umount = false);
	int mount();
	int umount();
	int suspend(unsigned int flags = 0, bool use_context = false, bool stop_tracker = false);
	int tsnapshot(const char *guid);
	int snapshot_delete(const char *guid);
	int dump();
	int kill_chkpnt();
	int kill_restore();
	int resume_chkpnt();
	int pageout(int fd_in, int fd_out);
	int vm_prepare();
	int vm_iteration(int fd_in, int fd_out);
	int setlazyvm(int flag);
	int destroy();
	int cmd_suspend();
	int cmd_restore();
	int unSet(const char *param);
	int updateConfig(const char *param, const char *uuid = NULL);
	int registration();
	int unregister();

	/* check VE status */
	int getStatus(int status, int *out);
	int isexist();
	int isrun();
	int ismount();
	int issuspended();
	bool isfrozen();

	/* register ve with new layout */
	int veRegister();
	/* exec post create VE action: randomize cron too */
	int ExecPostCreate();

	/* stop vpsd inside VPS */
	int stopVpsd();

	int createLayout();

	unsigned long checkTechnologies(unsigned long *tech_mask);
	int checkRate();
	int createDumpFile();
	string confPath() const;
	/* get real VE config file path */
	string confRealPath() const;
	/* get VE VZFS directory */
	const string getVEPrivateVZFS();
	string suspendPath() const;
	string dumpDir() const;
	string tmplDir() const;
	void setPrivate(const char *p);
	void setRoot(const char *p);
	int setNameData(const char *name);
	std::string getPrivateConf();
	std::string getRootConf();
	int prepareConfig();
	int hasExternalBindmounts();
	int hasInternalBindmounts();
	std::string templatePath() const;
	std::string bindmountPath() const;

	const string scriptPath(const char * action);

	bool isNewTemOS();

	const char *gen_snap_guid();
	const char *snap_guid()
	{
		return m_snap_guid.c_str();
	}

	int getVEHandle(struct vzctl_env_handle **h) const;

	/* check that this name does not used by other VE */
	int checkName(const char *name);
	/* set VE name */
	int setName(char const *);
	int resume_restore(int use_context);
	int undump(int use_context);
	int renewMAC();
	/* returns maximum ploop format version among
	   all CT disks */
	int getPloopMaxVersion(int &version);


	int loadConfig();
	void setLayout(int new_layout);
	int updateMAC();
	bool isCustomPrivate() const;
private:
	bool findInBindmounts(bool (*func)(const std::string &bstr));
};

int checkVEDir(const char * vedir, int unique = 0);

int exchangeIPs(VEObj &k, VEObj &v);
int restoreIPs(VEObj &k, VEObj &v);
int rollbackIPs(VEObj &k, VEObj &v);

/* check target VE RATE on destination node */
int check_rate(struct string_list *rate);
char *subst_CTID(const char *ctid, const char *src);
std::string subst_VEID_back(const char *ctid, const char *path);
void remove_trail_slashes(char *path);
std::string remove_trail_slashes(const char *path);

#endif

