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
#ifndef __VEENTRY_H__
#define __VEENTRY_H__

#include <sys/stat.h>
#include <string>
#include <vector>
#include <list>
#include <stdlib.h>

#include "util.h"
#include "ct_config.h"

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
public:
	disk_entry(const ve_disk_data& data, bool _ext = false,
			bool _persistent = true, bool _device = false)
		: image(data.m_path)
		, uuid(data.m_uuid)
		, ext(_ext)
		, persistent(_persistent)
		, shared(false)
		, secondary(data.m_mnt != "/")
		, device(_device)
	{
	}

	bool is_external() const { return ext; }
	bool is_shared() const { return shared; }
	bool is_secondary() const { return secondary; }
	bool is_device() const {return device; }

public:
	std::string image;
	std::string uuid;
	bool ext;
	bool persistent;
	bool shared;
	bool secondary;
	bool device;
};

bool disk_is_shared(const disk_entry &d);
bool disk_is_shared_not_device(const disk_entry &d);
bool disk_is_secondary(const disk_entry &d);
bool disk_is_secondary_or_device(const disk_entry &d);
bool disk_is_device(const disk_entry &d);

inline bool disk_is_non_shared(const struct disk_entry &d)
{
	return !d.is_shared();
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
	ctid_t m_ctid;
	int lock_fd;

public:
	const char* ctid() const
	{
		return m_ctid;
	}

	const char * root;
	const char * priv;
	bool priv_custom;
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
	void init_disks(const struct ve_data& data);

	int lock ();
	void unlock();
	int islocked();
	void clean();

	int operateVE(const char * func, const char * action,
			const char ** option, int quiet);

	/* VE actions */
	int start();
	int stop(bool skip_umount = false);
	int kill();
	int mount();
	int umount();
	int tsnapshot(const char *guid);
	int tsnapshot_delete(const char *guid);
	int destroy();
	int cmd_suspend();
	int cmd_restore();
	int unSet(const char *param);
	int updateConfig(const char *param, const char *uuid = NULL);
	int registration(const char *uuid = NULL);
	int unregister();
	int createDevmap();

	/* check VE status */
	int getStatus(int status, int *out);
	int isexist();
	int isrun();
	int ismount();
	int issuspended();

	/* register ve with new layout */
	int veRegister(const char *uuid = NULL);
	/* exec post create VE action: randomize cron too */
	int ExecPostCreate();

	/* stop vpsd inside VPS */
	int stopVpsd();

	int createLayout();

	unsigned long checkTechnologies(unsigned long *tech_mask);
	int checkRate();
	string confPath() const;
	/* get real VE config file path */
	string confRealPath() const;
	/* get VE VZFS directory */
	const string getVEPrivateVZFS();
	string dumpDir() const;
	string tmplDir() const;
	void setPrivate(const char *p);
	void setRoot(const char *p);
	void setNameData(const char *name);
	std::string getPrivateConf();
	std::string getRootConf();
	int prepareConfig();
	int hasExternalBindmounts();
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
	int renewMAC();
	/* returns maximum ploop format version among
	   all CT disks */
	int getPloopMaxVersion(int &version);


	int loadConfig();
	void setLayout(int new_layout);
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

