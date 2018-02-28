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

#ifndef __CT_CONFIG_H_
#define __CT_CONFIG_H_

#include <string>
#include <list>
#include <vzctl/libvzctl.h>
#include "util.h"

#define VZ_CONF                 VZ_GLOBAL_CFG
#define VZ_CONF_LOCKDIR	        "LOCKDIR"
#define VZ_CONF_TMPLDIR         "TEMPLATE"
#define VZ_CONF_DUMPDIR         "DUMPDIR"
#define VZ_CONF_QUOTA           "DISK_QUOTA"
#define VZ_CONF_SHAPING         "TRAFFIC_SHAPING"
#define VZ_CONF_REMOVEMIGRATED  "REMOVEMIGRATED"
#define VZ_CONF_TOOLS_IOLIMIT   "VZ_TOOLS_IOLIMIT"

#define VE_CONF_PRIV            "VE_PRIVATE"
#define VE_CONF_ROOT            "VE_ROOT"
#define VE_CONF_UUIDDIR         "UUID"
#define VE_CONF_TECHNOLOGIES    "TECHNOLOGIES"
#define VE_CONF_BINDMOUNT       "BINDMOUNT"
#define VE_CONF_NAME            "NAME"
#define VE_CONF_OSTEMPLATE      "OSTEMPLATE"
#define VE_CONF_IPADDR          "IP_ADDRESS"
#define VE_CONF_VETYPE          "VE_TYPE"
#define VE_CONF_DISKSPACE       "DISKSPACE"
#define VE_CONF_DISKINODES      "DISKINODES"
#define VE_CONF_RATE            "RATE"
#define VE_CONF_UUID            "UUID"
#define VE_CONF_TEMPLATES       "TEMPLATES"
#define VE_CONF_SLMMODE         "SLMMODE"
#define VE_CONF_QUOTAUGIDLIMIT  "QUOTAUGIDLIMIT"
#define VE_CONF_HA_ENABLE       "HA_ENABLE"
#define VE_CONF_HA_PRIO         "HA_PRIO"
#define VE_CONF_JOURNALED_QUOTA "JOURNALED_QUOTA"
#define VE_CONF_VEFORMAT        "VEFORMAT"
#define VE_CONF_DISK            "DISK"

/*
 * Global vz config.
 */
struct vz_data {
public:
	vz_data();

private:
	vz_data(const vz_data&);
	vz_data& operator =(const vz_data&);

public:
	char *root_orig;
	char *priv_orig;
	char *lockdir;
	char *tmpldir;
	char *dumpdir;
	int quota;
	int shaping;
	int removemigrated;
	unsigned long iolimit;
};

/*
 * Container disk data.
 */
struct ve_disk_data {
public:
	ve_disk_data(const vzctl_disk_param& disk_param);

public:
	std::string m_path;
	std::string m_uuid;
	std::string m_mnt;
};

/*
 * Container config.
 */
struct ve_data {
public:
	ve_data();
	~ve_data();

private:
	ve_data(const ve_data&);
	ve_data& operator =(const ve_data&);

public:
	char *name;
	char *uuid;
	char *ostemplate;
	unsigned long technologies;
	char *bindmount;
	char *root;
	char *root_orig;
	char *priv;
	char *priv_orig;
	char *ve_type;
	struct string_list ipaddr;
	struct string_list rate;
	unsigned long diskspace[2];
	unsigned long diskinodes[2];
	struct string_list templates;
	char *slmmode;
	unsigned long quotaugidlimit;
	int ha_enable;
	unsigned long ha_prio;
	std::list<ve_disk_data> disks;
	std::list<ve_disk_data> ext_disks;
	std::list<ve_disk_data> np_disks;
	std::list<ve_disk_data> dev_disks;
	char *disk_raw_str;
};

/*
 * Read global VZ config.
 */
int vz_data_load(struct vz_data *vz);

/*
 * Read VE config.
 */
int ve_data_load(const char *ctid, struct ve_data *ve);
int ve_data_load_by_conf(const char *conf, struct ve_data *ve);

#endif
