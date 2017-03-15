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
#ifndef __MIGSRLOCAL__
#define __MIGSRLOCAL__

#include "migratesrc.h"
#include <set>
#include <map>
#include <string>

struct bundle {

	std::string src;
	std::string dst;
	std::vector<std::string> disks;
};

struct external_disk_path {

	external_disk_path(const char *path, const std::string &src_id, const std::string &a_dst_id);

	std::string src_bundle() const;
	std::string dst_bundle() const;
	std::string src_path() const;
	std::string dst_path() const;

	bool has_bundle;
	std::string dst_id;
	std::string src_id;
	std::string location;
	std::string name;
};

class MigrateStateLocal : public MigrateStateSrc
{
public:
	virtual int doCtMigration();

	int stopVE();
	virtual int startVE();

	MigrateStateLocal(const char * src_ctid, const char * dst_ctid,
			const char * priv, const char * root,
			const char *dst_name = NULL, const char *uuid = NULL);
	~MigrateStateLocal();

protected:
	int is_thesame_ctid;
	int is_thesame_private;
	int is_thesame_root;
	int is_thesame_location;
	std::map<std::string, bundle> bundles;
	std::vector<external_disk_path> unb_disks;
	int is_priv_on_shared;
	const char *m_uuid;

	int correctVZCache();

	bool isSameLocation();

	static int clean_restoreVE(const void * arg1, const void * arg2);

	/* HA cluster-related cleaner set */
	static int clean_unitaryHaClusterResouce(const void * arg1, const void * arg2);
	static int clean_moveHaClusterResource(const void * arg1, const void * arg2);

private:

	void buildBundles();

	int checkBundleMix();

	int createBundle(const std::string &p);
	int createDstBundles();
	int createDstBundlesUnbundledDisks();

	int copyBundles();
	int copyUnbundledDisks();

	int checkDiskSpaceValues(unsigned long long bytes, unsigned long long inodes);
	int checkDiskSpaceClone();

	// migrate preparation
	int updateDiskPath();
	int preMigrateStage();
	// stage between, after data copping but before dst VE starting
	int preFinalStage();
	// the final stage post VE starting cleaning
	int postFinalStage();
	int copyDiskDescriptors();
	int ploopCtClone();
	int ploopCtMove();
	int regenerate_fs_uuid();
};

#endif

