/* $Id$
 *
 * Copyright (c) 2006-2016 Parallels IP Holdings GmbH
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
 * Our contact details: Parallels IP Holdings GmbH, Vordergasse 59, 8200
 * Schaffhausen, Switzerland.
 *
 */
#ifndef __MIGSRCREMOTE__
#define __MIGSRCREMOTE__

#include <memory>
#include "migratesrc.h"
#include "ploop.h"

class PhaulChannels;

class MigrateStateRemote : public MigrateStateSrc
{
public:
	virtual int doCtMigration();
	int doCtMigrationDefault();
	int doCtMigrationPhaul();

	int stopVE();
	virtual int startVE();

	// checks
	int checkIPAddresses();
	int checkAvailLicense();
	int checkTechnologies();
	int checkRate();
	int checkKernelModules();
	int checkBindMounts();
	/* check cluster id */
	int checkClusterID();
	int checkSharedFile(const char *dir, bool *shared);
	int checkSharedDisk();
	int checkKeepDir();
	int checkOptions(unsigned long long *options);
	int checkSharedDir(
			const char *cmd400,
			const char *cmd401,
			const char *dir,
			const char *title,
			const char *uuid,
			int *shared,
			int *reply);

	/* check target VE name */
	int checkDstName();

	MigrateStateRemote(
		const char * src_ctid,
		const char * dst_ctid,
		const char * priv,
		const char * root,
		const char * dst_name);

	~MigrateStateRemote();

protected:
	long is_keep_dir;
	bool m_bIsPrivOnShared;
	long m_isTargetInHaCluster;
	typedef std::list<struct ploop_delta_desc *> listDeltaDesc_t;
	listDeltaDesc_t m_deltas;

	std::auto_ptr<PhaulChannels> m_phaulChannels;

protected:
	int invertLazyFlag();

	int establishChannel(class MigrateSshChannel *ch, char *cmd);

	/* copy functions */
	int h_copy_remote_rsync_file(const char * cmd, const char * path);
	int copy_remote(const char *src, struct string_list *exclude, bool use_rsync);

	/* Restore VE config from backup (<veprivate>/ve.conf.migrated)
	   Used for migration in the same cluster */
	static int clean_restoreVEconf(const void * arg1, const void * arg2);
	static int clean_startVE(const void * arg1, const void * arg2);
	static int clean_termPhaul(const void * arg, const void *);

	bool isSameLocation();
	int checkDiskSpaceValues(unsigned long long bytes, unsigned long long inodes);

private:
	bool is_shared() const
	{
		return (m_nFlags & VZMSRC_SHARED_PRIV) || srcVE->m_disks.is_shared();
	}
	int checkDiskSpacePloop();
	int checkPloopFormat();

	// migrate preparation
	int preMigrateStage();
	// stage between, after data copping but before dst VE starting
	int preFinalStage();
	// the final stage post VE starting cleaning
	int postFinalStage();

	int doOfflinePloopCtMigration();
	int doOfflineSimfsCtMigration();
	int doOnlinePloopCtMigration();
	int doLegacyOnlinePloopCtMigration();

	int preparePhaulConnection(const std::vector<std::string>& activeDeltas);
	int prePhaulMigration();
	int runPhaulMigration();
	std::vector<std::string> getPhaulArgs(const PhaulChannels& channels);
	std::string getPhaulSharedDisksArg() const;
	pid_t execPhaul(const std::vector<std::string>& args);

	int syncPageCacheAndFreezeFS(const char *mnt);
	void unfreezeFS(int fd);

	int sendHaClusterID();
	void unregisterHA();
	int copy_disk(const ct_disk &disks, struct string_list *exclude);
	int copy_ve_layout();
	int copy_ct(struct string_list *exclude);
	int copy_delta(const char *delta, struct string_list *exclude);
	int copy_deltas(struct string_list *deltas);
	int open_active_deltas(struct string_list *active_deltas);
	int copy_active_delta(struct ploop_delta_desc *desc);
	int copy_active_deltas();
	int copy_active_delta_dirty(struct ploop_delta_desc *desc);
	int copy_active_deltas_dirty();
	void close_active_deltas();

	int sendVersionCmd();
	int sendInitCmd();
	int checkRemoteVersion();
	void finishDestination();

	void deletePloopStatfsFiles();
};

#endif

