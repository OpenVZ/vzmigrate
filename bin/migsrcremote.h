/* $Id$
 *
 * Copyright (c) SWsoft, 2006-2007
 *
 */
#ifndef __MIGSRCREMOTE__
#define __MIGSRCREMOTE__

#include "migratesrc.h"
#include "ploop.h"

class MigrateStateRemote : public MigrateStateSrc
{
public:
	void *swapch;

	virtual int doCtMigration();
	int doCtMigrationDefault();

	virtual int startVE();

	// checks
	int checkIPAddresses();
	int checkAvailLicense();
	int checkTechnologies();
	int checkRate();
	int checkCapabilities();
	int checkKernelModules();
	int checkCPTImageVersion();
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

	/* check templates on destination HN */
	int checkTemplates();
	int checkNewTemPackageDependencies();

	MigrateStateRemote(
		const char * src_ctid,
		const char * dst_ctid,
		const char * priv,
		const char * root,
		const char * dst_name);

	~MigrateStateRemote();

protected:
	int sockfd;
//	MigrateSshChannel * ch;
	bool use_iteration;
	unsigned int cpu_flags;
	long is_keep_dir;
	bool m_bIsPrivOnShared;
	long m_isTargetInHaCluster;
	typedef std::list<struct ploop_delta_desc *> listDeltaDesc_t;
	listDeltaDesc_t m_deltas;

protected:
	int establishSshChannel();

	int invertLazyFlag();

	int establishChannel(class MigrateSshChannel *ch, char *cmd);

	/* copy functions */
	int h_copy_remote_rsync_dump(const char * src);
	/* dumpdirs of source and target nodes are on the same cluster.
	   Do not rsync dumpfile, copy name only */
	int h_copy_cluster_dump(const char * dumpfile);
	int h_copy_remote_rsync_file(const char * cmd, const char * path);
	int copy_remote(const char *src, struct string_list *exclude, bool use_rsync);

	/* Restore VE config from backup (<veprivate>/ve.conf.migrated)
	   Used for migration in the same cluster */
	static int clean_restoreVEconf(const void * arg1, const void * arg2);
	static int clean_startVE(const void * arg1, const void * arg2);
	static int clean_closeChannel(
			const void * arg,
			const void * dummy = NULL);

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
	int doOnlinePloopCtMigration();
	int doOnlinePloopSharedCtMigration();

	int createDiskDescriptorXmlCopy(const char *basedir, const char *delta,
			char *dd_copy, size_t size, int cleaner);

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

	int copyDumpFile();
	int suspendVEOnline();
	int suspendVEOffline();
	int memoryCopyOnline();
	int sendVersionCmd();
	int sendInitCmd();
	int checkRemoteVersion();
	void finishDestination();

	void delete_ploop_statfs_files();
};

#endif

