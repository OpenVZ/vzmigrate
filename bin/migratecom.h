/* $Id$
 *
 * Copyright (c) SWsoft, 2006-2007
 *
 */
#ifndef __MIGRATECOM_H__
#define __MIGRATECOM_H__

#include <linux/limits.h>
#include <string>
#include <stack>
#include <vector>
#include <list>
#include <vzctl/libvzctl.h>
#include <ploop/libploop.h>
#include "veentry.h"
using namespace std;

#define START_STAGE() logger(LOG_DEBUG, "begin stage : %s", __FUNCTION__)
#define END_STAGE() logger(LOG_DEBUG, "end stage : %s", __FUNCTION__)

#define DEF_SCRIPT_MODE	0755

#define GET_DISKDESCRIPTOR_XML(private, path) \
		snprintf((path), sizeof(path),\
		"%s/" VZCTL_VE_ROOTHDD_DIR "/" DISKDESCRIPTOR_XML, (private));

#define CPT18_NO_IPV6             13
#define CPT32_NO_IPV6             28

class MigrateSshChannel;
int get_real_tmpl_path(
		const char *vztemplate,
		const char *src_path,
		int step,
		char *dst_path,
		size_t sz);

// internal migration source flags
#define VZMSRC_SHARED_PRIV	(1ULL << 0)
#define VZMSRC_SHARED_DUMP	(1ULL << 3)

class MigrateStateCommon
{
protected:
	unsigned long long m_nFlags;

public:
	int erase_flag;
	int use_sparse_opt; // use --sparse option in rsync

	// Cleaning functionality
	typedef int (*MigrateCleanFunc) (const void *, const void *);
	struct MCleanEntry
	{
		MigrateCleanFunc func;
		const void * arg1;
		const void * arg2;
	};
	typedef stack<MCleanEntry> CleanActions;
	// Actions on case of failure
	CleanActions CleanerErr;
	// Actions on case of success
	CleanActions CleanerSuccess;
	// Actions on any case
	CleanActions CleanerAny;

	// Temporary file names
	vector<string> tmpNames;
	// Temporary files collection
	vector<string> tmpFiles;

public:
	static MigrateSshChannel channel;
	char * dst_name;

	// Clean cleaner
	void erase()
	{
		erase_flag = 0;
	};
#define ERROR_CLEANER	0
#define SUCCESS_CLEANER	1
#define ANY_CLEANER	2

#define GETCLEANER(type) (((type) == ANY_CLEANER) ? CleanerAny : \
	(((type) == SUCCESS_CLEANER) ? CleanerSuccess : CleanerErr))

	int doCleaning(int success = ERROR_CLEANER);
	void delLastCleaner(int type = ERROR_CLEANER);
	void addCleaner(MigrateCleanFunc _func, const void * _arg1 = NULL,
	                const void * _arg2 = NULL, int type = ERROR_CLEANER);

	static int clean_delEntry(const void * arg, const void * dummy);
//	static int clean_channel(const void * arg, const void * dummy);
	static int clean_rmDir(const void * arg, const void * dummy);
	static int clean_removeDir(const void * arg, const void * dummy = NULL);
	static int clean_removeFile(const void * arg, const void * dummy);
	void addCleanerRemove(MigrateCleanFunc _func, const char * name,
			int success = ERROR_CLEANER);
	void addCleanerRemove(MigrateCleanFunc _func, const char *arg1,
			const char *arg2, int success = ERROR_CLEANER);
	static int clean_rename(const void * arg1, const void * arg2) ;
	void addCleanerRename(const char * src, const char * dest,
			int success = ERROR_CLEANER);

protected:
	int applyPloopQuotaImpl(const char *qfile);
	virtual VEObj *getDstVE()
	{
		return NULL;
	}

public:
	MigrateStateCommon();
	virtual ~MigrateStateCommon();

	const char ** getRsyncArgs();

	int remoteRsyncSrc(
			const char * cmd,
			bool withprogress,
			const list<string> &params);
	int remoteRsyncDst(const char * const args[], ...);

	int sendRequest(const char *buffer, long *retcode);
	int adjustTimeout(struct timeout *tmo);
	/* create snapshot */
	static int ploopCreateSnapshot(const char *xmlconf, const char *guid);
	/* create temporary snapshot */
	static int ploopCreateTSnapshot(const char *xmlconf, const char *guid);
	/* merge top delta */
	static int ploopMergeTopDelta(const char *xmlconf);
	/* delete ploop snapshot by guid */
	static int ploopDeleteSnapshot(const char *xmlconf, const char *guid);
	/* remove top delta offline */
	static int ploopDeleteTopDelta(const char *xmlconf);
	/* get filename of active delta (image) for ploop-based CT */
	static int ploopGetTopImageFileName(const char *xmlconf, char *path, size_t size);
	/* run HA cluster manager */
	static int runHaman(unsigned veid, const char *cmd, ...);
	/* get node id of HA cluster */
	int getHaClusterNodeID(string & id);
	int getActivePloopDelta(struct string_list *list);
	int checkDstIDFree(const VEObj &ve);
	int checkCommonDst(const VEObj &ve);

public:
	int h_copy(const char * src, const char * dst);
	int h_rename(const char * src, const char * dst);
	int h_backup(const char * src);
	int h_true(const char * , const char * );

private:
	int run_rsync_srv(char *args[]);
	int run_rsync_srv_old(char *args[]);
};

class CWD
{
	const char * m_new_dir;
	char m_buf[PATH_MAX];
public:
	CWD()
	{
		m_new_dir = NULL;
	};
	~CWD()
	{
		if (m_new_dir) restore();
	}

	int chdir(const char * dir);
	int restore();
};

int restoreIOState(const void *, const void *);

/* get cluster id for <path> */
#define GFS_LOCKNAME_LEN        64
/* for path <path> try to get cluster id <id> */
int gfs_cluster_getid(
		const char *path,
		char *id,
		size_t id_size);

/* set *is_shared=1 if path is on NFS, GFS or pstorage, set fs type in *fstype */
int is_path_on_shared_storage(const char *path, int *is_shared, long *fstype);
/* return 1 if kernel supports graceful stopping of VZFS tracker on suspend */
int is_cpt_stop_tracker_supported();
std::string rsync_dir(const char *str);
std::string rsync_dir(const std::string &str);
std::string get_dd_xml(const char *dir);
std::string get_dd_xml(const std::string &dir);
std::string convert_root_path(const char *root);
std::string convert_bindmount_path(const char *root);
int check_free_space(const char *path, unsigned long long r_bytes, unsigned long long r_inodes);

#endif

