/* $Id$
 *
 * Copyright (c) SWsoft, 2006-2007
 *
 */
#ifndef __MIGRATESRC__H
#define __MIGRATESRC__H

#include "migratecom.h"
#include "veentry.h"
#include "bincom.h"

class HWExec;
class TemporaryFile;

class MigrateStateSrc : public MigrateStateCommon
{
public:
	/* Source (from) VE */
	VEObj * srcVE;
	/* destination (to) VE*/
	VEObj * dstVE;
	/* keeper VE, that keeps some src VEs parameters on process of migration
	   now we transfer VE IPs to keeper
	 */
	VEObj * keepVE;

protected:

	VEObj *getDstVE()
	{
		return dstVE;
	}

	// Clean functions
	static int clean_startVE(const void * arg, const void *);
	static int clean_closeSocket(const void * arg, const void *);
	static int clean_mountVE(const void * arg, const void *);
	static int clean_rollbackIPs(const void * arg, const void *);
	static int clean_deletePloopSnapshot(const void * arg, const void * arg2);
	static int clean_registerVE(const void * arg1, const void * arg2);
	static int clean_resumeVE(const void * arg1, const void * arg2);
	static int clean_deleteSnapshot(const void * arg1, const void * arg2);

	int exchangeKeeperIPs();
	int restoreKeeperIPs();
	int suspendVE();
	int checkCommonSrc();

	int checkDiskSpace();
	int checkDiskSpaceRC(int rc);
	virtual int checkDiskSpaceValues(unsigned long long bytes, unsigned long long inodes) = 0;

public:
	operator void*() const
	{
		return srcVE == NULL ? NULL : (void*) (-1);
	};
	int doMigration();

	virtual int doCtMigration(){ return 0; }

	virtual bool isSameLocation() = 0;
	virtual int copyDumpFile() = 0;
	virtual int suspendVEOnline() = 0;

	MigrateStateSrc(const char * src_ctid, const char * dst_ctid,
		const char * priv, const char * root, const char *name);
	~MigrateStateSrc();

	static int getRelativePath(const char *directory, const char *path, char *rpath, size_t size);

protected:

	int m_srcInitStatus;
	char m_convertQuota2[PATH_MAX];


	/* migrate stages */

	int startVEStage();

	// stage of dst VE starting
	virtual int startVE() = 0;

	int excludeActiveDelta(const char *dd_xml, char *path,  size_t size);
	int getActivePloopDelta(struct string_list *list);
	int getActivePloopDelta(const ct_disk &disk, struct string_list *list);
	void cleanExternalDisk();
	void removeSrcPrivate();
	int checkDisks();
};

void add_excludes(std::list<std::string> &args, const std::list<std::string> *exclude);

#endif

