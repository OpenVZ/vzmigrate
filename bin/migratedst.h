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
#ifndef __MIGRATE_DST__
#define __MIGRATE_DST__

#include "bincom.h"
#include "migratecom.h"
#include "veentry.h"
#include "ploop.h"

#include <sstream>
#include <memory>
#include <vector>
#include <string>

enum {
    SCRIPT_TYPE		= 0,
    SCRIPT_TYPE_CONF,
    SCRIPT_TYPE_QUOTA
};

class VEObj;
class MigrateSshChannel;
class PhaulSockServer;
class PhaulConn;

class MigrateStateDstRemote : public MigrateStateCommon
{
private:
	pid_t m_nVziterindPid;
	VEObj * dstVE;

protected:
	int m_initOptions;
	int is_thesame_private;
	int is_privdir_exist;
	int is_keepdir_exist;
	struct ploop_online_copy_data *m_pPloopData;
	char m_convertQuota2[PATH_MAX];

	std::auto_ptr<PhaulSockServer> m_phaulSockServer;
	std::auto_ptr<PhaulConn> m_phaulConn;
	pid_t m_phaulSrvPid;

protected:
	static int clean_umount(const void * arg, const void *);
	static int clean_destroy(const void * arg, const void *);
	static int clean_unregister(const void * arg, const void *);
	static int clean_deletePloopSnapshot(const void * arg, const void *);
	static int clean_umountImage(const void * arg, const void *);
	static int clean_unregisterOnHaCluster(const void * arg1, const void *arg2);
	static int clean_termPhaulSrv(const void * arg, const void *);

	/* copy data functions */
	typedef int (MigrateStateDstRemote::*DataCopy) (const char *);
	DataCopy func_copyFirst, func_copyFile;

	enum mig_method {
		METHOD_CHECKSUM,
		METHOD_TRACKER
	};

	int h_copy_remote_rsync(const char * dst);
	int h_copy_remote_rsync_fast(const char * dst, mig_method mth);
	int h_copy_remote_rsync_file(const char * dst);
	int h_copy_remote_rsync_dir(const char * dst);
	int h_copy_remote_tar(const char *dst);

	int registerOnHaCluster();

	std::vector<std::string> getPhaulSrvArgs();
	int execPhaulSrv(const std::vector<std::string>& args);

public:
	int is_priv_on_shared;
	string m_sHaClusterNodeID;

	MigrateStateDstRemote(
			VEObj * ve,
			int options = 0);
	virtual ~MigrateStateDstRemote();

	/* Commands */
	int cmdCheckLicense();
	int cmdCheckDiskSpace(istringstream &is);
	int cmdCheckTechnologies(istringstream &is, ostringstream & os);
	int cmdCheckRate();
	int cmdCheckName(istringstream &is);
	/* process 'cluster id request': get cluster id of target VE private,
	   compare in success, and send '1' if it the same cluster */
	int cmdCheckClusterID(istringstream &is, ostringstream & os);
	/* The same for vzcache */
	int cmdCheckSharedPriv(istringstream &is, ostringstream & os);
	int cmdCheckSharedFile(istringstream &is, ostringstream &os);
	int cmdCheckSharedTmpl(istringstream &is, ostringstream & os);
	int cmdCheckClusterTmpl(istringstream &is, ostringstream & os);
	int cmdClusterDumpCopy(istringstream &is);
	int cmdCheckKeepDir(ostringstream & os);
	int cmdCheckOptions(istringstream & is, ostringstream & os);
	int cmdCheckKernelModules(istringstream &is);
	int cmdTemplateSync(istringstream &is);
	int cmdCopyPloopPrivate() { return h_copy_remote_tar(dstVE->priv); }
	int cmdCopyPloopPrivateSync() { return h_copy_remote_rsync_dir(dstVE->priv); }

	// vzfs -> ploop conversion
	int cmdCopyPloopRoot() { return h_copy_remote_tar(dstVE->root); }
	int cmdCopyPloopBindmounts()
	{
		return h_copy_remote_tar(dstVE->bindmountPath().c_str());
	}

	int cmdCopyExternalDisk(istringstream &is);
	int cmdCopyVzPackages();
	int copySetNativeQuota(istringstream &is);
	int cmdCopyPloopImageOnline1(size_t blksize, const std::string &fname);
	int cmdCopyPloopImageOnline2(istringstream &is);
	int cmdCreatePloopSnapshot(istringstream &is, bool rollback = true);
	int cmdCreatePloopSnapshotNoRollback(istringstream &is);
	int cmdDeletePloopSnapshot(istringstream &is);
	int cmdMountPloop(unsigned long ploop_size, unsigned long create_size, int lmounted);
	int cmdHaClusterNodeID(istringstream &is, ostringstream &os);
	int cmdCheckPloopFormat(istringstream &is);
	int cmdPreEstablishPhaulConn();
	int cmdEstablishPhaulConn(istringstream &is);
	int cmdStartPhaulSrv();

	int initVEMigration(VEObj * ve);
	int initMigration();

	int copyStage(int stage);
	int copyUUIDStage();

	int copySetConf();

	/* final VE operation before start/mounting */
	int finalVEtuning();
	int finalStage(int action);
	int undump();
	int resume();
	int resume_non_fatal();
	int createSwapChannel(string veid_str);
	std::string getCopyArea();
	VEObj *getDstVE()
	{
		return dstVE;
	}
};

#endif

