/* $Id$
 *
 * Copyright (c) SWsoft, 2006-2007
 *
 */
#include "bincom.h"
#include "common.h"
#include "migratedst.h"
#include "migssh.h"
#include "remotecmd.h"
#include "veentry.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sstream>

#include <libgen.h>

#include "server.h"

#include <fstream>
#include <memory>
#include <string>
#include <map>

using namespace std;

CNewVEsList::~CNewVEsList()
{
	for (std::map<std::string, VEObj *>::const_iterator it = this->begin();
			it != this->end(); it++)
		delete it->second;
}

CNewVEsList * g_veList = NULL;
std::map<std::string, std::string> * g_ctidMap = NULL;
MigrateStateDstRemote * state = NULL;

static int cmdVersion(istringstream & is, ostringstream & os)
{
	int remote_version;
	if ((is >> remote_version) == NULL)
		return putErr(MIG_ERR_PROTOCOL, MIG_MSG_PROTOCOL);
	VZMoptions.remote_version = remote_version;
	if (VZMoptions.remote_version < MIGRATE_VERSION_400) {
		if (state->is_priv_on_shared)
			return putErr(MIG_ERR_SYSTEM,
				"Can't migrate this private area "
				"on shared FS (old version)");
	}

	// report version
	os << VZMoptions.version;
	return 0;
}

static int cmdCapabilities(ostringstream & os)
{
	char buf[BUFSIZ];
	const char *cmd = "/usr/libexec/vztestcaps";
	FILE *fd;
	char *p;
	const char *hdr = "CAPS ";

	logger(LOG_DEBUG, cmd);
	if ((fd = popen(cmd, "r")) == NULL)
		return putErr(MIG_ERR_SYSTEM, "popen('%s') : %m", cmd);

	if (fgets(buf, sizeof(buf), fd) == NULL) {
		pclose(fd);
		return putErr(MIG_ERR_SYSTEM,
			"can't get capabilities (%s) : %m", cmd);
	}
	pclose(fd);

	if (strncmp(buf, hdr, strlen(hdr)))
		return putErr(MIG_ERR_SYSTEM,
			"can't get capabilities : %s reply is '%s'", cmd, buf);

	if ((p = strchr(buf, '\n')))
		*p = '\0';

	if (VZMoptions.remote_version <= MIGRATE_VERSION_460) {
		/*
		  See https://jira.sw.ru/browse/PSBM-11558 and
		  https://jira.sw.ru/browse/PCLIN-30480.
		  - copy the 28th bit into 13th bit
		  - clear 28th bit
		*/
		unsigned int flags;
		char *ep;
		for (p = buf + strlen(hdr); *p == ' '; p++);
		flags = strtoul(p, &ep, 10);
		if (*ep != '\0')
			return putErr(MIG_ERR_SYSTEM,
				"invalid capabilities value : '%s'", p);

		if (flags & (1U << CPT32_NO_IPV6))
			flags |= 1U << CPT18_NO_IPV6;
		else
			flags &= ~(1U << CPT18_NO_IPV6);
		flags &= ~(1U << CPT32_NO_IPV6);
		os << hdr << flags;
	} else {
		os << buf;
	}

	return 0;
}

static int cmdCreateSwapChannel(void)
{
	return putErr(MIG_ERR_SYSTEM, "Lazy migration is not supported");
}

static int cmdCreateIterChannel(istringstream & is)
{
	string veid_str;
	if ((is >> veid_str) == NULL)
		return putErr(MIG_ERR_PROTOCOL, MIG_MSG_PROTOCOL);
	return state->createSwapChannel(veid_str);
}

static int cmdInvertLazyFlag(void)
{
	isOptSet(OPT_NOCONTEXT) ? unSetOpt(OPT_NOCONTEXT) : setOpt(OPT_NOCONTEXT);
	return 0;
}

static int cmdFinalStage(istringstream & is)
{
	int action = 0;
	if ((is >> action) == NULL)
		return putErr(MIG_ERR_PROTOCOL, MIG_MSG_PROTOCOL);
	return state->finalStage(action);
}

static int cmdCheckIPs(istringstream & is)
{
	// obsoleted
	return 0;
}

static int cmdCopyPloopImageOnline1(istringstream & is)
{
	size_t blksize;

	if ((is >> blksize) == NULL)
		return putErr(MIG_ERR_PROTOCOL, MIG_MSG_PROTOCOL);

	string fname;

	is >> fname;

	return state->cmdCopyPloopImageOnline1(blksize, fname);
}

static int cmdInitMigration(istringstream & is)
{
	// Get CTID to init
	std::string ctid;
	if ((is >> ctid) == NULL)
		return putErr(MIG_ERR_PROTOCOL, MIG_MSG_PROTOCOL);

	// Get additional init options
	int options = 0;
	if ((is >> options) == NULL)
		options = 0;

	CNewVEsList::iterator it = g_veList->find(ctid);
	if (it == g_veList->end()) {
		// New syntax for PSBM - src part knows nothing about CTID
		// change and thus put src CTID to "init" cmd. Try to find
		// respective mapping and thus veObj with new ID.
		std::map<std::string, std::string>::iterator it2 = g_ctidMap->find(ctid);
		if (it2 == g_ctidMap->end())
			return putErr(MIG_ERR_PROTOCOL, MIG_MSG_PROTOCOL);

		// map found, search list by dst_ctid
		it = g_veList->find(it2->second);
		if (it == g_veList->end())
			return putErr(MIG_ERR_PROTOCOL, MIG_MSG_PROTOCOL);
	}

	state = new MigrateStateDstRemote(it->second, options);
	if (state == NULL)
		return putErr(MIG_ERR_SYSTEM, MIG_MSG_SYSTEM);

	g_veList->erase(it);
	return state->initMigration();
}

static int cmdCheckTechnologies(istringstream & is, ostringstream & os)
{
	return state->cmdCheckTechnologies(is, os);
}

static int cmdAdjustTimeout(istringstream & is, ostringstream & os)
{
	if ((is >> VZMoptions.tmo.val) == NULL)
		return putErr(MIG_ERR_PROTOCOL, MIG_MSG_PROTOCOL);
	VZMoptions.tmo.customized = 1;
	snprintf(VZMoptions.tmo.str, sizeof(VZMoptions.tmo.str),
		"%ld", VZMoptions.tmo.val);
	logger(LOG_DEBUG, "Set custom timeout %ld sec", VZMoptions.tmo.val);
	os << "1";
	return 0;
}

static int cmdMountPloop(istringstream & is)
{
	unsigned long ploop_size, create_size;
	int lmounted;
	int rc;

	if ((is >> ploop_size >> lmounted) == NULL)
		return putErr(MIG_ERR_PROTOCOL, MIG_MSG_PROTOCOL);

	if ((is >> create_size) == NULL)
		create_size = 0;

	return state->cmdMountPloop(ploop_size, create_size, lmounted);
}

static int proc_cmd(const char *cmd, istringstream & is, ostringstream & os)
{
	int rc;

	bool init_cmd = strcmp(cmd, CMD_INIT) == 0;
	if ((init_cmd && state != NULL) || 
		(!init_cmd && state == NULL))
		return putErr(MIG_ERR_PROTOCOL, MIG_MSG_PROTOCOL);

	if (strcmp(cmd, CMD_INIT) == 0) {
		return cmdInitMigration(is);
	} else if (strcmp(cmd, CMD_FIRST) == 0) {
		// first (full) rsync, 'first'
		return state->copyStage(SIMPLECOPY);
	} else if (strcmp(cmd, CMD_DUMPCOPY) == 0) {
		// dump rsync
		return state->copyStage(DUMPCOPY);
	} else if (strcmp(cmd, CMD_SUSPENDCOPY) == 0) {
		// suspend rsync - added in 4.0
		return state->copyStage(SUSPENDCOPY);
	} else if (strcmp(cmd, CMD_VENAME) == 0) {
		// bug #65012 - added in 4.0
		return state->cmdCheckName(is);
	} else if (strcmp(cmd, CMD_CHECK_IPS) == 0) {
		// check IPs dependencies
		return cmdCheckIPs(is);
	} else if (strcmp(cmd, CMD_SECOND) == 0) {
		// second (fast) rsync, 'second'
		return state->copyStage(FASTCOPY);
	} else if (strcmp(cmd, CMD_SECOND_TRACKER) == 0) {
		// new version, rsync with track file
		return state->copyStage(FASTCOPY_TRACKER);
	} else if (strcmp(cmd, CMD_SECOND_BINDMOUNTS) == 0) {
		// second (fast) rsync, 'secondbindmounts'
		return state->copyStage(FASTCOPY_BINDMOUNTS);
	} else if (strcmp(cmd,CMD_PLOOP_COPY) == 0) {
		// copy ploop private exclude active disc image
		return state->cmdCopyPloopPrivate();
	} else if (strcmp(cmd, CMD_COPY_EXTERNAL_DISK) == 0) {
		// copy ploop private exclude active disc image
		return state->cmdCopyExternalDisk(is);
	} else if (strcmp(cmd,CMD_PLOOP_COPY_SYNC) == 0) {
		// copy ploop private exclude active disc image via rsync
		return state->cmdCopyPloopPrivateSync();
	} else if (strcmp(cmd, CMD_ONLINE_PLOOP_COPY_1) == 0) {
		// copy ploop active disc image in live CT
		return cmdCopyPloopImageOnline1(is);
	} else if (strcmp(cmd, CMD_ONLINE_PLOOP_COPY_2) == 0) {
		// copy dirty blocks of ploop active disc image in suspended CT
		return state->cmdCopyPloopImageOnline2(is);
	} else if (strcmp(cmd, CMD_CREATE_PLOOP_SNAPSHOT_NO_ROLLBACK) == 0) {
		// create snapshot on online pcs migration
		return state->cmdCreatePloopSnapshotNoRollback(is);
	} else if (strcmp(cmd, CMD_CREATE_PLOOP_SNAPSHOT) == 0) {
		// create snapshot on online pcs migration
		return state->cmdCreatePloopSnapshot(is);
	} else if (strcmp(cmd, CMD_MERGE_PLOOP_SNAPSHOT) == 0) {
		// mergesnapshot on online pcs migration
		return state->cmdDeletePloopSnapshot(is);
	} else if (strcmp(cmd, CMD_MOUNT_PLOOP) == 0) {
		// mount ploop for migration with convert zfs4 to ext4
		return cmdMountPloop(is);
	} else if (strcmp(cmd, CMD_COPY_PLOOP_ROOT) == 0) {
		// copy remote content to mounted ploop root
		return state->cmdCopyPloopRoot();
	} else if (strcmp(cmd, CMD_COPY_PLOOP_BINDMOUNTS) == 0) {
		// copy remote bind-mounts content to mounted ploop root
		return state->cmdCopyPloopBindmounts();
	} else if (strcmp(cmd, CMD_COPY_VZPACKAGES) == 0) {
		// copy list of installed into CT vzpackages and templates
		return state->cmdCopyVzPackages();
	} else if (strcmp(cmd, CMD_FINAL) == 0) {
		// post migrate: Ve start, 'post'
		return cmdFinalStage(is);
	} else if (strcmp(cmd, CMD_UNDUMP) == 0) {
		return state->undump();
	} else if (strcmp(cmd, CMD_NON_FINAL_RESUME) == 0) {
		return state->resume_non_fatal();
	} else if (strcmp(cmd, CMD_RESUME) == 0) {
		return state->resume();
	} else if (strcmp(cmd, CMD_NATIVE_QUOTA_SET) == 0) {
		// turn off quota, and apply 2-level limits from source
		return state->copySetNativeQuota(is);
	} else if (strcmp(cmd, CMD_CHECKLICENSE) == 0) {
		// checking - all added in 4.0
		return state->cmdCheckLicense();
	} else if (strcmp(cmd, CMD_CHECK_DISKSPACE) == 0) {
		// checking - all added in 4.0
		return state->cmdCheckDiskSpace(is);
	} else if (strcmp(cmd, CMD_CHECK_TECHNOLOGIES) == 0) {
		// checking - all added in 4.0
		return cmdCheckTechnologies(is, os);
	} else if (strcmp(cmd, CMD_CHECKRATE) == 0) {
		// checking - all added in 4.0
		return state->cmdCheckRate();
	} else if (strcmp(cmd, CMD_CHECK_CLUSTER) == 0) {
		// checking - all added in 4.0
		return state->cmdCheckClusterID(is, os);
	} else if (strcmp(cmd, CMD_CHECK_CLUSTER_DUMP) == 0) {
		// checking - all added in 4.0
		return state->cmdCheckClusterDump(is, os);
	} else if (strcmp(cmd, CMD_CHECK_SHARED_PRIV) == 0) {
		// checking - all added in 4.0
		return state->cmdCheckSharedPriv(is, os);
	} else if (strcmp(cmd, CMD_CHECK_SHARED_FILE) == 0) {
		return state->cmdCheckSharedFile(is, os);
	} else if (strcmp(cmd, CMD_CHECK_SHARED_DUMP) == 0) {
		// checking - all added in 4.0
		return state->cmdCheckSharedDump(is, os);
	} else if (strcmp(cmd, CMD_CHECK_CLUSTER_TMPL) == 0) {
		// checking - all added in 4.0
		return state->cmdCheckClusterTmpl(is, os);
	} else if (strcmp(cmd, CMD_CHECK_SHARED_TMPL) == 0) {
		// checking - all added in 4.0
		return state->cmdCheckSharedTmpl(is, os);
	} else if (strcmp(cmd, CMD_CLUSTER_DUMPCOPY) == 0) {
		// checking - all added in 4.0
		return state->cmdClusterDumpCopy(is);
	} else if (strcmp(cmd, CMD_CHECK_KEEP_DIR) == 0) {
		// checking - all added in 4.0
		return state->cmdCheckKeepDir(os);
	} else if (strcmp(cmd, CMD_CHECK_OPTIONS) == 0) {
		// added in 4.0.1
		return state->cmdCheckOptions(is, os);
	} else if (strcmp(cmd, CMD_CHECK_KERNEL_MODULES) == 0) {
		// added in 4.6.1
		return state->cmdCheckKernelModules(is);
	} else if (strcmp(cmd, CMD_CONFSET) == 0) {
		// upload VE config, and update it
		return state->copySetConf();
	} else if (strcmp(cmd, CMD_PING) == 0) {
		/* for debug purposes .
		??? - migsrcremote has not this command */
		return 0;
	} else if (strcmp(cmd, CMD_VERSION) == 0) {
		return cmdVersion(is, os);
	} else if (strcmp(cmd, CMD_CPT_VER) == 0) {
		// check cpt image version
		return state->cmdCheckCPTVersion(is);
	} else if (strcmp(cmd, CMD_CAPS) == 0) {
		// check capabilities
		return cmdCapabilities(os);
	} else if (strcmp(cmd, CMD_SLMONLY) == 0) {
		/* will receive slm-only containers from Vz <= 4.6
		   (https://jira.sw.ru/browse/PCLIN-29285) */
		return 0;
	} else if (strcmp(cmd, CMD_SWAPCH ) == 0) {
		// create new channel for lazy migration
		return cmdCreateSwapChannel();
	} else if (strcmp(cmd, CMD_ITERCH) == 0) {
		// create new channel for iteration migration - added in 4.0
		return cmdCreateIterChannel(is);
	} else if (strcmp(cmd, CMD_INVERTLAZY) == 0) {
		// invert LAZY flag for iteration migration - added in 4.0
		return cmdInvertLazyFlag();
	} else if (strcmp(cmd, CMD_SYNCTT) == 0) {
		return state->cmdTemplateSync(is);
	} else if (strcmp(cmd, CMD_ADJUST_TMO) == 0) {
		return cmdAdjustTimeout(is, os);
	} else if (strcmp(cmd, CMD_STOP) == 0) {
		// just a finish
		return 0;
	} else if (strcmp(cmd, CMD_HA_CLUSTER_NODE_ID) == 0) {
		return state->cmdHaClusterNodeID(is, os);
	} else if (strcmp(cmd, CMD_CHECK_PLOOP_FORMAT) == 0) {
		return state->cmdCheckPloopFormat(is);
	}
	if (VZMoptions.remote_version < MIGRATE_VERSION_401) {
		rc = putErr(MIG_ERR_PROTOCOL,
			MIG_MSG_UNKNOWN_CMD, cmd);
	} else {
		/* starting with protocol version 401 will
		   send a reply 'Unknown command' and continue */
		rc = putErr(MIG_ERR_UNKNOWN_CMD,
			MIG_MSG_UNKNOWN_CMD, cmd);
	}
	return rc;
}

static int doReply(int status_, const std::string& message_)
{
	return MigrateStateCommon::channel.sendReply(status_, "%s",
			status_ ? getError() : message_.c_str());
}

static int doGoodbye(int status_, const std::string& message_)
{
	if (0 != status_)
		return doReply(status_, message_);

	// success cleaning
	state->doCleaning(SUCCESS_CLEANER);
	int output = doReply(status_, message_);
	if (0 == output)
	{
		// clean MigrateState Cleaners
		state->erase();
		xdelete(state);
	}
	return output;
}

int main_loop()
{
	int code;

	while (const char * str = MigrateStateCommon::channel.readPkt(PACKET_SEPARATOR, &code))
	{
		istringstream is(str);
		int rcode = -1, e = 0;
		ostringstream os;
		string cmd;

		if ((is >> cmd) == NULL)
			return putErr(MIG_ERR_PROTOCOL, MIG_MSG_PROTOCOL);

		logger(LOG_DEBUG, "Command : %s", cmd.c_str());
		rcode = proc_cmd(cmd.c_str(), is, os);
		if (rcode != 0)
			logger(LOG_DEBUG, "error [%d] : %s", rcode, getError());

		if (cmd.compare(CMD_FINAL) == 0 ||
		        cmd.compare(CMD_RESUME) == 0 ||
		        cmd.compare(CMD_FINTEMPL) == 0 ||
		        cmd.compare(CMD_STOP) == 0)
		{
			e = doGoodbye(rcode, os.str());
			if (0 == e)
			{
				if (isOptSet(OPT_PS_MODE))
					break;
			}
		}
		else
		{
			e = doReply(rcode, os.str());
		}
		if (0 != e)
			return e;
		if (rcode == MIG_ERR_PROTOCOL || rcode == MIG_ERR_TRANSMISSION_FAILED)
			break;
	}
	return 0;
}
