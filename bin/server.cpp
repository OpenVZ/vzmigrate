/*
 * Copyright (c) 2006-2017, Parallels International GmbH
 * Copyright (c) 2017-2019 Virtuozzo International GmbH. All rights reserved.
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
 * Our contact details: Virtuozzo International GmbH, Vordergasse 59, 8200
 * Schaffhausen, Switzerland.
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
	for (CNewVEsList::iterator it = begin(); it != end(); ++it) {
		delete it->second;
	}
}

CNewTemplsList::~CNewTemplsList()
{
	for (CNewTemplsList::iterator it = begin(); it != end(); ++it) {
		delete it->second;
	}
}

CNewVEsList * g_veList = NULL;
std::map<std::string, std::string> * g_ctidMap = NULL;
MigrateStateDstRemote * state = NULL;

CNewTemplsList* g_templList = NULL;
MigrateStateDstTempl* g_stateTempl = NULL;

static int cmdVersion(istringstream & is, ostringstream & os)
{
	int remote_version;
	if ((is >> remote_version) == NULL)
		return putErr(MIG_ERR_PROTOCOL, MIG_MSG_PROTOCOL);
	VZMoptions.remote_version = remote_version;
	if (VZMoptions.remote_version < MIGRATE_VERSION_400) {
		if (state && state->is_priv_on_shared)
			return putErr(MIG_ERR_SYSTEM,
				"Can't migrate this private area "
				"on shared FS (old version)");
	}

	// report version
	os << VZMoptions.version;
	return 0;
}

static int cmdCreateSwapChannel(void)
{
	return putErr(MIG_ERR_SYSTEM, "Lazy migration is not supported");
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

static int cmdCheckIPs(istringstream &)
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
		return putErr(MIG_ERR_PROTOCOL, MIG_MSG_PROTOCOL "0");

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
			return putErr(MIG_ERR_PROTOCOL, "Cann not find ctid %s in map", ctid.c_str());

		// map found, search list by dst_ctid
		it = g_veList->find(it2->second);
		if (it == g_veList->end())
			return putErr(MIG_ERR_PROTOCOL, MIG_MSG_PROTOCOL "2");
	}

	state = new MigrateStateDstRemote(it->second, options);
	if (state == NULL)
		return putErr(MIG_ERR_SYSTEM, MIG_MSG_SYSTEM);

	g_veList->erase(it);
	return state->initMigration();
}

static int cmdInitTemplMigration(istringstream & is)
{
	std::string pkg;
	std::string version;

	if ((is >> pkg >> version) == NULL)
		return putErr(MIG_ERR_PROTOCOL, MIG_MSG_PROTOCOL);

	CNewTemplsList::iterator it = g_templList->find(pkg);
	if (it == g_templList->end())
		return putErr(MIG_ERR_PROTOCOL, MIG_MSG_PROTOCOL);

	g_stateTempl = new MigrateStateDstTempl(it->second);
	if (g_stateTempl == NULL)
		return putErr(MIG_ERR_SYSTEM, MIG_MSG_SYSTEM);

	g_templList->erase(it);
	return g_stateTempl->initMigration(version);
}

static int cmdCheckTechnologies(istringstream & is, ostringstream & os)
{
	if (VZMoptions.bintype == BIN_DEST_TEMPL)
		return g_stateTempl->cmdCheckTechnologies(is, os);
	else
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

static int cmdCheckEZDir(istringstream & is, ostringstream & os)
{
	if (VZMoptions.bintype == BIN_DEST_TEMPL)
		return g_stateTempl->cmdCheckEZDir(is, os);
	else
		return putErr(MIG_ERR_PROTOCOL, MIG_MSG_PROTOCOL);
}

static int cmdCopyEZDirTar(istringstream & is)
{
	if (VZMoptions.bintype == BIN_DEST_TEMPL)
		return g_stateTempl->cmdCopyEZDirTar(is);
	else
		return putErr(MIG_ERR_PROTOCOL, MIG_MSG_PROTOCOL);
}

static int cmdMountPloop(istringstream & is)
{
	unsigned long ploop_size, create_size;
	int lmounted;

	if ((is >> ploop_size >> lmounted) == NULL)
		return putErr(MIG_ERR_PROTOCOL, MIG_MSG_PROTOCOL);

	if ((is >> create_size) == NULL)
		create_size = 0;

	return state->cmdMountPloop(ploop_size, create_size, lmounted);
}

/*
 * Log received command except few commands which must preserve connection in
 * consistent state for bidirectional communication.
 */
static void log_cmd(const std::string& cmd)
{
	if (cmd.compare(CMD_RUN_PHAUL_MIGRATION) != 0)
		logger(LOG_DEBUG, "Command : %s", cmd.c_str());
}

static bool check_cmd(const char* cmd)
{
	bool initCmd;
	bool stateCreated;

	if (VZMoptions.bintype == BIN_DEST_TEMPL) {
		initCmd = (strcmp(cmd, CMD_INITEMPL) == 0);
		stateCreated = (g_stateTempl != NULL);
	} else {
		initCmd = (strcmp(cmd, CMD_INIT) == 0);
		stateCreated = (state != NULL);
	}

	return ((initCmd && !stateCreated) || (!initCmd && stateCreated));
}

static int proc_cmd(const char *cmd, istringstream & is, ostringstream & os)
{
	int rc;

	if (!check_cmd(cmd))
		return putErr(MIG_ERR_PROTOCOL, MIG_MSG_PROTOCOL);

	if (strcmp(cmd, CMD_INIT) == 0) {
		return cmdInitMigration(is);
	} else if (strcmp(cmd, CMD_FIRST) == 0) {
		// first (full) rsync, 'first'
		return state->copyStage(SIMPLECOPY);
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
	} else if (strcmp(cmd, CMD_CHECK_EZDIR) == 0) {
		// checking - all added in 4.0
		return cmdCheckEZDir(is, os);
	} else if (strcmp(cmd, CMD_COPY_EZDIR_TAR) == 0) {
		// added in 4.0
		return cmdCopyEZDirTar(is);
	} else if (strcmp(cmd, CMD_CHECK_SHARED_PRIV) == 0) {
		// checking - all added in 4.0
		return state->cmdCheckSharedPriv(is, os);
	} else if (strcmp(cmd, CMD_CHECK_SHARED_FILE) == 0) {
		return state->cmdCheckSharedFile(is, os);
	} else if (strcmp(cmd, CMD_CHECK_CLUSTER_TMPL) == 0) {
		// checking - all added in 4.0
		return state->cmdCheckClusterTmpl(is, os);
	} else if (strcmp(cmd, CMD_CHECK_SHARED_TMPL) == 0) {
		// checking - all added in 4.0
		return state->cmdCheckSharedTmpl(is, os);
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
	} else if (strcmp(cmd, CMD_SLMONLY) == 0) {
		/* will receive slm-only containers from Vz <= 4.6
		   (https://jira.sw.ru/browse/PCLIN-29285) */
		return 0;
	} else if (strcmp(cmd, CMD_SWAPCH ) == 0) {
		// create new channel for lazy migration
		return cmdCreateSwapChannel();
	} else if (strcmp(cmd, CMD_INVERTLAZY) == 0) {
		// invert LAZY flag for iteration migration - added in 4.0
		return cmdInvertLazyFlag();
	} else if (strcmp(cmd, CMD_INITEMPL) == 0) {
		return cmdInitTemplMigration(is);
	} else if (strcmp(cmd, CMD_FIRSTEMPL) == 0) {
		return g_stateTempl->copyStage();
	} else if (strcmp(cmd, CMD_FINTEMPL) == 0) {
		return g_stateTempl->finalStage();
	} else if (strcmp(cmd, CMD_COPY_EZCACHE) == 0) {
		return g_stateTempl->cmdCopyEzCache(is);
	} else if (strcmp(cmd, CMD_SYNCTT) == 0) {
		return state->cmdTemplateSync(is);
	} else if (strcmp(cmd, CMD_ADJUST_TMO) == 0) {
		return cmdAdjustTimeout(is, os);
	} else if (strcmp(cmd, CMD_ADJUST_XXL_TMO) == 0) {
		return state->cmdAdjustXxlTimeout(is);
	} else if (strcmp(cmd, CMD_HA_CLUSTER_NODE_ID) == 0) {
		return state->cmdHaClusterNodeID(is, os);
	} else if (strcmp(cmd, CMD_CHECK_PLOOP_FORMAT) == 0) {
		return state->cmdCheckPloopFormat(is);
	} else if (strcmp(cmd, CMD_PREPARE_PHAUL_CONN) == 0) {
		return state->cmdPreparePhaulConn(is);
	} else if (strcmp(cmd, CMD_RUN_PHAUL_MIGRATION) == 0) {
		return state->cmdRunPhaulMigration();
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

static int doReply(const string &cmd, int status_, const std::string& message_)
{
	if (VZMoptions.remote_version >= MIGRATE_VERSION_702 &&
			(cmd == CMD_CONFSET ||
			 cmd == CMD_PLOOP_COPY_SYNC ||
			 cmd == CMD_FIRSTEMPL ||
			 cmd == CMD_COPY_EZCACHE))
		return 0;

	return MigrateStateCommon::channel.sendReply(status_, "%s",
			status_ ? getError() : message_.c_str());
}

static int doGoodbye(const string &cmd, int status_, const std::string& message_)
{
	if (0 != status_)
		return doReply(cmd, status_, message_);

	MigrateStateCommon* migrateState =
		((VZMoptions.bintype == BIN_DEST_TEMPL)
			? static_cast<MigrateStateCommon*>(g_stateTempl)
			: static_cast<MigrateStateCommon*>(state));

	// success cleaning
	migrateState->doCleaning(SUCCESS_CLEANER);

	int output = doReply(cmd, status_, message_);
	if (0 == output)
	{
		// clean MigrateState Cleaners
		migrateState->erase();
		if (VZMoptions.bintype == BIN_DEST_TEMPL)
			xdelete(g_stateTempl);
		else
			xdelete(state);
	}

	return output;
}

int main_loop()
{
	int code, rcode = 0;

	while (const char * str = MigrateStateCommon::channel.readPkt(PACKET_SEPARATOR, &code))
	{
		istringstream is(str);
		int e = 0;
		ostringstream os;
		string cmd;

		if ((is >> cmd) == NULL)
			return putErr(MIG_ERR_PROTOCOL, MIG_MSG_PROTOCOL);

		log_cmd(cmd);
		rcode = proc_cmd(cmd.c_str(), is, os);
		if (rcode != 0)
			logger(LOG_INFO, "cmd '%s' error [%d] : %s",
					cmd.c_str(), rcode, getError());

		if (cmd.compare(CMD_FINAL) == 0 ||
		        cmd.compare(CMD_RESUME) == 0 ||
		        cmd.compare(CMD_FINTEMPL) == 0)
		{
			e = doGoodbye(cmd, rcode, os.str());
			if (0 == e)
			{
				if (isOptSet(OPT_PS_MODE))
					break;
			}
		}
		else
		{
			e = doReply(cmd, rcode, os.str());
		}
		if (0 != e)
			return e;
		if (rcode == MIG_ERR_PROTOCOL || rcode == MIG_ERR_TRANSMISSION_FAILED)
			break;
	}
	return rcode;
}
