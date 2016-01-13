/* $Id$
 *
 * Copyright (c) SWsoft, 2006-2007
 *
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <libgen.h>
#include <termios.h>

#include <vzctl/libvzctl.h>
#include <vz/libvzsock.h>

#include <sstream>

#include "common.h"
#include "bincom.h"
#include "remotecmd.h"

#include "migsrcremote.h"
#include "migssh.h"
#include "migsrclocal.h"
#include "ssl.h"

/* global vz config data */
struct vz_data *vzcnf = NULL;

void *istorage_ctx = NULL;
static void migrateVEs();

static void exitM(int code);

static MigrateStateCommon *conn = NULL;

extern int init_connection(MigrateStateCommon *st);

int main(int argc, char **argv)
{
	int rc;

	static struct vz_data vz_conf;
	memset((void *)&vz_conf, 0, sizeof(vz_conf));

	argv[0] = basename(argv[0]);

	/*
	 * Create new group because SIGTERM handler will
	 * redirect this signal to all procceses in group.
	 * If we will not do it, handler will terminate parent too
	 * https://jira.sw.ru/browse/PSBM-13885
	 */
	setpgrp();

	if (strcmp(argv[0], BNAME_LOCAL) == 0)
		INIT_BIN(BIN_LOCAL, LOG_INFO, "vzmlocal");
	else if (strcmp(argv[0], BNAME_SRC) == 0)
		INIT_BIN(BIN_SRC, LOG_INFO, "vzmsrc");
	else if (strcmp(argv[0], BNAME_MIGRATE) == 0) {
		logger(LOG_ERR, "BUG: vzmlocal should not be called as vzmigrate");
		exit(MIG_ERR_USAGE);
	} else if (strcmp(argv[0], BNAME_PM_C2C) == 0) {
		debug_level = LOG_INFO;
		; /* will init later */
	} else {
		logger(LOG_ERR, VZM_MSG_UNKBIN, argv[0]);
		exit(MIG_ERR_USAGE);
	}

	/* init vzctl */
	if ((rc = vzctl2_lib_init())) {
		logger(LOG_ERR, "vzctl initialize error %d", rc);
		exit(MIG_ERR_VZCTL);
	}

	/* suppress libvzctl stderr and stdout */
/* vzctl logger() conflict with vzmigrate logger(): FIXME
	vzctl2_set_log_quiet(1);*/

	/* read global vz config */
	vzcnf = &vz_conf;
	if ((rc = vz_data_load(vzcnf)))
		exitM(rc);

	/* dumpdir must be exist */
	if ((rc = make_dir(vzcnf->dumpdir, S_IRWXU|S_IRWXG|S_IRWXO)))
		exit(rc);

	parse_options(argc, argv);

	if (VZMoptions.bintype == BIN_SRC) {
		if ((conn = new MigrateStateCommon()) == NULL) {
			logger(LOG_ERR, "new() : %m");
			exitM(-MIG_ERR_SYSTEM);
		}

		if ((rc = init_connection(conn)))
			exitM(-rc);
	}

	init_sig_handlers();
	// Apply IO limits if any
	vz_setiolimit();

	if (isOptSet(OPT_PS_MODE)) {
		/*
		   to forbid to send vzevents by libvzctl to avoid race
		   between vzevents from vzctl and events from dispatcher's migration task
		   https://jira.sw.ru/browse/PSBM-9463
		*/
		vzctl2_set_flags(VZCTL_FLAG_DONT_SEND_EVT);
	}
	migrateVEs();

	/* and close ssh connection */
	if (VZMoptions.bintype == BIN_SRC) {
		if (!isOptSet(OPT_AGENT)) {
			if (conn)
				conn->channel.killSshChannel();
		}
	}

	return 0;
}

MigrateStateCommon * state = NULL;

static unsigned failedVE = 0;

static void exitM(int code)
{
	VEOptEntries::const_iterator it;

	/* and close ssh connection */
	if (VZMoptions.bintype == BIN_SRC) {
		if (!isOptSet(OPT_AGENT)) {
			if (conn)
				conn->channel.killSshChannel();
		}
	}

	it = VZMoptions.veMigrateList.begin();
	if (!failedVE || (unsigned)(*it)->dst_veid == failedVE)
		exit(code);
	ostringstream s;
	for (it = VZMoptions.veMigrateList.begin();
	        it != VZMoptions.veMigrateList.end() && (unsigned)(*it)->dst_veid != failedVE; ++it)
		s << " " << (*it)->dst_veid;
	logger(LOG_INFO, isOptSet(OPT_COPY) ? "Successfully created CT(s):%s"
	       : "Successfully moved CT(s):%s", s.str().c_str());

	exit(code);
}

static void migrateVEs()
{
	int rc;

	for (VEOptEntries::const_iterator it = VZMoptions.veMigrateList.begin();
	        it != VZMoptions.veMigrateList.end(); it ++)
	{
		logger(LOG_INFO, isOptSet(OPT_DRY_RUN) ? "The beginning of check " "CT#%d -> CT#%d, [%s], [%s] ..." : "Moving/copying"
			" CT#%d -> CT#%d, [%s], [%s] ...",
		       (*it)->src_veid, (*it)->dst_veid, (*it)->priv_path ?: "" ,
		       (*it)->root_path ?: "");

		failedVE = (*it)->dst_veid;

		unsigned dstve = ((*it)->dst_veid == (*it)->src_veid)
	                     ? (*it)->src_veid : (*it)->dst_veid;

		if (VZMoptions.bintype == BIN_SRC)
			state = new MigrateStateRemote((*it)->src_veid, dstve,
                               (*it)->priv_path, (*it)->root_path, (*it)->dst_name);
		else if (VZMoptions.bintype == BIN_LOCAL)
			state = new MigrateStateLocal((*it)->src_veid, dstve,
                              (*it)->priv_path, (*it)->root_path, (*it)->dst_name, (*it)->uuid);
		if (state == NULL) {
			logger(LOG_ERR, MIG_MSG_SYSTEM);
			exitM(-MIG_ERR_SYSTEM);
		}

		rc = static_cast<MigrateStateSrc *>(state)->doMigration();
		if (rc == MIG_ERR_DRYRUN)
			rc = 0;

		if (rc != 0)
		{
			if (isOptSet(OPT_DRY_RUN))
				logger(LOG_ERR, "Checking error: %s", getError());
			else
				logger(LOG_ERR, "Can't move/copy CT#%d -> CT#%d, [%s], [%s] : %s",
			               (*it)->src_veid, (*it)->dst_veid, (*it)->priv_path ?: "" ,
			               (*it)->root_path ?: "", getError());
		}
		else
			logger(LOG_INFO, "Successfully completed");

		if (terminated) {
			logger(LOG_ERR, VZM_MSG_TERM);
			rc = MIG_ERR_TERM;
			/* cleanup routines shouldn't be affected by the terminated flag */
			terminated = 0;
		}
		xdelete(state);
		if (rc)
			exitM(-rc);
	}
}

