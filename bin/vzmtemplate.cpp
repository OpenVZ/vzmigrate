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

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <libgen.h>
#include <termios.h>
#include <vzctl/libvzctl.h>
#include <sstream>

#include "common.h"
#include "bincom.h"
#include "remotecmd.h"
#include "migsrcremote.h"
#include "migssh.h"
#include "migsrclocal.h"
#include "migsrctempl.h"
#include "ssl.h"
#include "ct_config.h"

/* global vz config data */
struct vz_data* vzcnf = NULL;

static void exitM(int code);

static MigrateStateCommon* conn = NULL;

extern int init_connection(MigrateStateCommon* st);

MigrateStateTemplate* state = NULL;

static void exitM(int code)
{
	/* and close ssh connection */
	if (!isOptSet(OPT_AGENT)) {
		if (conn)
			conn->channel.killSshChannel();
	}

	exit(code);
}

int main(int argc, char** argv)
{
	int rc;
	TemplOptEntries::const_iterator it;

	static struct vz_data vz_conf;

	/*
	 * Create new group because SIGTERM handler will
	 * redirect this signal to all procceses in group.
	 * If we will not do it, handler will terminate parent too
	 * https://jira.sw.ru/browse/PSBM-13885
	 */
	setpgrp();

	argv[0] = basename(argv[0]);
	INIT_BIN(BIN_TEMPL, LOG_INFO, "vzmtemplate");

	/* init vzctl */
	if ((rc = vzctl2_lib_init())) {
		logger(LOG_ERR, "vzctl initialize error %d", rc);
		exit(MIG_ERR_VZCTL);
	}

	/* read global vz config */
	vzcnf = &vz_conf;
	if ((rc = vz_data_load(vzcnf)))
		exitM(rc);

	/* suppress libvztt stderr and stdout */
	vztt_init_logger(VZPKGLOG, VZTT_QUIET);

	parse_options(argc, argv);

	// Unconditionally specify template as ez
	setOpt(OPT_EZTEMPLATE);

	if (isOptSet(OPT_PS_MODE)) {
		/*
		   to forbid to send vzevents by libvzctl to avoid race
		   between vzevents from vzctl and events from dispatcher's migration task
		   https://jira.sw.ru/browse/PSBM-9463
		*/
		vzctl2_set_flags(VZCTL_FLAG_DONT_SEND_EVT);
	}

	if ((conn = new MigrateStateCommon()) == NULL) {
		logger(LOG_ERR, "new() : %m");
		exitM(-MIG_ERR_SYSTEM);
	}

	if ((rc = init_connection(conn)))
		exitM(-rc);

	init_sig_handlers();

	for (it = VZMoptions.templMigrateList.begin();
		it != VZMoptions.templMigrateList.end(); it ++)
	{
		logger(LOG_INFO, "Copying template \"%s\"", it->c_str());

		state = new MigrateStateTemplate(*it);
		if (state == NULL) {
			logger(LOG_ERR, MIG_MSG_SYSTEM);
			exitM(-MIG_ERR_SYSTEM);
		}
		rc = state->doMigration();
		if (terminated) {
			logger(LOG_ERR, VZM_MSG_TERM);
			rc = MIG_ERR_TERM;
			/* cleanup routines shouldn't be affected by the terminated flag */
			terminated = 0;
		}
		xdelete(state);
		if (rc) {
			logger(LOG_ERR, "Can't copy template \"%s\" : %s",
				it->c_str(), getError());
			exitM(-rc);
		}
		logger(LOG_INFO, "Successfully completed");
	}

	/* and close ssh connection */
	if (!isOptSet(OPT_AGENT)) {
		conn->channel.killSshChannel();
	}
	delete conn;

	return 0;
}
