/* $Id$
 *
 * Copyright (c) SWsoft, 2006-2007
 *
 */
#define _STREAM_COMPAT
#include <fstream>

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
#include <vzctl/libvzctl.h>


#include "server.h"
#include "vzacompat.h"
#include "channel.h"

#include <memory>
#include <string>
#include <map>

using namespace std;

/* global vz config data */
struct vz_data *vzcnf = NULL;

void *istorage_ctx = NULL;

extern pid_t tar_dst_pid;

extern "C" {
// set special function for data transter - restore stdout & stderr before
// and redirect to null after (https://jira.sw.ru/browse/PSBM-11287)
int vzmdest_send(
		struct vzsock_ctx *ctx,
		void *conn,
		const char *data,
		size_t size)
{
	int ret;

	if ((ret = vzsock_send(ctx, conn, data, size))) {
		/* to avoid call of vzsock_send() via logging */
		syslog(LOG_ERR, "vzsock_send() return %d", ret);
		return MIG_ERR_VZSOCK;
	}

	return 0;
}
}

static void exitM(int rc)
{
	delete g_veList;
	delete g_ctidMap;
	exit(-rc);
}

static int initializeVEs()
{
	g_veList = new CNewVEsList();
	if (g_veList == NULL)
		return putErr(MIG_ERR_SYSTEM, MIG_MSG_SYSTEM);

	g_ctidMap = new std::map<std::string, std::string>();
	if (g_ctidMap == NULL)
		return putErr(MIG_ERR_SYSTEM, MIG_MSG_SYSTEM);

	// initialize VEs, check status and do locking
	for (VEOptEntries::const_iterator it = VZMoptions.veMigrateList.begin();
		it != VZMoptions.veMigrateList.end(); ++it)
	{
		VEObj * ve = new VEObj((*it)->dst_ctid);
		if (ve == NULL)
			return putErr(MIG_ERR_SYSTEM, MIG_MSG_SYSTEM);

		(*g_veList)[std::string(ve->ctid())] = ve;
		(*g_ctidMap)[std::string((*it)->src_ctid)] = std::string(ve->ctid());

		ve->setPrivate((*it)->priv_path);
		ve->setRoot((*it)->root_path);
		int rc = ve->init_empty();
		if (rc != 0)
			return rc;
	}

	return 0;
}

void sigterm(int signum)
{
	logger(LOG_ERR, VZM_MSG_TERM);

	xdelete(state);

	// send sigterm to all processes in group
	kill(0, signum);
	// kil tar server - vzmsrc start this process via ssh
	if (tar_dst_pid != -1) {
		kill(tar_dst_pid, signum);
		tar_dst_pid = -1;
	}
	exitM(MIG_ERR_TERM);
}

/* this function call by logger() & putErr() to send message to client */
static void printOut(int level, const char * str)
{
	if (!MigrateStateCommon::channel.isConnected())
		return;
	MigrateStateCommon::channel.sendErrMsg(
		level + MIG_ERR_DEBUG_OUT, "%s", str);
}

#define CONNECTION_TIMEOUT	100

static int backGround[2];

// vzmdest -agent need to goto background, to not be connected with
// calling process (vzagent) during migration
// also we need to do VE initializations (locks) in process that come to background
// 'cause VE lock depend on PID
static void gotoBackGroundStep1()
{
	if (pipe(backGround)) {
		logger(LOG_ERR, MIG_MSG_SYSTEM);
		exitM(MIG_ERR_SYSTEM);
	}

	pid_t pid = fork();
	if (pid < 0)
	{
		logger(LOG_ERR, MIG_MSG_SYSTEM);
		exitM(MIG_ERR_SYSTEM);
	}

	if (pid > 0)
	{
		// father
		close(backGround[1]);
		char dummy;
		if (read(backGround[0], &dummy, 1) != 1)
		{
			int status;
			if (::waitpid(pid, &status, 0) < 0)
			{
				logger(LOG_ERR, MIG_MSG_SYSTEM);
				exitM(MIG_ERR_SYSTEM);
			}
			exitM(-WEXITSTATUS(status));
		}
//logger(LOG_INFO, "!!! exitM(0)");
		exitM(0);
	}
}

#define DEVNULL		"/dev/null"
static void gotoBackGroundStep2()
{
	// redirect all IO descriptors to 'null'
	int devn;

	devn = ::open(DEVNULL, O_RDWR);
	if (devn < 0
	        || dup2(devn, STDIN_FILENO) < 0
	        || dup2(devn, STDOUT_FILENO) < 0
	        || dup2(devn, STDERR_FILENO) < 0)
		exitM(MIG_ERR_SYSTEM);

	assert(MigrateStateCommon::channel.isConnected());

	close(backGround[0]);
	if (::write(backGround[1], "dummy", 1) != 1)
		exitM(MIG_ERR_SYSTEM);
	close(backGround[1]);

	// wait for connection establishment with 'source' migrate part
	fd_set rset;
	FD_ZERO(&rset);
	FD_SET(MigrateStateCommon::channel.getFd(0), &rset);
	struct timeval tv =
	    {
		    CONNECTION_TIMEOUT, 0
	    };
	if (select(MigrateStateCommon::channel.getFd(0) + 1, &rset,
	           NULL, NULL, &tv) != 1)
		exitM(MIG_ERR_CONN_BROKEN);

	close(devn);
}

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

	if (strcmp(argv[0], BNAME_DEST) == 0)
		INIT_BIN(BIN_DEST, LOG_INFO, "vzmdest");
	else
	{
		logger(LOG_ERR, VZM_MSG_UNKBIN, argv[0]);
		exit(MIG_ERR_USAGE);
	}

	vzm_send = vzmdest_send;

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
		exit(rc);

	parse_options(argc, argv);

	init_sig_handlers(sigterm);
	// Apply IO limits if any
	vz_setiolimit();

	if (isOptSet(OPT_PS_MODE) || isOptSet(OPT_NOEVENT))
	{
		/*
		   to forbid to send vzevents by libvzctl to avoid race
		   between vzevents from vzctl and events from dispatcher's migration task
		   https://jira.sw.ru/browse/PSBM-9463
		*/
		vzctl2_set_flags(VZCTL_FLAG_DONT_SEND_EVT);
	}

	// Channel initialization
	if (isOptSet(OPT_AGENT))
	{
		/* assume old client, new client will redefine version
		   via "version" command in agent mode */
		VZMoptions.remote_version = MIGRATE_VERSION_250;

		if ((rc = vza_init_srv(&MigrateStateCommon::channel.ctx,
				&MigrateStateCommon::channel.conn)))
		{
			logger(LOG_ERR, MIG_MSG_CANT_CONN_SRC,
			       VZMoptions.src_addr, getError());
			exitM(rc);
		}
		gotoBackGroundStep1();
	}
	else if (isOptSet(OPT_PS_MODE))
	{
		rc = MigrateStateCommon::channel.createParallelsServerChannel();
		if (rc)
			exitM(rc);
//		open_logger("vzmdest");
//		print_func = printOutPsMode;
//		print_func = printOut;
		/* wait package version */
		char *reply;
		if ((reply = MigrateStateCommon::channel.readPkt(PACKET_SEPARATOR, &rc)) == NULL) {
			logger(LOG_ERR, "can't read package from client");
			exitM(MIG_ERR_PROTOCOL);
		}
		if (sscanf(reply, CMD_START_PARAMS "%d", &VZMoptions.remote_version) != 1)
		{
			logger(LOG_ERR, "invalid remote version : %s", reply);
			exitM(MIG_ERR_PROTOCOL);
		}
		/* send reply with version */
		rc = MigrateStateCommon::channel.sendPkt(PACKET_SEPARATOR, VZMDEST_REPLY, MIGRATE_VERSION);
		if (rc)
		{
			logger(LOG_ERR, "can't send package to client");
			exitM(rc);
		}
	}
	else
	{
		// migrations support only protocol version >= 250 (virtuozzo ?, 2.6.0, 3.0) on source.
		if (VZMoptions.remote_version < MIGRATE_VERSION_250)
		{
			MigrateStateCommon::channel.sendReply(MIG_ERR_CANT_CONNECT, "%s",
			                                      MIG_MSG_UNCOMPATIBILITY_SRC);
			exitM(MIG_ERR_CANT_CONNECT);
		}

		if ((rc = MigrateStateCommon::channel.createChannel()))
			exitM(MIG_ERR_CANT_CONNECT);
		// print reply for non-agent, and report with '\n' separator
		// after this packet will be with '\0' separator

		rc = MigrateStateCommon::channel.sendPkt('\n', VZMDEST_REPLY, MIGRATE_VERSION);
		if (rc != 0)
			exitM(rc);

		// OK connection was established,
		// so set special output report function (now all log/info/debug reports
		// go to in special form
		print_func = printOut;

		// stdout -> /dev/null
		// before in MigrateStateCommon::channel.createChannel we dup
		// it to another descriptor for communications
		// thus all unconrolled writes to stdout are zeroed.
		int fd;
		if ((fd = open("/dev/null", O_WRONLY)) == -1)
			return putErr(MIG_ERR_SYSTEM, "open(/dev/null) : %m");
		if (dup2(fd, STDOUT_FILENO) == -1)
			return putErr(MIG_ERR_SYSTEM, "setting STDOUT to NULL dup2() : %m");
		close(fd);
	}

	// initialize VEs
	rc = initializeVEs();
	if (rc != 0)
	{
		if (isOptSet(OPT_AGENT))
			logger(LOG_ERR, "%s", getError());
		else
			MigrateStateCommon::channel.sendReply(rc, "%s", getError());
		exitM(rc);
	}

	// post initialization
	if (isOptSet(OPT_AGENT))
	{
		gotoBackGroundStep2();
		print_func = printOut;
	}
	else if (!isOptSet(OPT_PS_MODE))
	{
		MigrateStateCommon::channel.sendReply(0, "");
	}

	main_loop();

	xdelete(state);

	vzctl2_lib_close();

	exitM(0);
}
