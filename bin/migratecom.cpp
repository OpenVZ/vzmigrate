/* $Id$
 *
 * Copyright (c) SWsoft, 2006-2007
 *
 */
#include <sys/wait.h>
#include <sys/statfs.h>
#include <mntent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <dirent.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <libgen.h>
#include <ploop/libploop.h>
#include <stdarg.h>
#include <sys/ioctl.h>
#include <sstream>

#include "remotecmd.h"
#include "migratecom.h"
#include "migssh.h"
#include "channel.h"
#include "common.h"
#include "bincom.h"

#include "veentry.h"
#include "ssl.h"
#include "remotecmd.h"

/*
   This is workaround:
   vzmsrc send full path for EZ template (with TEMPLATE variable from vz.conf).
   vzmdest check this path on dst node. But TEMPLATE differ on dst and src nodes,
   vzmdest will check and copy template area in wrong path.
   As workaround will cut out lase <step> subdirs from source path
   and add TEMPLATE before.
*/
int get_real_tmpl_path(
		const char *vztemplate,
		const char *src_path,
		int step,
		char *dst_path,
		size_t sz)
{
	char *p;
	int i;

	p = (char *)src_path + strlen(src_path) - 1;
	while((p > src_path) && (*p == '/')) p--;

	for (i = step; i > 0; i--) {
		while((p > src_path) && (*p != '/')) p--;
		if (p < src_path)
			return putErr(MIG_ERR_SYSTEM,
				"Bad path for template area : %s", src_path);
		while((p > src_path) && (*p == '/')) p--;
	}
	snprintf(dst_path, sz, "%s/%s", vztemplate, p + 2);
	return 0;
}

extern struct vz_data *vzcnf;

int CWD::chdir(const char * dir)
{
	assert(m_new_dir == NULL);
	if (getcwd(m_buf, sizeof(m_buf)) == NULL || ::chdir(dir) != 0)
		return -1;
	m_buf[sizeof(m_buf)-1] = 0;
	m_new_dir = dir;
	return 0;
}

int CWD::restore()
{
	assert(m_new_dir != NULL);
	return ::chdir(m_buf);
}

MigrateSshChannel MigrateStateCommon::channel;

MigrateStateCommon::MigrateStateCommon()
{
	erase_flag = 1;
	dst_name = NULL;
	use_sparse_opt = 1;

	m_nFlags = 0ULL;
}

MigrateStateCommon::~MigrateStateCommon()
{
	if (erase_flag)
		doCleaning(ERROR_CLEANER);

	if (dst_name)
	{
		free(dst_name);
		dst_name = 0;
	}

	for (vector<string>::const_iterator it =
	            tmpFiles.begin(); it != tmpFiles.end(); it ++)
	{
		unlink(it->c_str());
	}

	doCleaning(ANY_CLEANER);
}

void MigrateStateCommon::addCleaner(MigrateCleanFunc _func, const void * _arg1,
                                    const void * _arg2, int type)
{
	CleanActions & cl = GETCLEANER(type);
	MCleanEntry entry =
	{	func :	_func,
		arg1 :	_arg1,
		arg2 :	_arg2
	};
	cl.push(entry);
};

void MigrateStateCommon::delLastCleaner(int type)
{
	CleanActions & cl = GETCLEANER(type);
	assert(!cl.empty());
	cl.pop();
};

int MigrateStateCommon::doCleaning(int type)
{
	CleanActions & cl = GETCLEANER(type);
	while (!cl.empty())
	{
		const MCleanEntry & it = cl.top();
		cl.pop();

		int rc = it.func(it.arg1, it.arg2);
		if (rc)
		{
			/* will ignore errors on cleaning */
			logger(LOG_WARNING, "Can't do correct cleaning: %s",
			       getError());
		}
	}
	return 0;
}

int MigrateStateCommon::clean_rename(const void * arg1, const void * arg2)
{
	const char * from = (const char *) arg1;
	const char * to = (const char *) arg2;
	assert(from && to);
	logger(LOG_DEBUG, MIG_MSG_RST_RENAME, from, to);
	if (::rename(from, to) != 0)
		return putErr(MIG_ERR_COPY, MIG_MSG_MOVE,
		              from, to);
	return 0;
};

int MigrateStateCommon::clean_removeFile(const void * arg, const void *)
{
	const char * path = (const char*) arg;
	assert(path);
	logger(LOG_DEBUG, MIG_MSG_RST_RM_FILE, path);
	if (::remove(path) != 0)
	{
		if (errno != ENOENT)
			return putErr(-1, MIG_MSG_DELETE, path, strerror(errno));
		// may be entry was already deleted
		logger(LOG_DEBUG, "can not find entry for delete : [%s]", path);
	}
	return 0;
};

int MigrateStateCommon::clean_rmDir(const void * arg, const void *)
{
	const char * path = (const char*) arg;
	assert(path);
	logger(LOG_DEBUG, MIG_MSG_RST_RMDIR, path);
	if (::rmdir(path) != 0)
	{
		if (errno != ENOENT)
			return putErr(-1, MIG_MSG_DELETE, path, strerror(errno));
		// may be entry was already deleted
		logger(LOG_DEBUG, "can not find entry for delete : [%s]", path);
	}
	return 0;
};

int MigrateStateCommon::clean_removeDir(const void * arg, const void *)
{
	char path[PATH_MAX + 1];
	int i, status;
	pid_t pid, chpid;
	char *dir = (char *)arg;
	char *const rm_args[] =
	    {(char *)"rm", (char *)"-r", (char *)"-f", path, NULL };

	assert(arg);

	logger(LOG_DEBUG, MIG_MSG_RST_RM_DIR, dir);

	strncpy(path, dir, sizeof(path));
	path[sizeof(path)-1] = '\0';
	/* remove tail slashes */
	for(i = strlen(path)-1; (i >= 0) && (path[i] == '/'); --i)
		path[i] = '\0';
	if (strlen(path) == 0)
		return 0;

	strncat(path, ".XXXXXX", sizeof(path)-strlen(path)-1);
	if (mkdtemp(path) == NULL)
		return putErr(-1, "mkdtemp(%s) : %m", path);
	if (rmdir(path))
		return putErr(-1, "rmdir(%s) : %m", path);
	if (rename(dir, path)) {
		// copy function may haven't time to create dir
		logger(LOG_DEBUG, "can not rename : [%s] -> [%s]", dir, path);
		strncpy(path, dir, sizeof(path));
	}

	chpid = fork();
	if (chpid < 0) {
		return putErr(-1, "fork() : %m");
	} else if (chpid == 0) {
		int fd;
		fd = open("/dev/null", O_RDWR);
		/* redirect stdout to out and stdin to in */
		close(STDIN_FILENO); close(STDOUT_FILENO); close(STDERR_FILENO);
		dup2(fd, STDIN_FILENO);
		dup2(fd, STDOUT_FILENO);
		dup2(fd, STDERR_FILENO);
		close(fd);

		setsid();
		execvp(rm_args[0], rm_args);
		exit(MIG_ERR_SYSTEM);
	}
	while ((pid = waitpid(chpid, &status, WNOHANG)) == -1)
		if (errno != EINTR)
			break;

	if (pid < 0)
		return putErr(-1, "waitpid() return %d : %m", pid);

	// simply return and remain rm works offline
	return 0;
};

void MigrateStateCommon::addCleanerRemove(MigrateCleanFunc _func, const char *arg1,
		const char *arg2, int success)
{
	const char *_arg1, *_arg2 = NULL;

	tmpNames.push_back(arg1);
	_arg1 = tmpNames.back().c_str();

	if (arg2 != NULL) {
		tmpNames.push_back(arg2);
		_arg2 = tmpNames.back().c_str();
	}

	addCleaner(_func, _arg1, _arg2, success);
	logger(LOG_DEBUG, "add '%s' remove cleaner : %s %s",
			success ? "on success" : "on failure",
			arg1, arg2 ? arg2 : "");
}

void MigrateStateCommon::addCleanerRemove(MigrateCleanFunc _func, const char * name,
        int success)
{
	addCleanerRemove(_func, name, NULL, success);
}

void MigrateStateCommon::addCleanerRename(const char * src, const char * dest, int success)
{
	tmpNames.push_back(src);
	const char * src_path = tmpNames.back().c_str();
	tmpNames.push_back(dest);
	const char * dst_path = tmpNames.back().c_str();

	addCleaner(clean_rename, src_path, dst_path, success);
	logger(LOG_DEBUG, "add '%s' rename cleaner : %s -> %s",
	       success ? "on success" : "on failure", src_path, dst_path);
}

int MigrateStateCommon::clean_delEntry(const void * arg, const void *)
{
	VEObj * e = (VEObj *) arg;
	delete e;
	return 0;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 *	Next functions provide 'copy' functionality for different cases
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 */

/* Due to bug in ssh & non-well rsync working with read/write(s) in socket
we should introduce "timeout" on IO operation in rsync
*/

// single file copy
int MigrateStateCommon::h_copy(const char * src, const char * dst)
{
	addCleanerRemove(clean_removeFile, dst);
	if (copy_file(dst, src) != 0)
		return putErr(MIG_ERR_COPY, MIG_MSG_COPY_FILE,
		              src, dst, getError());
	return 0;
}

// file / directory rename
int MigrateStateCommon::h_rename(const char * src, const char * dst)
{
	struct stat st;

	if (stat(dst, &st) == 0) {
		if (S_ISDIR(st.st_mode)) {
			/* as workaround of #83304 until #83461 fix */
			//remove_directory(dst);
			/* workaround of #PSBM-14698 */
			clean_removeDir(dst, NULL);
		} else {
			unlink(dst);
		}
	}
	errno = 0;
	if (::rename(src, dst) != 0)
		return putErr(MIG_ERR_COPY ,MIG_MSG_MOVE, src, dst);
	addCleanerRename(dst, src);
	return 0;
}

// single file backup
int MigrateStateCommon::h_backup(const char * src)
{
	int rc;
	char tmpdir[PATH_MAX+1];
	char path[PATH_MAX + 1];
	int fd;
	string tmp;

	/* get temporary directory */
	if (get_tmp_dir(tmpdir, sizeof(tmpdir)))
		tmpdir[0] = '\0';

	snprintf(path, sizeof(path), "%s/vzmtmpfile.XXXXXX", tmpdir);
	if ((fd = mkstemp(path)) == -1)
			return putErr(MIG_ERR_SYSTEM, "mkstemp(%s) : %m", path);
	close(fd);
	tmp = path;

	// save for cleaning
	tmpFiles.push_back(tmp);
	if ((rc = copy_file(path, src)))
		return rc;
	// add clean renamer
	addCleanerRename(path, src);
	return 0;
}

const char ** MigrateStateCommon::getRsyncArgs()
{
	static const char *rsync_args[MAX_ARGS];
	static char sIOLimitKBPS[32];
	int i = 0;

	rsync_args[i++] = "rsync";
	rsync_args[i++] = "-q";
	rsync_args[i++] = "-a";
	rsync_args[i++] = "-H";
	if (use_sparse_opt)
		rsync_args[i++] = "--sparse";
	rsync_args[i++] = "--numeric-ids";
	rsync_args[i++] = "--timeout";
	rsync_args[i++] = VZMoptions.tmo.str;

	if( vzcnf && !(vzcnf->iolimit == 0 || vzcnf->iolimit == ULONG_MAX) )
	{
		sprintf(sIOLimitKBPS,"--bwlimit=%ld", vzcnf->iolimit / 1024 );
		rsync_args[i++] = sIOLimitKBPS;
	}

	if (isOptSet(OPT_WHOLE_FILE))
		rsync_args[i++] = "--whole-file";
	rsync_args[i++] = NULL;
	return rsync_args;
}

/* for path <path> get :
	cluster id <id>,
	mount point <mpoint>,
	local path on device <lpath>
*/
/* to get device name for path */
static int get_device_name_for_path(const char *path, char *devname, int size)
{
	const char *mntfile = "/proc/mounts";
	FILE *fp;
	struct stat st;
	struct mntent *mnt;
	dev_t rdev;

	if (stat(path, &st) != 0)
		return putErr(MIG_ERR_SYSTEM, "stat(%s) error", path);
	rdev = st.st_dev;

	if ((fp = setmntent(mntfile, "r")) == NULL)
		return putErr(MIG_ERR_SYSTEM, "setmntent(%s) error", mntfile);

	while ((mnt = getmntent(fp)) != NULL) {
		if (stat(mnt->mnt_fsname, &st) != 0)
			continue;

		if (!S_ISBLK(st.st_mode))
			continue;

		if (rdev == st.st_rdev)
			break;
	}
	endmntent(fp);
	if (mnt == NULL)
		return putErr(MIG_ERR_SYSTEM, "can not find device for %s", path);
	strncpy(devname, mnt->mnt_fsname, size);
	devname[size-1] = '\0';
	return 0;
}

int gfs_cluster_getid(
		const char *path,
		char *id,
		size_t isize)
{
	char name[GFS_LOCKNAME_LEN+100];
	char cmd[PATH_MAX+100];
	FILE *fd;
	int rc, status;
	char *p;
	const char *sb_lockproto = "sb_lockproto";
	const char *sb_locktable = "sb_locktable";
	struct statfs stfs;

	id[0] = '\0';

	if (statfs(path, &stfs))
		return putErr(MIG_ERR_SYSTEM, "statfs(%s) : %m", path);

	if (stfs.f_type != GFS_MAGIC)
		return 0;

	if ((access("/sbin/gfs_tool", X_OK) == 0) || (access("/usr/sbin/gfs_tool", X_OK) == 0))
	{
		snprintf(cmd, sizeof(cmd), "gfs_tool getsb %s 2>/dev/null", path);
	}
	else if ((access("/sbin/gfs2_edit", X_OK) == 0) || (access("/usr/sbin/gfs2_edit", X_OK) == 0))
	{
		char buf[PATH_MAX+1];
		/* gfs2_tool nas not 'getsb' command, will use 'gfs2_edit -p sb /dev/sdm' */
		if ((rc = get_device_name_for_path(path, buf, sizeof(buf))) != 0)
			return rc;
		snprintf(cmd, sizeof(cmd), "gfs2_edit -p sb %s 2>/dev/null", buf);
	} else {
		return putErr(MIG_ERR_SYSTEM,
			"%s is placed on gfs/gfs2, but gfs tool"
			" (gfs_tool or gfs2_edit) were not found",
			path);
	}

	logger(LOG_DEBUG, cmd);
	if ((fd = popen(cmd, "r")) == NULL)
		return putErr(MIG_ERR_SYSTEM, "popen('%s') error: %s",
				cmd, strerror(errno));

	while(fgets(name, sizeof(name), fd)) {
		if ((p = strchr(name, '\n')))
			*p = '\0';
		/* skip leading spaces */
		for(p = name; *p == ' '; p++) ;
		if (*p == '\0') continue;
/*
  sb_lockproto = lock_dlm
  sb_locktable = cluster_vzctl:test1
*/
		if (strncmp(sb_lockproto, p, strlen(sb_lockproto)) == 0) {
			/* sb_lockproto should be lock_dlm */
			for(p += strlen(sb_lockproto);
				*p == ' ' || *p == '='; p++) ;
			if (strcmp(p, "lock_dlm")) {
				id[0] = '\0';
				break;
			}
		} else if (strncmp(sb_locktable, p, strlen(sb_locktable)) == 0) {
			for(p += strlen(sb_locktable);
				*p == ' ' || *p == '='; p++) ;
			strncpy(id, p, isize);
			break;
		}
	}
	status = pclose(fd);
	if (WEXITSTATUS(status)) {
		rc = WEXITSTATUS(status);
		if (rc == 1) {
			/* gfs_tool return 1 for:
			can't open /vzt1/qqq/test: No such file or directory
			gfs_tool: /etc/ is not a GFS file/filesystem
			...? */
			return 0;
		}
		return putErr(MIG_ERR_SYSTEM, "'%s' error: rc=%d", cmd, rc);
	}

	return 0;
}

/*
 remoteRsyncSrc() and remoteRsyncDst() works via main ssh connection
 and use patched rsync (--fdin/--fdout options).
 To leave them for compatibility only.
*/
int MigrateStateCommon::remoteRsyncSrc(
		const char * cmd,
		bool withprogress,
		const list<string> &params)
{
	int rc;
	string_list ls;
	const char **rsync_args;
	int i;
	char **args;
	char in[ITOA_BUF_SIZE];
	char out[ITOA_BUF_SIZE];
	int ret;
	list<string>::const_iterator e;

	assert(channel.isConnected());

	string_list_init(&ls);
	if (isOptSet(OPT_SOCKET)) {
	 	strcpy(in, "0");
 		strcpy(out, "1");
	} else {
	 	snprintf(in, sizeof(in), "%u", channel.getFd(0));
		snprintf(out, sizeof(out), "%u", channel.getFd(1));
	}
	rsync_args = getRsyncArgs();
	for(i = 0; rsync_args[i]; i++)
		string_list_add(&ls, (char *)rsync_args[i]);
	string_list_add(&ls, "--fdin");
	string_list_add(&ls, in);
	string_list_add(&ls, "--fdout");
	string_list_add(&ls, out);
	string_list_add(&ls, "--write-timeout");
	string_list_add(&ls, VZMoptions.tmo.str);
	if (withprogress) {
		if (isOptSet(OPT_APROGRESS)) {
			string_list_add(&ls, "--progress-line");
		} else if (isOptSet(OPT_PROGRESS)) {
			string_list_add(&ls, "--progress-bar");
		}
	}
	for (e = params.begin(); e != params.end(); ++e)
		string_list_add(&ls, (char *)e->c_str());
	if ((rc = string_list_to_array(&ls, &args)))
		goto cleanup_0;

	/* send command to dst */
	if ((rc = channel.sendCommand(cmd)))
		goto cleanup_0;

	if (isOptSet(OPT_SOCKET)) {
		if ((ret = vzsock_send_data(&channel.ctx, channel.conn, (char * const *)args)))
		{
			rc = putErr(MIG_ERR_VZSOCK, "vzsock_send_data() return %d", ret);
			goto cleanup_0;
		}
	} else {
		if ((rc = vzm_execve(args, NULL, -1, -1, NULL)))
			goto cleanup_0;
	}

	if ((rc = channel.readReply()))
		goto cleanup_0;

cleanup_0:
	for (i = 0; args[i]; i++)
		free((void *)args[i]);
	free((void *)args);
	string_list_clean(&ls);
	return rc;
}

// call programm (now it is 'rsync') with redirected descriptors
int MigrateStateCommon::remoteRsyncDst(const char * const rsync_args[], ...)
{
	int rc = 0;
	char **args;
	va_list pvar;
	int i;
	string_list ls;
	char *p;

	string_list_init(&ls);

	for(i = 0; rsync_args[i]; i++)
		string_list_add(&ls, (char *)rsync_args[i]);
	va_start(pvar, rsync_args);
	while ((p = va_arg(pvar, char *)))
		string_list_add(&ls, p);
	va_end(pvar);
	if ((rc = string_list_to_array(&ls, &args)))
		goto cleanup_0;

	if (isOptSet(OPT_SOCKET))
		rc = run_rsync_srv(args);
	else
		rc = run_rsync_srv_old(args);

cleanup_0:
	for (i = 0; args[i]; i++)
		free((void *)args[i]);
	free((void *)args);
	string_list_clean(&ls);
	return rc;
}

// call programm (now it is 'rsync') with redirected descriptors
int MigrateStateCommon::run_rsync_srv_old(char *args[])
{
	int rc = 0;
	pid_t pid, chpid;
	int status;
	int fds[2];
	size_t size;
	int ret;

	assert(channel.isConnected());

	if (debug_level >= LOG_DEBUG)
		dump_args("", args);

	size = sizeof(fds);
	if ((ret = vzsock_get_conn(&channel.ctx, channel.conn,
			VZSOCK_DATA_FDPAIR, fds, &size)))
	{
		rc = putErr(MIG_ERR_VZSOCK,
			"vzsock_get_conn() return %d\n", ret);
		return rc;
	}

	// send readiness reply
	if ((rc = channel.sendPkt("|0|")))
		return rc;

	/* nothing output during rsync session: it use stdin & stdout
	   we can't use vzm_execve() */
	if ((chpid = fork()) < 0) {
		return putErr(MIG_ERR_SYSTEM, "fork() : %m");
	} else if (chpid == 0) {
		int fd;
		fd = open("/dev/null", O_WRONLY);
		dup2(fd, STDERR_FILENO);
		close(fd);
		dup2(fds[0], STDIN_FILENO);
		dup2(fds[1], STDOUT_FILENO);
		execvp(args[0], (char *const *)args);
		exit(MIG_ERR_SYSTEM);
	}

	while ((pid = waitpid(chpid, &status, 0)) == -1)
		if (errno != EINTR)
			break;

	if (pid < 0)
		return putErr(MIG_ERR_SYSTEM, "waitpid() : %m");

	if (check_exit_status(args[0], status))
		return MIG_ERR_TRANSMISSION_FAILED;

	return 0;
}

int MigrateStateCommon::run_rsync_srv(char *args[])
{
	int rc = 0;
	int ret;

	// send readiness reply
	if ((rc = channel.sendPkt("|0|")))
		return rc;

	if ((ret = vzsock_recv_data(&channel.ctx, channel.conn, (char * const *)args)))
		return putErr(MIG_ERR_VZSOCK, "vzsock_recv_data() return %d", ret);

	return 0;
}

/* send request and check reply */
int MigrateStateCommon::sendRequest(const char *buffer, long *retcode)
{
	int rc;
	const char * reply;

	logger(LOG_DEBUG, "Send command: %s", buffer);

	if ((rc = channel.sendBuf(buffer, strlen(buffer) + 1)))
		return rc;
	if ((reply = channel.readReply(&rc)) == NULL)
		return putErr(MIG_ERR_CONN_BROKEN, MIG_MSG_REPLY);
	if (rc)
		return putErr(rc, reply);
	if (rc == MIG_ERR_UNKNOWN_CMD)
		*retcode = 0;
	else if (rc)
		return putErr(rc, reply);
	else
		*retcode = atol(reply);
	return 0;
}

/* adjust timeout with recipient */
int MigrateStateCommon::adjustTimeout(struct timeout *tmo)
{
	int rc;
	long reply;
	char buffer[BUFSIZ];

	if (!tmo->customized)
		return 0;
	if (VZMoptions.remote_version < MIGRATE_VERSION_401)
		return 0;

	snprintf(buffer, sizeof(buffer), CMD_ADJUST_TMO " %ld", tmo->val);
	logger(LOG_DEBUG, buffer);

	if ((rc = sendRequest(buffer, &reply)))
		return rc;

	if (reply == 0) {
		tmo->customized = 0;
		tmo->val = IO_TIMEOUT;
		snprintf(tmo->str, sizeof(tmo->str), "%ld", tmo->val);
		logger(LOG_INFO, "Option --timeout is not supported "\
			"by recipient, will use default timeout value"\
			": %ld sec", tmo->val);
	}

	return 0;
}

/* create snapshot */
int MigrateStateCommon::ploopCreateSnapshot(const char *xmlconf, const char *guid)
{
	int rc = 0;
	int ret;
	struct ploop_disk_images_data *di;
	struct ploop_snapshot_param param;

	logger(LOG_DEBUG, "create snapshot %s for %s",
			guid, xmlconf);
	ret = ploop_open_dd(&di, xmlconf);
	if (ret)
		return putErr(MIG_ERR_PLOOP,
			"ploop_open_dd() : %s", ploop_get_last_error());

	memset(&param, 0, sizeof(param));
	param.guid = (char *)guid;
	ret = ploop_create_snapshot(di, &param);
	if (ret)
		rc = putErr(MIG_ERR_PLOOP,
			"ploop_create_snapshot() : %s [%d]", ploop_get_last_error(), ret);
	ploop_close_dd(di);

	return rc;
}

/* create temporary snapshot */
int MigrateStateCommon::ploopCreateTSnapshot(const char *xmlconf, const char *guid)
{
	int rc = 0;
	int ret;
	struct ploop_disk_images_data *di;
	struct ploop_tsnapshot_param param;

	logger(LOG_DEBUG, "create tmp snapshot %s for %s",
			guid, xmlconf);
	ret = ploop_open_dd(&di, xmlconf);
	if (ret)
		return putErr(MIG_ERR_PLOOP,
			"ploop_open_dd() : %s", ploop_get_last_error());

	memset(&param, 0, sizeof(param));
	param.guid = (char *)guid;
	param.component_name = (char *)VZMIGRATE_COMPONENT_NAME;

	ret = ploop_create_temporary_snapshot(di, &param, NULL);
	if (ret)
		rc = putErr(MIG_ERR_PLOOP,
			"ploop_create_temporary_snapshot() : %s [%d]", ploop_get_last_error(), ret);
	ploop_close_dd(di);

	return rc;
}

/* merge ploop snapshot */
int MigrateStateCommon::ploopMergeTopDelta(const char *xmlconf)
{
	int rc = 0;
	int ret;
	struct ploop_disk_images_data *di;
	struct ploop_merge_param param;

	logger(LOG_DEBUG, "merge top delta for %s", xmlconf);
	ret = ploop_open_dd(&di, xmlconf);
	if (ret)
		return putErr(MIG_ERR_PLOOP,
			"ploop_open_dd() : %s", ploop_get_last_error());
	memset(&param, 0, sizeof(param));
	ret = ploop_merge_snapshot(di, &param);
	if (ret)
		rc = putErr(MIG_ERR_PLOOP,
			"ploop_merge_snapshot() : %s [%d]", ploop_get_last_error(), ret);
	ploop_close_dd(di);

	return rc;
}

int MigrateStateCommon::ploopDeleteSnapshot(const char *xmlconf, const char *guid)
{
	int rc = 0;
	int ret;
	struct ploop_disk_images_data *di;

	logger(LOG_DEBUG, "delete snapshot %s for %s",
			guid, xmlconf);
	ret = ploop_open_dd(&di, xmlconf);
	if (ret)
		return putErr(MIG_ERR_PLOOP,
			"ploop_open_dd() : %s", ploop_get_last_error());

	ret = ploop_delete_snapshot(di, guid);
	if (ret)
		rc = putErr(MIG_ERR_PLOOP,
			"ploop_delete_snapshot() : %s [%d]", ploop_get_last_error(), ret);
	ploop_close_dd(di);

	return rc;
}

/* remove top delta offline */
int MigrateStateCommon::ploopDeleteTopDelta(const char *xmlconf)
{
	int rc = 0;
	int ret;
	struct ploop_disk_images_data *di;

	logger(LOG_DEBUG, "delete top delta for %s", xmlconf);
	ret = ploop_open_dd(&di, xmlconf);
	if (ret)
		return putErr(MIG_ERR_PLOOP,
			"ploop_open_dd() : %s", ploop_get_last_error());

	ret = ploop_delete_top_delta(di);
	if (ret)
		rc = putErr(MIG_ERR_PLOOP,
			"ploop_delete_top_delta() : %s [%d]", ploop_get_last_error(), ret);
	ploop_close_dd(di);

	return rc;
}

int MigrateStateCommon::ploopGetTopImageFileName(const char *xmlconf, char *path, size_t size)
{
	int rc = 0;
	int ret;
	struct ploop_disk_images_data *di;

	ret = ploop_read_disk_descr(&di, xmlconf);
	if (ret) {
		rc = putErr(MIG_ERR_PLOOP, "ploop_read_diskdescriptor(%s) : %s [%d]",
				xmlconf, ploop_get_last_error(), ret);
		goto cleanup;
	}
	ret = ploop_get_top_delta_fname(di, path, size);
	if (ret)
		rc = putErr(MIG_ERR_PLOOP,
			"ploop_get_top_delta_fname() : %s [%d]", ploop_get_last_error(), ret);
cleanup:
	ploop_free_diskdescriptor(di);

	return rc;
}

int MigrateStateCommon::runHaman(const char *ctid, const char *cmd, ...)
{
	char buf[100], argbuf[100];
	char * args[] = {(char *)BIN_HAMAN, (char *)"-i", (char *)"-q", (char *)cmd,
					 buf, NULL, NULL, NULL, NULL, NULL };
	struct stat st;
	int ndx;
	va_list pvar;

	if (stat(BIN_HAMAN, &st)) {
		// return success if haman does not exist
		if (errno == ENOENT)
			return 0;
		else
			return putErr(MIG_ERR_SYSTEM, "stat(" BIN_HAMAN ") : %m");
	}

	ndx = 5;
	va_start(pvar, cmd);
	if (strcmp(cmd, "rename") == 0) {
		// for rename specify new resource id
		snprintf(argbuf, sizeof(argbuf), "ct-%s", va_arg(pvar, const char*));
		args[ndx++] = (char *)argbuf;
	} else if (strcmp(cmd, "move-to") == 0) {
		strncpy(argbuf, va_arg(pvar, char *), sizeof(argbuf));
		args[ndx++] = (char *)argbuf;
	} else if (strcmp(cmd, "move-from") == 0) {
		strncpy(argbuf, va_arg(pvar, char *), sizeof(argbuf));
		args[ndx++] = (char *)argbuf;
	} else if (strcmp(cmd, "add") == 0) {
		char prio[10 + 1];
		char path[PATH_MAX + 1];

		// set HA priority value
		args[ndx++] = (char *)"--prio";
		snprintf(prio, sizeof(prio), "%u", va_arg(pvar, unsigned int));
		args[ndx++] = (char *)prio;
		args[ndx++] = (char *)"--path";
		strncpy(path, va_arg(pvar, char *), sizeof(path));
		args[ndx++] = (char *)path;
	}
	va_end(pvar);
	snprintf(buf, sizeof(buf), "ct-%s", ctid);
	return vzm_execve(args, NULL, -1, -1, NULL);
}

int MigrateStateCommon::getHaClusterNodeID(string & id)
{
	struct stat st;
	char buf[BUFSIZ];
	const char *cmd = BIN_HAMAN " -i -q info";
	FILE *fd;
	char *p = NULL;
	char *token = (char *)"ID :";

	if (stat(BIN_HAMAN, &st)) {
		if (errno == ENOENT)
			return 0;
		return putErr(MIG_ERR_SYSTEM, "stat(" BIN_HAMAN ") : %m");
	}

	if ((fd = popen(cmd, "r")) == NULL)
		return putErr(MIG_ERR_SYSTEM, "popen('%s') : %m", cmd);

	while (fgets(buf, sizeof(buf), fd)) {
		if (strncmp(buf, token, strlen(token)))
			continue;
		if ((p = strchr(buf, '\n')))
			*p = '\0';
		for (p = buf + strlen(token); isblank(*p); p++) ;
		break;
	}
	pclose(fd);

	if (p)
		id = p;
	return 0;
}

int MigrateStateCommon::applyPloopQuotaImpl(const char *qfile)
{
	int rc;
	FILE *fp;
	char buf[BUFSIZ];
	const char *token = "ugid:";
	char *p;
	unsigned ID, type;
	unsigned long long bsoft, bhard, isoft, ihard;
	const char * args[] = { buf, NULL };
	int status;
	VEObj *dstVE = getDstVE();

	if ((fp = fopen(qfile, "r")) == NULL)
		return putErr(MIG_ERR_SYSTEM, "fopen(%s) : %m", qfile);

	if ((rc = dstVE->getStatus(
			ENV_STATUS_RUNNING | ENV_STATUS_MOUNTED, &status)))
		goto cleanup_0;

	if (!(status & ENV_STATUS_RUNNING) && (rc = dstVE->start()))
		goto cleanup_0;

	while (fgets(buf, sizeof(buf), fp)) {
		if (strncmp(token, buf, strlen(token)))
			continue;
		for (p = buf + strlen(token); isblank(*p); p++) ;
		if (sscanf(p, "%u\t%u\t%llu\t%llu\t%llu\t%llu\t",
				&ID, &type, &bsoft, &bhard, &isoft, &ihard) != 6)
		{
			logger(LOG_ERR, "invalid quota record : '%s'", buf);
			continue;
		}
		if ((type != 0) && (type != 1))
			continue;
		snprintf(buf, sizeof(buf)-1, "setquota %s %u %llu %llu %llu %llu -a",
			(type == 0) ? "-u" : "-g", ID, bsoft, bhard, isoft, ihard);
		rc = dstVE->operateVE("exec", "Exec", args, 0);
		if (rc)
			break;
	}

	/* stop and mount CT to have VE_ROOT in the same
	 * state as it was before the start.
	 */
	if (!(status & ENV_STATUS_RUNNING))
		dstVE->stop(status & ENV_STATUS_MOUNTED);

cleanup_0:
	fclose(fp);
	return rc;
}

int MigrateStateCommon::checkDstIDFree(const VEObj &ve)
{
	int rc;
	int status;

	if ((rc = ((VEObj&)ve).getStatus(ENV_STATUS_EXISTS, &status)))
		return rc;

	if (status & ENV_STATUS_EXISTS)
		return putErr(MIG_ERR_EXISTS, MIG_MSG_EXISTS, ve.ctid());

	return 0;
}

int MigrateStateCommon::checkCommonDst(const VEObj &ve)
{
	if (ve.layout < VZCTL_LAYOUT_5 && !isOptSet(OPT_CONVERT_VZFS))
		return putErr(MIG_ERR_VZFS_ON_PSTORAGE,
			"Unable to migrate the Container.\n"
			"To migrate a Container based on the VZFS file system to a server\n"
			"using a Parallels Cloud Storage, use the --convert-vzfs option.\n"
			"Note: this will convert the Container to a new ploop-based layout.\n");

	return 0;
}

int is_path_on_shared_storage(const char *path, int *is_shared, long *fstype)
{
	int rc;
	struct statfs stfs;
	char cid[GFS_LOCKNAME_LEN+1];
	char mpoint[PATH_MAX+1];
	char lpath[PATH_MAX+1];

	if ((rc = split_path(path,
			mpoint, sizeof(mpoint), lpath, sizeof(lpath))))
		return rc;

	if (statfs(mpoint, &stfs))
		return putErr(MIG_ERR_SYSTEM, "statfs(%s) : %m", mpoint);
	if (fstype)
		*fstype = stfs.f_type;

	*is_shared = 0;
	if ((stfs.f_type == NFS_SUPER_MAGIC) || (stfs.f_type == PCS_SUPER_MAGIC)) {
		*is_shared = 1;
	} else if (stfs.f_type == GFS_MAGIC) {

		if ((rc = gfs_cluster_getid(mpoint, cid, sizeof(cid))))
			return rc;
		*is_shared = (strlen(cid));
	}
	return 0;
}

std::string rsync_dir(const char *str)
{
	std::string dir(str);

	if (*dir.rbegin() != '/')
		dir += "/";
	return dir;
}

std::string rsync_dir(const std::string &str)
{
	return rsync_dir(str.c_str());
}

std::string get_dd_xml(const std::string &dir)
{
	return dir + "/"DISKDESCRIPTOR_XML;
}

std::string get_dd_xml(const char *dir)
{
	return get_dd_xml(std::string(dir));
}

std::string convert_root_path(const char *root)
{
	std::ostringstream os;

	os << remove_trail_slashes(root) << ".ploop";

	return os.str();
}

std::string convert_bindmount_path(const char *root)
{
	std::ostringstream os;

	os << remove_trail_slashes(root) << ".ploop" << VE_PLOOP_BINDMOUNT_DIR;

	return os.str();
}

int check_free_space(const char *path, unsigned long long r_bytes, unsigned long long r_inodes)
{
	struct statfs st;
	unsigned long long a_bytes, a_inodes;

	if (statfs(path, &st) == -1)
		return putErr(MIG_ERR_SYSTEM, "statfs(%s) error", path);

	if (getuid() == 0)
		a_bytes = (unsigned long long)st.f_bfree * st.f_bsize;
	else
		a_bytes = (unsigned long long)st.f_bavail * st.f_bsize;

	a_inodes = (unsigned long long)st.f_ffree;

	logger(LOG_DEBUG, "bytes: free %llu, need %llu", a_bytes, r_bytes);
	logger(LOG_DEBUG, "inodes: free %llu, need %llu", a_inodes, r_inodes);

	if (a_bytes < r_bytes)
		return putErr(MIG_ERR_DISKSPACE, "%s free:%llu need:%llu bytes", path, a_bytes, r_bytes);

	/* "reiserfs allocates inodes dynamically, and always returns zero for available inodes" - #472684 */
	/* pstorage does the same https://jira.sw.ru/browse/PSBM-20442 */
	if ((st.f_type != PCS_SUPER_MAGIC) && (st.f_type != REISERFS_SUPER_MAGIC) && (a_inodes < r_inodes))
		return putErr(MIG_ERR_DISKSPACE, "%s free:%llu need:%llu inodes", path, a_inodes, r_inodes);

	return 0;
}
