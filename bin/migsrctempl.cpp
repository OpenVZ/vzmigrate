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

#include <libgen.h>
#include <sstream>
#include <vzctl/libvzctl.h>

#include "migsrctempl.h"
#include "migssh.h"
#include "common.h"
#include "bincom.h"
#include "remotecmd.h"
#include "channel.h"

MigrateStateTemplate::MigrateStateTemplate(const std::string& id)
	: srcTempl(new TmplEntryEz(id))
{
}

int MigrateStateTemplate::doMigration()
{
	const char* DUMMY_DEST = "0.0.0.0:/dummy";
	int rc;
	std::string lastmark;

	// bug 57973 (but in agent mode source don't call ssh)
	// ssh connection kill moved to main function (#79439)
	//if (!isOptSet(OPT_AGENT))
	//	addCleaner(clean_channel, &channel, NULL, ANY_CLEANER);

	// init stage
	rc = srcTempl->init();
	if (rc != 0)
		return rc;
	if ((rc = srcTempl->list()))
		return rc;

	logger(LOG_INFO, "Copy %s %s %s", srcTempl->m_id.c_str(),
		srcTempl->m_path.c_str(), srcTempl->m_tpath.c_str());

	rc = srcTempl->getLastVersion(&lastmark);
	if (rc != 0)
		return rc;

	// Send initialization command
	rc = channel.sendCommand(CMD_INITEMPL " %s %s", srcTempl->m_id.c_str(),
		lastmark.c_str());
	if (rc != 0) {
		if (rc == MIG_ERR_EXISTS && (isOptSet(OPT_FORCE) || isOptSet(OPT_PS_MODE))) {
			// Display warning and continue
			logger(LOG_WARNING, "%s", getError());
		} else {
			return rc;
		}
	}

	if (isOptSet(OPT_AGENT)) {
		channel.sendPkt(PACKET_SEPARATOR, CMD_VERSION " %d", VZMoptions.version);
		int errcode = 0;
		const char* reply = channel.readReply(&errcode);
		if (reply == NULL)
			return putErr(MIG_ERR_CONN_BROKEN, MIG_MSG_REPLY);
		if (errcode == MIG_ERR_PROTOCOL) {
			VZMoptions.remote_version = MIGRATE_VERSION_OLD;
		} else if (errcode != 0) {
			return putErr(errcode, "%s", reply);
		} else {
			VZMoptions.remote_version = atoi(reply);
		}
	}

	// Check technologies
	if ((rc = checkTechnologies()) == MIG_ERR_TECHNOLOGIES) {
		if (!isOptSet(OPT_SKIP_TECHNOLOGIES) && !isOptSet(OPT_FORCE))
			return rc;
	} else if (rc != 0) {
		return rc;
	}

	if ((rc = adjustTimeout(&VZMoptions.tmo)))
		return rc;

	// Copy template directory
	if (!isOptSet(OPT_DRY_RUN)) {
		std::list<std::string> args;
		std::string srcpath = srcTempl->m_path + "/";

		// Lock template
		if ((rc = srcTempl->lock()))
			return rc;

		if (isOptSet(OPT_PS_MODE))
			args.push_back("--delete");

		args.push_back(srcpath);
		args.push_back(DUMMY_DEST);
		rc = remoteRsyncSrc(CMD_FIRSTEMPL, true, args);

		// Unlock template
		srcTempl->unlock();

		if (rc != 0)
			return rc;

		// For PS_MODE send template area and cache file too if OS template cached
		if (!srcTempl->isAppTemplate() && isOptSet(OPT_PS_MODE)) {
			options_vztt* opts;
			char** vzdir;
			char cache_path[PATH_MAX + 1];

			// Get ezdir list for VE
			opts = vztt_options_create();
			if (opts == NULL)
				return putErr(MIG_ERR_VZTT, "vztt_options_create() error");

			vztt_options_set_force(isOptSet(OPT_FORCE), opts);
			rc = vztt2_get_cache_vzdir(srcTempl->getOsTemplate(), opts,
				cache_path, sizeof(cache_path), &vzdir);
			vztt_options_free(opts);
			if (rc == VZT_TMPL_NOT_CACHED) {
				logger(LOG_INFO, "OS template \"%s\" is not cached",
					srcTempl->getOsTemplate());
			} else if (rc) {
				return putErr(MIG_ERR_VZTT,
					"vztt2_get_cache_vzdir() error, retcode=%d", rc);
			} else {
				if (access(cache_path, F_OK) == 0)
					rc = copyEZDirSocket(vzdir);
				for (int i = 0; vzdir[i]; i++)
					free((void *)vzdir[i]);
				free((void *)vzdir);

				if (rc == 0) {
					char cmd[BUFSIZ];
					std::list<std::string> args;

					logger(LOG_INFO, "Copying tarball \"%s\"", cache_path);
					args.clear();
					args.push_back(cache_path);
					args.push_back(DUMMY_DEST);
					snprintf(cmd, sizeof(cmd),
						CMD_COPY_EZCACHE " %s", basename(cache_path));
					if ((rc = remoteRsyncSrc(cmd, false, args)))
						return rc;
				}
			}
		}
	}

	rc = channel.sendCommand(CMD_FINTEMPL);
	if (rc != 0)
		return rc;

	return 0;
}

int MigrateStateTemplate::checkTechnologies()
{
	int rc;
	char mask_str[ITOA_BUF_SIZE];

	if (VZMoptions.remote_version < MIGRATE_VERSION_400)
		return 0;

	logger(LOG_INFO, "Checking technologies");

	unsigned long tech_mask = 0;
	if ((rc = srcTempl->getMaskTechnologies(&tech_mask)))
		return rc;

	if (tech_mask == 0) {
		logger(LOG_INFO, "Technologies mask is empty, skipped");
		return 0;
	}

	snprintf(mask_str, sizeof(mask_str), "%lu", tech_mask);
	std::ostringstream outStr;
	outStr << CMD_CHECK_TECHNOLOGIES << " " << mask_str;
	logger(LOG_DEBUG, "%s",  outStr.str().c_str());

	channel.sendPkt(PACKET_SEPARATOR, outStr.str().c_str());
	int errcode = 0;
	const char* reply = channel.readReply(&errcode);
	if (reply == NULL)
		return putErr(MIG_ERR_CONN_BROKEN, MIG_MSG_REPLY);
	if (errcode != 0)
		putErr(errcode, "%s", reply);

	std::istringstream is(reply);
	std::string cmd;
	unsigned long utech = 0;

	if ((is >> cmd >> utech) == NULL || cmd.compare(CMD_CHECK_TECHNOLOGIES) != 0)
		return putErr(MIG_ERR_PROTOCOL, MIG_MSG_PROTOCOL);

	if (utech) {
		unsigned long tech;
		char buf[100];
		const char* str;

		buf[0] = '\0';
		for (size_t i = 0; i < sizeof(utech); i++) {
			tech = utech & (1 << i);
			if (tech == 0)
				continue;
			if ((str = vzctl2_tech2name(tech)) == NULL)
				continue;
			strncat(buf, " ", sizeof(buf)-strlen(buf)-1);
			strncat(buf, str, sizeof(buf)-strlen(buf)-1);
		}
		return putErr(MIG_ERR_TECHNOLOGIES, MIG_MSG_TECHNOLOGIES, buf);
	}

	return 0;
}

/*
 * Copy list of directories of EZ template area via one sockets.
 */
int MigrateStateTemplate::copyEZDirSocket(char* const* const vzdir)
{
	int rc = 0;
	char buf[BUFSIZ];
	char dir[PATH_MAX + 1];
	char listfile[PATH_MAX + 1];
	char* const argv[] = {
		(char*)BIN_TAR,
		(char*)"-c",
		(char*)"-S",
		(char*)"--ignore-failed-read",
		(char*)"--numeric-owner",
		(char*)"-f",
		(char*)"-",
		(char*)"-C",
		dir,
		(char*)"-T",
		listfile,
		NULL
		};

	if (VZMoptions.tmpl_data_sock == -1)
		return putErr(MIG_ERR_VZSOCK, "tmpl_data_sock is closed");

	rc = fillEZDirList(vzdir, dir, sizeof(dir), listfile, sizeof(listfile));
	if (rc)
		return rc;

	if (strlen(dir) == 0)
		// Nothing to copy
		return 0;

	logger(LOG_INFO, "copy ez template area directories from %s", dir);
	if (isOptSet(OPT_DRY_RUN))
		goto cleanup;

	logger(LOG_INFO, "copy %s", dir);
	snprintf(buf, sizeof(buf), CMD_COPY_EZDIR_TAR " %s", dir);

	// Send command to destination and wait ack
	if ((rc = ch_send_str(&channel.ctx, channel.conn, buf)))
		goto cleanup;

	// Copy ez directories
	do_block(VZMoptions.tmpl_data_sock);
	rc = vzm_execve((char* const*)argv, NULL, VZMoptions.tmpl_data_sock,
		VZMoptions.tmpl_data_sock, NULL);

	// Close template socket to terminate tar on destination side
	close(VZMoptions.tmpl_data_sock);
	VZMoptions.tmpl_data_sock = -1;

	if (rc)
		goto cleanup;

	rc = channel.readReply();

cleanup:
	unlink(listfile);
	return rc;
}

/*
 * Check EZ template packages (directories) on target node, put nonexistance
 * into <file> file and put template directory into <dir>.
 */
int MigrateStateTemplate::fillEZDirList(char* const* const vzdir, char* dir,
	unsigned dsize, char* file, unsigned fsize)
{
	int rc = 0;
	char tmpdir[PATH_MAX + 1];
	char path[PATH_MAX + 1];
	int fd;
	char buf[BUFSIZ];
	long lexist;
	int i;
	char* p;

	if (get_tmp_dir(tmpdir, sizeof(tmpdir)))
		tmpdir[0] = '\0';
	snprintf(file, fsize, "%s/listfile.XXXXXX", tmpdir);
	if ((fd = mkstemp(file)) == -1)
		return putErr(MIG_ERR_SYSTEM, "mkstemp(%s)", file);

	// Check ez directories on remote host
	dir[0] = '\0';
	for (i = 0; vzdir[i]; i++) {
		snprintf(buf, sizeof(buf), CMD_CHECK_EZDIR " %s", vzdir[i]);
		if ((rc = sendRequest(buf, &lexist)))
			break;
		if (lexist)
			continue;
		strncpy(path, vzdir[i], sizeof(path));
		p = basename(path);
		write(fd, p, strlen(p));
		write(fd, "\n", 1);
		if (strlen(dir) == 0)
			strncpy(dir, dirname(path), dsize);
	}
	close(fd);

	if (rc)
		unlink(file);

	return rc;
}
