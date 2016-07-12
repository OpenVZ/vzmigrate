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

#include <errno.h>
#include <iostream>
#include <sstream>
#include <vzctl/libvzctl.h>

#include "migdsttempl.h"
#include "bincom.h"
#include "util.h"

MigrateStateDstTempl::MigrateStateDstTempl(TmplEntryEz* entry)
	: dstTempl(entry)
{
}

int MigrateStateDstTempl::initMigration(const std::string& ver)
{
	logger(LOG_INFO, "Start of template %s migration", dstTempl->m_id.c_str());

	// Initialize template path
	dstTempl->m_path = dstTempl->m_tpath + ver;

	// Check target template
	return dstTempl->check();
}

int MigrateStateDstTempl::copyStage()
{
	int rc;
	std::string dst = dstTempl->m_path + "/";
	const char* path = dst.c_str();

	logger(LOG_DEBUG, "copyStage path:%s", path);

	char* start;
	if (path[0] == '/')
		start = (char*)strchr (path + 1, '/');
	else
		start = (char*)strchr (path, '/');

	while (start) {
		char* buffer = strdup (path);
		buffer[start - path] = '\0';
		errno = 0;
		if (mkdir(buffer, DEF_DIR_MODE) == -1 && errno != EEXIST) {
			int errtmp = errno;
			logger(LOG_DEBUG, "error creating path %s (%s)", path, strerror(errtmp));
			free (buffer);
			return -1;
		}
		if (errno != EEXIST)
			addCleanerRemove(clean_removeDir, buffer);
		free (buffer);
		start = strchr (start + 1, '/');
	}

	if (::mkdir(dst.c_str(), DEF_DIR_MODE) == 0) {
		addCleanerRemove(clean_removeDir, dst.c_str());
	} else {
		if (errno != EEXIST)
			return putErr(MIG_ERR_SYSTEM, MIG_MSG_SYSTEM);

		// errno == EEXIST

		// backup already existed template
		// ...
	}

	if ((rc = dstTempl->lock()))
		return rc;

	// Specify --ignore-existing if need to preserve existing template area files
	if (VZMoptions.remote_version < MIGRATE_VERSION_400) {
		rc = remoteRsyncDst(getRsyncArgs(), "--ignore-existing",
			"--server", "--delete", ".", dst.c_str(), NULL);
	} else if (isOptSet(OPT_PS_MODE)) {
		rc = remoteRsyncDst(getRsyncArgs(),
			"--server", "--delete", ".", dst.c_str(), NULL);
	} else {
		rc = remoteRsyncDst(getRsyncArgs(), "--ignore-existing",
			"--server", ".", dst.c_str(), NULL);
	}

	dstTempl->unlock();
	logger(LOG_DEBUG, "copyStage rc = %d", rc);
	return rc;
}

int MigrateStateDstTempl::finalStage()
{
	logger(LOG_INFO, "End of template %s migration", dstTempl->m_id.c_str());
	return 0;
}

int MigrateStateDstTempl::copyTarball(const std::string& mark)
{
	char path[PATH_MAX + 1];
	int rc;

	snprintf(path, sizeof(path), "%s-%s.tar.gz",
		dstTempl->m_path.c_str(), mark.c_str());
	if (access(path, F_OK) == 0)
		addCleanerRemove(clean_removeFile, path);

	// Specify --ignore-existing if need to preserve existing caches
	if (VZMoptions.remote_version < MIGRATE_VERSION_400) {
		rc = remoteRsyncDst(getRsyncArgs(), "--ignore-existing",
			"--server", "--delete", ".", path, NULL);
	} else {
		rc = remoteRsyncDst(getRsyncArgs(), "--server", ".", path, NULL);
	}

	return rc;
}

int MigrateStateDstTempl::cmdCheckTechnologies(std::istringstream& is,
	std::ostringstream& os)
{
	unsigned long technologies;
	if ((is >> technologies) == NULL)
		return putErr(MIG_ERR_PROTOCOL, MIG_MSG_PROTOCOL);

	logger(LOG_DEBUG, "cmdCheckTechnologies %u",  technologies);

	os << "checktechnologies " << vzctl2_check_tech(technologies);
	return 0;
}

/*
 * Search directory in EZ template area.
 */
int MigrateStateDstTempl::cmdCheckEZDir(std::istringstream& is,
	std::ostringstream& os)
{
	int rc;
	std::string ezdir;
	struct stat st;
	char path[PATH_MAX + 1];

	if ((is >> ezdir) == NULL)
		return putErr(MIG_ERR_PROTOCOL, MIG_MSG_PROTOCOL);

	if ((rc = get_real_tmpl_path(dstTempl->m_tpath.c_str(), ezdir.c_str(), 4,
		path, sizeof(path))))
		return rc;

	if ((stat(path, &st) == 0) && S_ISDIR(st.st_mode)) {
		os << "1";
	} else {
		os << "0";
		addCleanerRemove(clean_removeDir, path);
	}

	return 0;
}

/*
 * Copy EZ template area directories  via tar.
 */
int MigrateStateDstTempl::cmdCopyEZDirTar(std::istringstream& is)
{
	std::string tempPath;
	char path[PATH_MAX + 1];
	int rc;

	if ((is >> tempPath) == NULL)
		return putErr(MIG_ERR_PROTOCOL, MIG_MSG_PROTOCOL);

	if ((rc = get_real_tmpl_path(dstTempl->m_tpath.c_str(), tempPath.c_str(), 3,
		path, sizeof(path))))
		return rc;

	char* const args[] = {(char*)BIN_TAR, (char*)"-p", (char*)"-S",
		(char*)"--same-owner", (char*)"-x", (char*)"-C", path, NULL};

	do_block(VZMoptions.tmpl_data_sock);
	rc = vzm_execve(args, NULL, VZMoptions.tmpl_data_sock,
		VZMoptions.tmpl_data_sock, NULL);
	close(VZMoptions.tmpl_data_sock);
	return rc;
}

int MigrateStateDstTempl::cmdCopyEzCache(std::istringstream& is)
{
	char path[PATH_MAX + 1];
	std::string name;

	if ((is >> name) == NULL)
		return putErr(MIG_ERR_PROTOCOL, MIG_MSG_PROTOCOL);

	snprintf(path, sizeof(path), "%s/cache/%s", dstTempl->m_tpath.c_str(),
		name.c_str());

	if (access(path, F_OK) == 0)
		unlink(path);

	// Will rewrote existing caches
	return remoteRsyncDst(getRsyncArgs(), "--server", ".", path, (void *)NULL);
}

/*
 * This is workaround:
 * vzmsrc send full path for EZ template (with TEMPLATE variable from vz.conf).
 * vzmdest check this path on dst node. But TEMPLATE differ on dst and src nodes,
 * vzmdest will check and copy template area in wrong path.
 * As workaround will cut out lase <step> subdirs from source path
 * and add TEMPLATE before.
 */
int get_real_tmpl_path(const char* vztemplate, const char* src_path,
	int step, char* dst_path, size_t sz)
{
	char* p;
	int i;

	p = (char*)src_path + strlen(src_path) - 1;
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
