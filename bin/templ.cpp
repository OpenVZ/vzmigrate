/* $Id$
 *
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

#include <unistd.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <vzctl/libvzctl.h>

#include "templ.h"
#include "bincom.h"
#include "util.h"
#include "ct_config.h"

extern struct vz_data* vzcnf;

TmplEntry::TmplEntry(const std::string& id)
	: m_id(id)
{
}

int TmplEntry::init()
{
	struct stat st;

	if (stat(vzcnf->tmpldir, &st) && mkdir(vzcnf->tmpldir, DEF_DIR_MODE))
		return putErr(MIG_ERR_NOTMPLDIR, MIG_MSG_NOTMPLDIR);

	// Initialize template path on HW
	m_tpath = std::string(vzcnf->tmpldir);

	return 0;
}

TmplEntryEz::TmplEntryEz(const std::string& id)
	: TmplEntry(id)
{
	m_isapptempl = false;
	memset(&info, 0, sizeof(tmpl_info));
	lockdata = NULL;
	ostemplate = NULL;
}

TmplEntryEz::~TmplEntryEz()
{
	if (ostemplate)
		free(ostemplate);

	vztt_clean_tmpl_info(&info);
}

int TmplEntryEz::list()
{
	int rc;
	struct options opts;
	char tmpl[PATH_MAX+1];
	char* ptr;
	char* ostmpl;

	strncpy(tmpl, m_id.c_str(), sizeof(tmpl));

	vztt_set_default_options(&opts);
	opts.fld_mask = VZTT_INFO_TMPL_ALL;
	if ((ptr = strchr(tmpl, '@'))) {
		*ptr = '\0';
		ostmpl = ptr + 1;
		m_isapptempl = 1;
		rc = vztt_get_app_tmpl_info(ostmpl, tmpl, &opts, &info);
	} else {
		ostmpl = tmpl;
		m_isapptempl = 0;
		rc = vztt_get_os_tmpl_info(ostmpl, &opts, &info);
	}

	if ((rc == VZT_TMPL_NOT_EXIST) || (rc == VZT_TMPL_NOT_FOUND))
		return putErr(MIG_ERR_NOEXIST, MIG_MSG_TEMPL_NOEXIST, m_id.c_str());
	else if (rc)
		return putErr(MIG_ERR_VZTT, "vztt_get_tmpl_info() return %d", rc);

	if ((ostemplate = strdup(ostmpl)) == NULL)
		return putErr(MIG_ERR_SYSTEM, MIG_MSG_SYSTEM);

	if (info.confdir)
		m_path = info.confdir;

	return 0;
}

int TmplEntryEz::lock()
{
	if (isOptSet(OPT_SKIP_LOCKVE))
		return 0;

	// Don't lock if base ostemplate full name not defined
	if (ostemplate == NULL)
		return 0;

	if (vztt_lock_ostemplate(ostemplate, &lockdata))
		return putErr(MIG_ERR_LOCK, MIG_MSG_TEMPL_LOCK, ostemplate);

	return 0;
}

void TmplEntryEz::unlock()
{
	if (lockdata)
		vztt_unlock_ostemplate(lockdata);

	return;
}

int TmplEntryEz::isAppTemplate()
{
	return m_isapptempl;
}

int TmplEntryEz::getLastVersion(std::string* add)
{
	assert(add);

	std::string::size_type loc = m_path.find(m_tpath);
	if (loc != std::string::npos) {
		*add = m_path;
		add->erase(0,m_tpath.size());
	}

	return 0;
}

int TmplEntryEz::getMaskTechnologies(unsigned long* tech_mask)
{
	int i;
	unsigned long tech;

	if (info.technologies == NULL)
		return 0;

	*tech_mask = 0;

	for (i = 0; info.technologies[i]; i++) {
		if ((tech = vzctl2_name2tech(info.technologies[i])) == 0) {
			return putErr(MIG_ERR_SYSTEM, "Unknown technology %s for template %s",
				info.technologies[i], info.name);
		}
		(*tech_mask) += tech;
	}

	return 0;
}

char* TmplEntryEz::getOsTemplate()
{
	return ostemplate;
}

/*
 * Check template on dst node - check that tmpl does not already exist.
 * For app templates additionally check that ostemplate exist.
 */
int TmplEntryEz::check()
{
	int rc;
	struct options opts;
	char tmpl[PATH_MAX+1];
	char* ptr;
	char* ostmpl;

	strncpy(tmpl, m_id.c_str(), sizeof(tmpl));

	vztt_set_default_options(&opts);
	opts.debug = 0;
	opts.fld_mask = VZTT_INFO_TMPL_ALL;

	if ((ptr = strchr(tmpl, '@'))) {
		*ptr = '\0';
		ostmpl = ptr + 1;
		m_isapptempl = 1;
		rc = vztt_get_app_tmpl_info(ostmpl, tmpl, &opts, &info);
	} else {
		ostmpl = tmpl;
		m_isapptempl = 0;
		rc = vztt_get_os_tmpl_info(ostmpl, &opts, &info);
	}

	if (rc == 0) {
		return putErr(MIG_ERR_EXISTS, MIG_MSG_EZTEMPL_EXISTS, m_id.c_str());
	} else if ((rc != VZT_TMPL_NOT_EXIST) && (rc != VZT_TMPL_NOT_FOUND)) {
		return putErr(MIG_ERR_VZTT, "vztt_get_tmpl_info() return %d", rc);
	}

	if (m_isapptempl) {
		rc = vztt_get_os_tmpl_info(ostmpl, &opts, &info);
		if ((rc == VZT_TMPL_NOT_EXIST) || (rc == VZT_TMPL_NOT_FOUND)) {
			return putErr(MIG_ERR_COPY,
				MIG_MSG_OS_EZTEMPL_NOT_EXISTS, m_id.c_str());
		} else if (rc) {
			return putErr(MIG_ERR_VZTT, "vztt_get_tmpl_info() return %d", rc);
		}
		if ((ostemplate = strdup(ostmpl)) == NULL)
			return putErr(MIG_ERR_SYSTEM, MIG_MSG_SYSTEM);
	}

	return 0;
}
