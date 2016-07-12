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

#ifndef __MIGDSTTEMPL_H_
#define __MIGDSTTEMPL_H_

#include <string>
#include <memory>
#include "templ.h"
#include "migratecom.h"

class MigrateStateDstTempl : public MigrateStateCommon {
public:
	MigrateStateDstTempl(TmplEntryEz* entry);
	int initMigration(const std::string& ver);
	int copyStage();
	int finalStage();
	int copyTarball(const std::string& mark);
	int cmdCheckTechnologies(std::istringstream& is, std::ostringstream& os);
	int cmdCheckEZDir(std::istringstream& is, std::ostringstream& os);
	int cmdCopyEZDirTar(std::istringstream& is);
	int cmdCopyEzCache(std::istringstream& is);
private:
	std::auto_ptr<TmplEntryEz> dstTempl;
};

int get_real_tmpl_path(const char* vztemplate, const char* src_path,
	int step, char* dst_path, size_t sz);

#endif
