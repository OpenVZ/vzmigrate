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

#ifndef __MIGSRCTEMPL_H_
#define __MIGSRCTEMPL_H_

#include <string>
#include <memory>
#include "templ.h"
#include "migratecom.h"

class MigrateStateTemplate : public MigrateStateCommon {
public:
	MigrateStateTemplate(const std::string& id);
	int doMigration();
	int checkTechnologies();

private:
	int copyEZDirSocket(char* const* const vzdir);
	int fillEZDirList(char* const* const vzdir, char* dir, unsigned dsize,
		char* file, unsigned fsize);

private:
	std::auto_ptr<TmplEntryEz> srcTempl;
};

#endif
