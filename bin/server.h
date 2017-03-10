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
#ifndef __SERVER_H__
#define __SERVER_H__

#include "bincom.h"
#include "common.h"
#include "migratedst.h"
#include "migdsttempl.h"
#include "migssh.h"
#include "remotecmd.h"
#include "veentry.h"
#include "templ.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sstream>

#include <libgen.h>

#include <fstream>
#include <memory>
#include <string>
#include <map>

class CNewVEsList : public std::map<std::string, VEObj*> {
public:
	~CNewVEsList();
};

class CNewTemplsList : public std::map<std::string, TmplEntryEz*> {
public:
	~CNewTemplsList();
};

extern CNewVEsList* g_veList;
extern std::map<std::string, std::string>* g_ctidMap;
extern MigrateStateDstRemote* state;

extern CNewTemplsList* g_templList;
extern MigrateStateDstTempl* g_stateTempl;

int main_loop();

#endif
