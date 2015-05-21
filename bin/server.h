/* $Id$
 *
 * Copyright (c) SWsoft, 2006-2007
 *
 */
#ifndef __SERVER_H__
#define __SERVER_H__

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

#include <fstream>
#include <memory>
#include <string>
#include <map>

class CNewVEsList : public std::map<std::string, VEObj *>
{
public:
	~CNewVEsList();
};

extern CNewVEsList * g_veList;
extern std::map<std::string, std::string> * g_ctidMap;
extern MigrateStateDstRemote * state;

int main_loop();

#endif
