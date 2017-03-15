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

#ifndef __TEMPL_H_
#define __TEMPL_H_

#include <vz/vztt.h>
#include <string>

class TmplEntry {
public:
	TmplEntry(const std::string& id);
	int init();

public:
	std::string m_id;
	std::string m_tpath;
	std::string m_path;
};

class TmplEntryEz : public TmplEntry {
public:
	TmplEntryEz(const std::string& id);
	~TmplEntryEz();

	int list();
	int lock();
	void unlock();
	int isAppTemplate();
	int getLastVersion(std::string* add);
	int getMaskTechnologies(unsigned long* tech_mask);
	char* getOsTemplate();
	int check();

public:
	char* ostemplate;
	void* lockdata;
	int m_isapptempl;
	tmpl_info info;
};

#endif
