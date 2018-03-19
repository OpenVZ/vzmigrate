/*
* Copyright (c) 2017, Parallels International GmbH
*
* This file is part of Virtuozzo Core. Virtuozzo Core is free
* software; you can redistribute it and/or modify it under the terms
* of the GNU General Public License as published by the Free Software
* Foundation; either version 2 of the License, or (at your option) any
* later version.
* 
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
* 
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
* 02110-1301, USA.
*
* Our contact details: Parallels International GmbH, Vordergasse 59, 8200
* Schaffhausen, Switzerland.
*/

#ifndef __TRACE_H__
#define __TRACE_H__

#include "common.h"

#include <syslog.h>
#include <boost/optional.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

struct Trace
{
	Trace(const char *name, const char *action, const char *ctid) :
		m_name(name), m_ctid(ctid), m_action(action)
	{
	}

	void start()
	{
		closelog();
		openlog(m_name, LOG_PID, LOG_INFO | LOG_USER);

		boost::property_tree::ptree t;
		t.put("action", m_action.c_str());
		t.put("op", "start");
		t.put("ctid", m_ctid.c_str());
		report(t);

		closelog();
		open_logger(NULL);
	}

	void finish(int code)
	{
		closelog();
		openlog(m_name, LOG_PID, LOG_INFO | LOG_USER);

		boost::property_tree::ptree t;
		t.put("action", m_action.c_str());
		t.put("op", "finish");
		t.put("ctid", m_ctid.c_str());
		t.put("result", code);
		report(t);

		closelog();
		open_logger(NULL);
	}

private:
	void report(const boost::property_tree::ptree &progress_)
	{
		std::stringstream s;
		boost::property_tree::json_parser::write_json(s, progress_, false);
		syslog(LOG_INFO, s.str().c_str());
	}

	const char * m_name;
	std::string m_ctid;
	std::string m_action;
};

#endif // __TRACE_H__
