/*
 * Copyright (c) 2016 Parallels IP Holdings GmbH
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
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>

#include <stdarg.h>
#include <time.h>

#include "common.h"

int debug_level = LOG_DEBUG;
const char * log_name = NULL;

void print_def(int level, const char * s);
printFunc print_func = print_def;

int set_block(int fd, int state)
{
	int flags = fcntl(fd, F_GETFL);
	if (flags < 0
	    || fcntl(fd, F_SETFL, state ? (flags & ~O_NONBLOCK) : (flags | O_NONBLOCK)))
		return -1;
	return 0;
}

int set_clo(int fd, int state)
{
	int flag = state ? FD_CLOEXEC : ~FD_CLOEXEC;
	if (fcntl(fd, F_SETFD, flag) < 0)
		return -1;
	return 0;
}

void open_logger(const char * name)
{
	openlog(name, LOG_CONS | LOG_PID, LOG_USER);
	log_name = name;
}

void vprint_log(int level, const char* oformat, va_list pvar)
{
	char buf[BUFSIZ];
	int point = 0;
	va_list pvar1;

	va_copy(pvar1, pvar);
	// put to syslog and to some output also
	vsyslog(level, oformat, pvar1);
	va_end(pvar1);

	va_copy(pvar1, pvar);
	vsnprintf(buf, sizeof(buf), oformat, pvar1);
	va_end(pvar1);
	if (debug_level >= LOG_DEBUG) {
		struct timeval tv;
		struct tm tm;
		if (gettimeofday(&tv, NULL) == 0 && localtime_r(&tv.tv_sec, &tm)) {
			point += snprintf(buf, sizeof(buf),
				"%4.4d-%2.2d-%2.2d %2.2d:%2.2d:%2.2d.%3.3ld: ",
				tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
				tm.tm_hour, tm.tm_min, tm.tm_sec, tv.tv_usec / 1000);
		} else {
			point += snprintf(buf, sizeof(buf), "%lu: ", time(NULL));
		}
	}
	vsnprintf(buf + point, sizeof(buf) - point, oformat, pvar);
	print_func(level, buf);
}

void print_log(int level, const char* oformat, ...)
{
	va_list pvar;
	va_start(pvar, oformat);
	vprint_log(level, oformat, pvar);
	va_end(pvar);
}

void print_def(int level, const char * s)
{
	FILE * out = level <= LOG_ERR ? stderr : stdout;
	fprintf(out, "%s\n", s);
}

static char err_buf[BUFSIZ];

const char * getError() {
	return err_buf;
}

int putErr(int rc, const char * fm, ...)
{
	/* it needs to support, putErr(getError()) functionality*/
	char backup_buf[BUFSIZ];
	va_list ap;
	va_list pvar;
	va_start(ap, fm);
	va_copy(pvar, ap);
	vsnprintf(backup_buf, BUFSIZ, fm, pvar);
	vprint_log(LOG_ERR, fm, ap);
	va_end(pvar);
	va_end(ap);
	strcpy(err_buf, backup_buf);
	return rc;
}
