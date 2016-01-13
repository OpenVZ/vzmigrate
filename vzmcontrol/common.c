#include <sys/types.h>
#include <sys/stat.h>
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

#if 0
/* set non-block mode for descriptor <fd> */
static int set_non_block(int fd)
{
	long flags;

	if ((flags = fcntl(fd, F_GETFL)) == -1)
		return putErr(MIG_ERR_SYSTEM, "fcntl() : %m");
	if ((fcntl(fd, F_SETFL, flags | O_NONBLOCK)) == -1)
		return putErr(MIG_ERR_SYSTEM, "fcntl() : %m");
	return 0;
}

/* set non-block mode for descriptor <fd> */
static int _set_block(int fd)
{
	long flags;

	if ((flags = fcntl(fd, F_GETFL)) == -1)
		return putErr(MIG_ERR_SYSTEM, "fcntl() : %m");
	if ((fcntl(fd, F_SETFL, flags & ~O_NONBLOCK)) == -1)
		return putErr(MIG_ERR_SYSTEM, "fcntl() : %m");
	return 0;
}
#endif


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
	if (debug_level >= LOG_DEBUG)
		point += sprintf(buf, "%lu: ", time(NULL));
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
