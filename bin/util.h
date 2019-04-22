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
 * Double-linked lists functions declarations
 */

#ifndef __QUEUE_H__
#define __QUEUE_H__

#include <sys/types.h>
#include <sys/stat.h>
#include <utime.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/queue.h>
#include <string.h>
#include <vzctl/libvzctl.h>

#define VE_PLOOP_BINDMOUNT_DIR	"/.bindmount"
#define PFCACHE_BIN "/usr/libexec/vztt_pfcache_xattr"
#define DEFAULT_DUMP_DIR	"/vz/dump"

#define fl_prls_release	"/etc/parallels-release"

#define VE_RUNNING_FILE	".running"
#define DISK_STATFS_FILE	".statfs"

/* char* double-linked list */
TAILQ_HEAD(string_list, string_list_el);
struct string_list_el {
	char *s;
	TAILQ_ENTRY(string_list_el) e;
};

#ifdef __cplusplus
extern "C" {
#endif

/* list initialization */
static inline void string_list_init(struct string_list *ls)
{
	TAILQ_INIT(ls);
}

/* remove all elements and its content */
void string_list_clean(struct string_list *ls);

/* add new element in tail */
int string_list_add(struct string_list *ls, const char *str);

/* find string <str> in list <ls> */
struct string_list_el *string_list_find(struct string_list *ls, const char *str);

/* remove element and its content and return pointer to previous elem */
struct string_list_el *string_list_remove(
		struct string_list *ls,
		struct string_list_el *el);

/* 1 if list is empty */
static inline int string_list_empty(struct string_list *ls)
{
	return (ls->tqh_first == NULL)?1:0;
}

/* get size of string list <ls> */
size_t string_list_size(struct string_list *ls);

/* copy string list <ls> to string array <*a> */
int string_list_to_array(struct string_list *ls, char ***a);

/* copy all elements of <src> to <dst> */
int string_list_copy(struct string_list *dst, struct string_list *src);

#define string_list_for_each(ls, el) \
	for (	(el) = ((ls) != NULL) ? (ls)->tqh_first : NULL; \
		(el) != NULL; \
		(el) = (el)->e.tqe_next)

/* run argv[0] with argv and envp, stderr redirect to log */
int vzm_execve(
		char *const argv[],
		char *const envp[],
		int in,
		int out,
		int *retcode);

/*
 * run argv[0] with argv and envp, don't wait for process termination. stderr
 * and stdout redirect to /dev/null and do not print any error messages
 */
int vzm_execve_quiet_nowait(
		char *const argv[],
		char *const envp[],
		int in,
		pid_t *child);

/*
 * run argv[0] with argv and envp, stderr and stdout redirect to /dev/null
 * and do not print any error messages
 */
int vzm_execve_quiet(
		char *const argv[],
		char *const envp[],
		int in,
		int *retcode);

/* run arglist[0] with arglist and envlist, stderr redirect to log */
int vzml_execve(
		struct string_list *arglist,
		struct string_list *envlist,
		int in,
		int out,
		int quiet);

/* create directory with parent directories as needed */
int make_dir(const char *path, mode_t mode);

/* copy from file src to file dst */
int copy_file(const char *dst, const char *src);

/* move from file src to file dst */
int move_file(const char *dst, const char *src);

/* get temporary directory */
int get_tmp_dir(char *path, size_t sz);

/* split path on mount point and path on device */
int split_path(	const char *path,
		char *mp,
		size_t msize,
		char *lpath,
		size_t lsize);

/* read VE_ROOT */
int get_ve_root(const char *ctid, char *root, size_t size);

/* check process exit status */
int check_exit_status(char *task, int status);

void dump_args(const char *title, char * const *args);

/* check if file fl_prls_release is available */
int check_fl_prls_release();

/* bind mount src to binddir */
int bind_mount(const char *src, int extra_flags, char *dst, size_t size);

/* Umount and remove bind-mounted dir */
void bind_umount(char *binddir);

const char *get_full_path(const char *ve_private, const char *fname,
		char *out,int size);
int is_external_disk(const char *delta);
int get_disk_usage_ploop(const char *path, unsigned long long *bytes);

int open_pipes(int pipefd[2]);
void init_pipes(int pipefd[2]);
void close_pipes(int pipefd[2]);
void close_safe(int *fd);
void term_clean(pid_t pid, int timeout);
void gen_uuid(char *buf);
int get_fd(char *fd);

int rmdir_recursively(const char *dirname);

unsigned long long floor2digit(unsigned long long v);
unsigned long long ceil2digit(unsigned long long v);

void copy_cstr(const char *str, char *buf, size_t buf_size);
int pfcache_set(const char *path, int on);

#ifdef __cplusplus
}
#endif

#endif
