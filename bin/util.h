/* $Id$
 *
 * Copyright (c) SWsoft, 2006-2007
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

#define VZ_CONF			VZ_GLOBAL_CFG

#define VZ_CONF_LOCKDIR 	"LOCKDIR"
#define VZ_CONF_TMPLDIR 	"TEMPLATE"
#define VZ_CONF_DUMPDIR 	"DUMPDIR"
#define VZ_CONF_USE_ATI 	"USE_ATI"
#define VZ_CONF_QUOTA 		"DISK_QUOTA"
#define VZ_CONF_SHAPING		"TRAFFIC_SHAPING"
#define VZ_CONF_REMOVEMIGRATED	"REMOVEMIGRATED"
#define VZ_CONF_TOOLS_BCID	"VZ_TOOLS_BCID"
#define VZ_CONF_TOOLS_IOLIMIT	"VZ_TOOLS_IOLIMIT"

#define VE_CONF_PRIV		"VE_PRIVATE"
#define VE_CONF_ROOT		"VE_ROOT"
#define VE_CONF_UUIDDIR 	"UUID"
#define VE_CONF_TECHNOLOGIES 	"TECHNOLOGIES"
#define VE_CONF_BINDMOUNT 	"BINDMOUNT"
#define VE_CONF_NAME	 	"NAME"
#define VE_CONF_OSTEMPLATE	"OSTEMPLATE"
#define VE_CONF_IPADDR		"IP_ADDRESS"
#define VE_CONF_VETYPE		"VE_TYPE"
#define VE_CONF_DISKSPACE	"DISKSPACE"
#define VE_CONF_DISKINODES	"DISKINODES"
#define VE_CONF_RATE		"RATE"
#define VE_CONF_UUID		"UUID"
#define VE_CONF_TEMPLATES	"TEMPLATES"
#define VE_CONF_SLMMODE		"SLMMODE"
#define VE_CONF_QUOTAUGIDLIMIT	"QUOTAUGIDLIMIT"
#define VE_CONF_HA_ENABLE	"HA_ENABLE"
#define VE_CONF_HA_PRIO		"HA_PRIO"
#define VE_CONF_JOURNALED_QUOTA	"JOURNALED_QUOTA"
#define VE_CONF_VEFORMAT	"VEFORMAT"
#define VE_CONF_DISK		"DISK"

#define VE_PLOOP_BINDMOUNT_DIR	"/.bindmount"
#define VE_VZFS_BINDMOUNT_DIR	"/fs/mnt"
#define PFCACHE_BIN "/usr/libexec/vztt_pfcache_xattr"

#define fl_prls_release	"/etc/parallels-release"

/* char* double-linked list */
TAILQ_HEAD(string_list, string_list_el);
struct string_list_el {
	char *s;
	TAILQ_ENTRY(string_list_el) e;
};

/* global vz config */
struct vz_data {
	char *root_orig;
	char *priv_orig;
	char *lockdir;
	char *tmpldir;
	char *dumpdir;
	int quota;
	int use_ati;
	int shaping;
	int removemigrated;
	unsigned long bcid;
	unsigned long iolimit;
};

/* container config */
struct ve_data {
	char *name;
	char *uuid;
	char *ostemplate;
	unsigned long technologies;
	char *bindmount;
	char *root;
	char *root_orig;
	char *priv;
	char *priv_orig;
	char *ve_type;
	struct string_list ipaddr;
	struct string_list rate;
	unsigned long diskspace[2];
	unsigned long diskinodes[2];
	struct string_list templates;
	char *slmmode;
	unsigned long quotaugidlimit;
	int ha_enable;
	unsigned long ha_prio;
	struct string_list _disk;
	struct string_list _ext_disk;
	struct string_list _np_disk;
	char *disk_raw_str;
};


#ifdef __cplusplus
extern "C" {
#endif

/* global config */
/* read global VZ config */
int vz_data_load(struct vz_data *vz);
void vz_data_clean(struct vz_data *vz);
/* limit IO rate of itself
   according to global VZ config settings */
int vz_setiolimit();

/* container config functions */
void ve_data_init(struct ve_data *ve);
void ve_data_clean(struct ve_data *ve);
/* read VE config */
int ve_data_load(const char *ctid, struct ve_data *ve);

/* char* double-linked list */
/* sample of using:
	struct string_list urls;
	struct string_list_el *p;

	init_string_list(&urls);

	if (read_string_list(path, &urls))
		return 0;

	for (p = urls.tqh_first; p != NULL; p = p->e.tqe_next) {
		printf("%s\n", p->s);
	}
	clean_string_list(&urls);

  List functions alloc and free <char *>
*/
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
int test_caps(unsigned veid, unsigned int flags, int *ret, unsigned *features);
int pfcache_set(const char *path, int on);

#ifdef __cplusplus
}
#endif

#endif
