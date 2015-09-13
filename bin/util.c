/* $Id$
 *
 * Copyright (c) SWsoft, 2006-2007
 *
 * queues
 */
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <dirent.h>
#include <linux/unistd.h>
#include <fcntl.h>
#include <libgen.h>
#include <termios.h>
#include <math.h>

#include <vzctl/libvzctl.h>
#include <uuid/uuid.h>

#include "util.h"
#include "common.h"

#include <linux/types.h>
#include <linux/ioctl.h>

#define VZCTLDEV	"/dev/vzctl"
#define VZIOLIMITTYPE	'I'

struct iolimit_state {
        unsigned int id;
        unsigned int speed;
        unsigned int burst;
        unsigned int latency;
};

#define PHYS_LIMIT	256UL	/* in Mb */
#define UB_PHYSPAGES	6

/*
 char* double-linked list
*/
/* add new element in tail */
int string_list_add(struct string_list *ls, const char *str)
{
	struct string_list_el *p;

	p = (struct string_list_el *)malloc(sizeof(struct string_list_el));
	if (p == NULL)
		return putErr(MIG_ERR_SYSTEM, MIG_MSG_SYSTEM);
	if ((p->s = strdup(str)) == NULL)
		return putErr(MIG_ERR_SYSTEM, MIG_MSG_SYSTEM);
	TAILQ_INSERT_TAIL(ls, p, e);

	return 0;
}

/* remove all elements and its content */
void string_list_clean(struct string_list *ls)
{
	struct string_list_el *el;

	while (ls->tqh_first != NULL) {
		el = ls->tqh_first;
		TAILQ_REMOVE(ls, ls->tqh_first, e);
		free((void *)el->s);
		free((void *)el);
	}
}

/* find string <str> in list <ls> */
struct string_list_el *string_list_find(struct string_list *ls, const char *str)
{
	struct string_list_el *p;

	if (str == NULL)
		return NULL;

	for (p = ls->tqh_first; p != NULL; p = p->e.tqe_next) {
		if (strcmp(str, p->s) == 0)
			return p;
	}
	return NULL;
}

/* remove element and its content and return pointer to previous elem */
struct string_list_el *string_list_remove(
		struct string_list *ls,
		struct string_list_el *el)
{
	/* get previous element */
	struct string_list_el *prev = *el->e.tqe_prev;

	TAILQ_REMOVE(ls, el, e);
	free((void *)el->s);
	free((void *)el);

	return prev;
}

/* get size of string list <ls> */
size_t string_list_size(struct string_list *ls)
{
	struct string_list_el *p;
	size_t sz = 0;

	for (p = ls->tqh_first; p != NULL; p = p->e.tqe_next)
		sz++;
	return sz;
}

/* copy string list <ls> to string array <*a> */
int string_list_to_array(struct string_list *ls, char ***a)
{
	struct string_list_el *p;
	size_t sz, i;

	/* get array size */
	sz = string_list_size(ls);
	if ((*a = (char **)calloc(sz + 1, sizeof(char *))) == NULL)
		return putErr(MIG_ERR_SYSTEM, MIG_MSG_SYSTEM);
	for (p = ls->tqh_first, i = 0; p != NULL && i < sz; \
				p = p->e.tqe_next, i++) {
		if (((*a)[i] = strdup(p->s)) == NULL)
			return putErr(MIG_ERR_SYSTEM, MIG_MSG_SYSTEM);
	}
	(*a)[sz] = NULL;

	return 0;
}

/* copy all elements of <src> to <dst> */
int string_list_copy(struct string_list *dst, struct string_list *src)
{
	int rc;
	struct string_list_el *p;

	for (p = src->tqh_first; p != NULL; p = p->e.tqe_next)
		if ((rc = string_list_add(dst, p->s)))
			return rc;
	return 0;
}

/* global config */
static void vz_data_init(struct vz_data *vz)
{
	memset((void *)vz, 0, sizeof(&vz));
}

void vz_data_clean(struct vz_data *vz)
{
	if (vz->lockdir)
		free((void *)vz->lockdir);
	if (vz->tmpldir)
		free((void *)vz->tmpldir);
	if (vz->dumpdir)
		free((void *)vz->dumpdir);
	vz_data_init(vz);
}

/* read global VZ config */
int vz_data_load(struct vz_data *vz)
{
	int err, rc = 0;
	const char *data;
	struct vzctl_env_handle *h;
	struct vzctl_env_param *env;

	vz_data_init(vz);

	h = vzctl2_env_open_conf(0, VZ_CONF, VZCTL_CONF_SKIP_GLOBAL|VZCTL_CONF_SKIP_PARAM_ERRORS, &err);
	if (err)
		return putErr(MIG_ERR_VZCTL, "vzctl2_env_open(%s) error: %s",
			VZ_CONF, vzctl2_get_last_error());

	env = vzctl2_get_env_param(h);

	/* read original root and private */
	if (vzctl2_env_get_ve_root_orig_path(env, &data)) {
		rc = putErr(MIG_ERR_SYSTEM,
			"Can't read VE_ROOT from " VZ_CONF);
		goto cleanup;
	}

	if ((vz->root_orig = strdup(data)) == NULL) {
		rc = putErr(MIG_ERR_SYSTEM, MIG_MSG_SYSTEM);
		goto cleanup;
	}

	if (vzctl2_env_get_ve_private_orig_path(env, &data)) {
		rc = putErr(MIG_ERR_SYSTEM,
			"Can't read VE_PRIVATE from " VZ_CONF);
		goto cleanup;
	}

	if ((vz->priv_orig = strdup(data)) == NULL) {
		rc = putErr(MIG_ERR_SYSTEM, MIG_MSG_SYSTEM);
		goto cleanup;
	}

	/* read LOCKDIR */
	if ((rc = vzctl2_env_get_param(h, VZ_CONF_LOCKDIR, &data)) || data == NULL) {
		rc = putErr(MIG_ERR_SYSTEM,
			"Can't read " VZ_CONF_LOCKDIR " from " VZ_CONF);
		goto cleanup;
	}

	if ((vz->lockdir = strdup(data)) == NULL) {
		rc = putErr(MIG_ERR_SYSTEM, MIG_MSG_SYSTEM);
		goto cleanup;
	}

	/* read TEMPLATE */
	if ((rc = vzctl2_env_get_param(h, VZ_CONF_TMPLDIR, &data)) || data == NULL) {
		rc = putErr(MIG_ERR_SYSTEM,
			"Can't read " VZ_CONF_TMPLDIR " from " VZ_CONF);
		goto cleanup;
	}

	if ((vz->tmpldir = strdup(data)) == NULL) {
		rc = putErr(MIG_ERR_SYSTEM, MIG_MSG_SYSTEM);
		goto cleanup;
	}

	/* read DUMPDIR */
	if ((rc = vzctl2_env_get_param(h, VZ_CONF_DUMPDIR, &data)) || data == NULL) {
		rc = putErr(MIG_ERR_SYSTEM,
			"Can't read " VZ_CONF_DUMPDIR " from " VZ_CONF);
		goto cleanup;
	}
	if ((vz->dumpdir = strdup(data)) == NULL) {
		rc = putErr(MIG_ERR_SYSTEM, MIG_MSG_SYSTEM);
		goto cleanup;
	}

	/* read DISK_QUOTA */
	if ((rc = vzctl2_env_get_param(h, VZ_CONF_QUOTA, &data)) == 0 && data != NULL)
		vz->quota = (strcasecmp(data, "yes") == 0);

	/* read USE_ATI */
	if ((rc = vzctl2_env_get_param(h, VZ_CONF_USE_ATI, &data)) == 0 && data != NULL)
		vz->use_ati = (strcasecmp(data, "yes") == 0);

	/* read TRAFFIC_SHAPING */
	if ((rc = vzctl2_env_get_param(h, VZ_CONF_SHAPING, &data)) == 0 && data != NULL)
		vz->shaping = (strcasecmp(data, "yes") == 0);

	/* read REMOVEMIGRATED */
	if ((rc = vzctl2_env_get_param(h, VZ_CONF_REMOVEMIGRATED, &data)) == 0 && data != NULL)
		vz->removemigrated = (strcasecmp(data, "yes") == 0);

	/* read VZ_TOOLS_BCID */
	vz->bcid = ULONG_MAX;	/* == NOT PROVIDED */
	if ((rc = vzctl2_env_get_param(h, VZ_CONF_TOOLS_BCID, &data)) == 0 && data != NULL)
	{
		unsigned long bcid = ULONG_MAX;
		errno = 0;
		bcid = strtoul(data, NULL, 10);
		if (errno == 0)
		{
			logger(LOG_INFO,
			       "vzctl2_env_get_param(" VZ_CONF_TOOLS_BCID ") return %ld",
			       bcid);
			vz->bcid = bcid;
		} else
			logger(LOG_ERR,
			       "Unable to parse from global config %s=%s (%s)",
			       VZ_CONF_TOOLS_BCID, data, strerror(errno));
	}

	/* read VZ_TOOLS_IOLIMIT */
	vz->iolimit = ULONG_MAX;	/* == NOT PROVIDED */
	if ((rc = vzctl2_env_get_param(h, VZ_CONF_TOOLS_IOLIMIT, &data)) == 0 && data != NULL)
	{
		unsigned long limit = ULONG_MAX;
		errno = 0;
		limit = strtoul(data, NULL, 10);
		if (errno == 0)
		{
			logger(LOG_INFO,
			       "vzctl2_env_get_param(" VZ_CONF_TOOLS_IOLIMIT ") return %ld",
			       limit);
			vz->iolimit = limit;
		} else
			logger(LOG_ERR,
			       "Unable to parse from global config %s=%s (%s)",
			       VZ_CONF_TOOLS_IOLIMIT, data, strerror(errno));
	}

cleanup:
	vzctl2_env_close(h);

	return rc;
}

/*
  Container config functions
*/
void ve_data_init(struct ve_data *ve)
{
	memset((void *)ve, 0, sizeof(struct ve_data));
	string_list_init(&ve->ipaddr);
	string_list_init(&ve->rate);
	string_list_init(&ve->templates);
	/* HA feature is enabled by default */
	ve->ha_enable = 1;
	string_list_init(&ve->_disk);
	string_list_init(&ve->_ext_disk);
	string_list_init(&ve->_np_disk);
}

void ve_data_clean(struct ve_data *ve)
{
	free((void *)ve->name);
	free((void *)ve->ostemplate);
	free((void *)ve->uuid);
	free((void *)ve->bindmount);
	free((void *)ve->root);
	free((void *)ve->root_orig);
	free((void *)ve->priv);
	free((void *)ve->priv_orig);
	free((void *)ve->ve_type);
	string_list_clean(&ve->ipaddr);
	string_list_clean(&ve->rate);
	string_list_clean(&ve->templates);
	string_list_clean(&ve->_disk);
	string_list_clean(&ve->_ext_disk);
	string_list_clean(&ve->_np_disk);
	ve_data_init(ve);
	free(ve->disk_raw_str);
}

/* read VE config */
int ve_data_load(const char *ctid, struct ve_data *ve)
{
	int err, rc = 0;
	const char *data;
	char *str, *token;
	struct vzctl_env_handle *h;
	struct vzctl_env_param *env;

	h = vzctl2_env_open(ctid, VZCTL_CONF_SKIP_PARAM_ERRORS, &err);
	if (err)
		return putErr(MIG_ERR_VZCTL, "vzctl2_env_open(%s) err: %d error: %s",
			ctid, err, vzctl2_get_last_error());

	env = vzctl2_get_env_param(h);
	/* read expanded and original root and private */
	if (vzctl2_env_get_ve_root_orig_path(env, &data)) {
		rc = putErr(MIG_ERR_SYSTEM,
				"Can't read VE_ROOT from CT %s config", ctid);
		goto cleanup;
	}
	if ((ve->root_orig = strdup(data)) == NULL) {
		rc = putErr(MIG_ERR_SYSTEM, MIG_MSG_SYSTEM);
		goto cleanup;
	}

	if (vzctl2_env_get_ve_root_path(env, &data)) {
		rc = putErr(MIG_ERR_SYSTEM,
				"Can't read VE_ROOT from CT config");
		goto cleanup;
	}
	if ((ve->root = strdup(data)) == NULL) {
		rc = putErr(MIG_ERR_SYSTEM, MIG_MSG_SYSTEM);
		goto cleanup;
	}

	if (vzctl2_env_get_ve_private_orig_path(env, &data)) {
		rc = putErr(MIG_ERR_SYSTEM,
				"Can't read VE_PRIVATE from CT config");
		goto cleanup;
	}
	if ((ve->priv_orig = strdup(data)) == NULL) {
		rc = putErr(MIG_ERR_SYSTEM, MIG_MSG_SYSTEM);
		goto cleanup;
	}

	if (vzctl2_env_get_ve_private_path(env, &data)) {
		rc = putErr(MIG_ERR_SYSTEM,
				"Can't read VE_PRIVATE from CT config");
		goto cleanup;
	}
	if ((ve->priv = strdup(data)) == NULL) {
		rc = putErr(MIG_ERR_SYSTEM, MIG_MSG_SYSTEM);
		goto cleanup;
	}

	/* read OSTEMPLATE */
	if ((rc = vzctl2_env_get_param(h, VE_CONF_OSTEMPLATE, &data))) {
		rc = putErr(MIG_ERR_VZCTL, "vzctl2_env_get_param(%s) error: %s",
			VE_CONF_OSTEMPLATE, vzctl2_get_last_error());
		goto cleanup;
	}
	if (data == NULL)
		ve->ostemplate = strdup("");
	else
		ve->ostemplate = strdup(data);
	if (ve->ostemplate == NULL) {
		rc = putErr(MIG_ERR_SYSTEM, MIG_MSG_SYSTEM);
		goto cleanup;
	}

	/* read UUID */
	if ((rc = vzctl2_env_get_param(h, VE_CONF_UUIDDIR, &data))) {
		rc = putErr(MIG_ERR_VZCTL, "vzctl2_env_get_param(%s) error: %s",
			VE_CONF_UUIDDIR, vzctl2_get_last_error());
		goto cleanup;
	}
	if (data) {
		if ((ve->uuid = strdup(data)) == NULL) {
			rc = putErr(MIG_ERR_SYSTEM, MIG_MSG_SYSTEM);
			goto cleanup;
		}
	}

	/* read TECHNOLOGIES */
	if ((rc = vzctl2_env_get_param(h, VE_CONF_TECHNOLOGIES, &data))) {
		rc = putErr(MIG_ERR_VZCTL, "vzctl2_env_get_param(%s) error: %s",
			VE_CONF_TECHNOLOGIES, vzctl2_get_last_error());
		goto cleanup;
	}
	if (data) {
		unsigned long tech;
		char *p;

		ve->technologies = 0L;
		str = strdupa(data);
		/* set buffer to lower case */
		for (p = str; *p; ++p)
			*str = tolower(*str);

		/* parse TECHNOLOGIES string */
		for (; ;str = NULL) {
			if ((token = strtok(str, "  ")) == NULL)
				break;
			if ((tech = vzctl2_name2tech(token)) == 0) {
				rc = putErr(MIG_ERR_TECHNOLOGIES,
				"Unknown technology in TECHNOLOGIES: %s",\
					token);
				goto cleanup;
			}
			ve->technologies |= tech;
		}
	}

	/* read NAME */
	if ((rc = vzctl2_env_get_param(h, VE_CONF_NAME, &data))) {
		rc = putErr(MIG_ERR_VZCTL, "vzctl2_env_get_param(%s) error: %s",
			VE_CONF_NAME, vzctl2_get_last_error());
		goto cleanup;
	}
	if (data) {
		if ((ve->name = strdup(data)) == NULL) {
			rc = putErr(MIG_ERR_SYSTEM, MIG_MSG_SYSTEM);
			goto cleanup;
		}
	}

	/* read BINDMOUNT */
	if ((rc = vzctl2_env_get_param(h, VE_CONF_BINDMOUNT, &data))) {
		rc = putErr(MIG_ERR_VZCTL, "vzctl2_env_get_param(%s) error: %s",
			VE_CONF_BINDMOUNT, vzctl2_get_last_error());
		goto cleanup;
	}
	if (data) {
		if ((ve->bindmount = strdup(data)) == NULL) {
			rc = putErr(MIG_ERR_SYSTEM, MIG_MSG_SYSTEM);
			goto cleanup;
		}
	}

	/* read IP_ADDRESS */
	if ((rc = vzctl2_env_get_param(h, VE_CONF_IPADDR, &data))) {
		rc = putErr(MIG_ERR_VZCTL, "vzctl2_env_get_param(%s) error: %s",
			VE_CONF_IPADDR, vzctl2_get_last_error());
		goto cleanup;
	}
	if (data) {
		for (str = strdupa(data); ;str = NULL) {
			if ((token = strtok(str, "  ")) == NULL)
				break;
			if ((rc = string_list_add(&ve->ipaddr, token)))
				goto cleanup;
		}
	}

	/* read RATE */
	if ((rc = vzctl2_env_get_param(h, VE_CONF_RATE, &data))) {
		rc = putErr(MIG_ERR_VZCTL, "vzctl2_env_get_param(%s) error: %s",
			VE_CONF_RATE, vzctl2_get_last_error());
		goto cleanup;
	}
	if (data) {
		for (str = strdupa(data); ;str = NULL) {
			if ((token = strtok(str, "  ")) == NULL)
				break;
			if ((rc = string_list_add(&ve->rate, token)))
				goto cleanup;
		}
	}

	/* read VE_TYPE */
	if ((rc = vzctl2_env_get_param(h, VE_CONF_VETYPE, &data))) {
		rc = putErr(MIG_ERR_VZCTL, "vzctl2_env_get_param(%s) error: %s",
			VE_CONF_VETYPE, vzctl2_get_last_error());
		goto cleanup;
	}
	if (data) {
		if ((ve->ve_type = strdup(data)) == NULL) {
			rc = putErr(MIG_ERR_SYSTEM, MIG_MSG_SYSTEM);
			goto cleanup;
		}
	}

	/* read DISKSPACE */
	if ((rc = vzctl2_env_get_param(h, VE_CONF_DISKSPACE , &data))) {
		rc = putErr(MIG_ERR_VZCTL, "vzctl2_env_get_param(%s) error: %s",
			VE_CONF_DISKSPACE, vzctl2_get_last_error());
		goto cleanup;
	}
	if (data) {
		if ((str = strchr(data, ':'))) {
			*str = '\0';
			ve->diskspace[0] = atol(data);
			ve->diskspace[1] = atol(++str);
		}
	}

	/* read DISKINODES */
	if ((rc = vzctl2_env_get_param(h, VE_CONF_DISKINODES , &data))) {
		rc = putErr(MIG_ERR_VZCTL, "vzctl2_env_get_param(%s) error: %s",
			VE_CONF_DISKINODES, vzctl2_get_last_error());
		goto cleanup;
	}
	if (data) {
		if ((str = strchr(data, ':'))) {
			*str = '\0';
			ve->diskinodes[0] = atol(data);
			ve->diskinodes[1] = atol(++str);
		}
	}

	/* read TEMPLATES */
	if ((rc = vzctl2_env_get_param(h, VE_CONF_TEMPLATES, &data))) {
		rc = putErr(MIG_ERR_VZCTL, "vzctl2_env_get_param(%s) error: %s",
			VE_CONF_TEMPLATES, vzctl2_get_last_error());
		goto cleanup;
	}
	if (data) {
		for (str = strdupa(data); ;str = NULL) {
			if ((token = strtok(str, "  ")) == NULL)
				break;
			if ((rc = string_list_add(&ve->templates, token)))
				goto cleanup;
		}
	}

	/* read SLMMODE */
	if ((rc = vzctl2_env_get_param(h, VE_CONF_SLMMODE, &data))) {
		rc = putErr(MIG_ERR_VZCTL, "vzctl2_env_get_param(%s) error: %s",
			VE_CONF_SLMMODE, vzctl2_get_last_error());
		goto cleanup;
	}
	if (data) {
		if ((ve->slmmode = strdup(data)) == NULL) {
			rc = putErr(MIG_ERR_SYSTEM, MIG_MSG_SYSTEM);
			goto cleanup;
		}
	}

	/* read HA_ENABLE */
	if ((rc = vzctl2_env_get_param(h, VE_CONF_HA_ENABLE, &data))) {
		rc = putErr(MIG_ERR_VZCTL, "vzctl2_env_get_param(%s) error: %s",
			VE_CONF_HA_ENABLE, vzctl2_get_last_error());
		goto cleanup;
	}
	if (data)
		ve->ha_enable = !strcasecmp(data, "yes");

	/* read HA_PRIO */
	if ((rc = vzctl2_env_get_param(h, VE_CONF_HA_PRIO, &data))) {
		rc = putErr(MIG_ERR_VZCTL, "vzctl2_env_get_param(%s) error: %s",
			VE_CONF_HA_PRIO, vzctl2_get_last_error());
		goto cleanup;
	}
	if (data) {
		unsigned long prio = 0;
		errno = 0;
		prio = strtoul(data, NULL, 10);
		if (errno == 0) {
			ve->ha_prio = prio;
		} else {
			logger(LOG_ERR, "Unable to parse from global config %s=%s (%s)",
			       VE_CONF_HA_PRIO, data, strerror(errno));
		}
	}

	if ( !(rc = vzctl2_env_get_param(h, VE_CONF_QUOTAUGIDLIMIT, &data)) && (data != NULL) )
	{
		unsigned long quotaugidlimit = 0;
		errno = 0;
		quotaugidlimit = strtoul(data, NULL, 10);
		if (errno == 0)
		{
			logger(LOG_INFO, "quotaugidlimit = %ld", quotaugidlimit);
			ve->quotaugidlimit = quotaugidlimit;
		} else
			logger(LOG_ERR,
			       "Unable to parse from global config %s=%s (%s)",
			       VE_CONF_QUOTAUGIDLIMIT, data, strerror(errno));
	}

	/* DISK */
	struct vzctl_disk_param disk;
	vzctl_disk_iterator it = NULL;

	if (vzctl2_env_get_param(h, VE_CONF_DISK, &data) == 0 && data != NULL)
		ve->disk_raw_str = strdup(data);

	while ((it = vzctl2_env_get_disk(env, it)) != NULL) {

		vzctl2_env_get_disk_param(it, &disk, sizeof(disk));

		/* FIXME: use normalized path */
		if (disk.storage_url != NULL) {
			logger(LOG_DEBUG, "non persistent disk %s", disk.path);
			rc = string_list_add(&ve->_np_disk, disk.path);
		} else if (strncmp(ve->priv, disk.path, strlen(ve->priv)) == 0) {
			logger(LOG_DEBUG, "disk %s", disk.path);
			rc = string_list_add(&ve->_disk, disk.path);
		} else {
			logger(LOG_DEBUG, "external disk %s", disk.path);
			rc = string_list_add(&ve->_ext_disk, disk.path);
		}

		if (rc)
			goto cleanup;
	}


cleanup:
	vzctl2_env_close(h);

	return rc;
}

/* run argv[0] with argv and envp, stderr redirect to log */
int vzm_execve(
		char *const argv[],
		char *const envp[],
		int in,
		int out,
		int *retcode)
{
	int rc, i, perr[2];
	pid_t pid, chpid;
	int status;
	FILE *fp;
	char buffer[MAX_CMD_SIZE + 1];
	char path[PATH_MAX+1];

	if (terminated)
		return MIG_ERR_TERM;

	strncpy(path, argv[0], sizeof(path));
/* TODO: relative path */
	if (debug_level >= LOG_DEBUG) {
		buffer[0] = '\0';
		for (i = 0; argv[i]; i++) {
			strncat(buffer, argv[i],
					sizeof(buffer)-strlen(buffer)-1);
			strncat(buffer, " ", sizeof(buffer)-strlen(buffer)-1);
		}
		logger(LOG_DEBUG, buffer);
	}

	if (pipe(perr))
		return putErr(MIG_ERR_SYSTEM, "pipe() : %m");

	if ((chpid = fork()) < 0) {
		close(perr[0]); close(perr[1]);
		return putErr(MIG_ERR_SYSTEM, "fork() : %m");
	} else if (chpid == 0) {
		/* redirect stdin/stdout into in/out or /dev/null */
		if (in == -1) {
			int fd;
			fd = open("/dev/null", O_RDONLY);
			dup2(fd, STDIN_FILENO);
			close(fd);
		} else {
			dup2(in, STDIN_FILENO);
		}
		if (out == -1) {
			int fd;
			fd = open("/dev/null", O_WRONLY);
			dup2(fd, STDOUT_FILENO);
			close(fd);
		} else {
			dup2(out, STDOUT_FILENO);
		}
		/* redirect stderr to pipe */
		close(perr[0]);
		dup2(perr[1], STDERR_FILENO);
		close(perr[1]);
		if (in != -1)
			close(in);
		if (out != -1)
			close(out);
		/* allow C-c for child */
		signal(SIGINT, SIG_DFL);
		if (envp)
			execve(argv[0], argv, envp);
		else
			execvp(argv[0], argv);
		exit(MIG_ERR_SYSTEM);
	}
	close(perr[1]);
	/* read stderr and put to log */
	if ((fp = fdopen(perr[0], "r")) != NULL) {
		while(fgets(buffer, sizeof(buffer), fp)) {
			if (buffer[strlen(buffer)-1] == '\n')
				buffer[strlen(buffer)-1] = '\0';
			logger(LOG_ERR, "%s : %s", basename(path), buffer);
		}
		fclose(fp);
	}
	close(perr[0]);

	while ((pid = waitpid(chpid, &status, 0)) == -1)
		if (errno != EINTR)
			break;

	if (pid < 0)
		return putErr(MIG_ERR_SYSTEM, "waitpid() : %m");

	if (WIFEXITED(status)) {
		rc = WEXITSTATUS(status);
		if (retcode)
			*retcode = rc;
		if (rc)
			return putErr(MIG_ERR_TASK_FAILED,
				"%s exited with code %d", argv[0], rc);
	} else if (WIFSIGNALED(status)) {
		return putErr(MIG_ERR_TASK_SIGNALED,
			"%s got signal %d", argv[0], WTERMSIG(status));
	} else {
		return putErr(MIG_ERR_TASK_EXITED,
			"%s exited with status %d", argv[0], status);
	}
	return 0;
}

/*
 * run argv[0] with argv and envp, stderr and stdout redirect to /dev/null
 *
 * and do not print any error messages
 */
int vzm_execve_quiet(
		char *const argv[],
		char *const envp[],
		int in,
		int *retcode)
{
	pid_t pid, chpid;
	int status;
	char path[PATH_MAX+1];

	if (terminated)
		return MIG_ERR_TERM;

	strncpy(path, argv[0], sizeof(path));

	if ((chpid = fork()) < 0) {
		return MIG_ERR_SYSTEM;
	} else if (chpid == 0) {
		/* redirect stdout and stderr to /dev/null */
		int fd;
		if (in != -1) {
			close(STDIN_FILENO);
			dup2(in, STDIN_FILENO);
			close(in);
		}
		fd = open("/dev/null", O_WRONLY);
		close(STDOUT_FILENO);
		dup2(fd, STDOUT_FILENO);
		close(STDERR_FILENO);
		dup2(fd, STDERR_FILENO);
		close(fd);
		/* allow C-c for child */
		signal(SIGINT, SIG_DFL);
		if (envp)
			execve(argv[0], argv, envp);
		else
			execvp(argv[0], argv);
		exit(MIG_ERR_SYSTEM);
	}

	while ((pid = waitpid(chpid, &status, 0)) == -1)
		if (errno != EINTR)
			break;

	if (pid < 0)
		return MIG_ERR_SYSTEM;

	if (retcode)
		*retcode = status;
	if (!WIFEXITED(status) || WEXITSTATUS(status))
		return MIG_ERR_SYSTEM;

	return 0;
}

/* run arglist[0] with arglist and envlist */
int vzml_execve(
		struct string_list *arglist,
		struct string_list *envlist,
		int in,
		int out,
		int quiet)
{
	int rc;
	char **argv = NULL;
	char **envp = NULL;
	int i;

	if ((rc = string_list_to_array(arglist, &argv)))
		return rc;

	if (envlist) {
		if ((rc = string_list_to_array(envlist, &envp)))
			goto cleanup;
	}

	if (quiet)
		rc = vzm_execve_quiet((char *const *)argv, (char *const *)envp,
				in, NULL);
	else
		rc = vzm_execve((char *const *)argv, (char *const *)envp,
				in, out, NULL);

	if (envp)
		for (i = 0; envp[i]; i++)
			free((void *)envp[i]);
cleanup:
	for (i = 0; argv[i]; i++)
		free((void *)argv[i]);

	return rc;
}

/* create directory with parent directories as needed */
int make_dir(const char *path, mode_t mode)
{
	char buf[PATH_MAX+1];
	char *ptr;

	if (path[0] != '/')
		return putErr(MIG_ERR_SYSTEM,
			"non-absolute path : %s", path);
	if (strlen(path)+1 > sizeof(buf))
		return putErr(MIG_ERR_SYSTEM,
			"too long path : %s", path);
	strcpy(buf, path);
	/* skip leading slashes */
	for (ptr=(char *)buf; *ptr=='/'; ++ptr);
	while(1) {
		if ((ptr = strchr(ptr, '/')))
			*ptr = '\0';
		if ((mkdir(buf, mode)) == -1) {
			if (errno == EEXIST) {
				struct stat st;
				if ((stat(buf, &st)))
					return putErr(MIG_ERR_SYSTEM,
						"stat(%s) : %m", buf);
				if (!S_ISDIR(st.st_mode))
					return putErr(MIG_ERR_SYSTEM,
						"%s is not a directory", buf);
			} else {
				return putErr(MIG_ERR_SYSTEM,
					"mkdir(%s) : %m", buf);
			}
		}
		if (ptr == NULL)
			break;
		*ptr = '/';
		/* skip leading slashes */
		for (ptr=(char *)ptr; *ptr=='/'; ++ptr);
	}
	return 0;
}

/* copy from file src to file dst */
int copy_file(const char *dst, const char *src)
{
	int s, d;
	struct stat st;
	struct utimbuf ut;
	char buf[BUFSIZ];
	int rs = 0, ws = 0;

	logger(LOG_DEBUG, "copy file %s -> %s", src, dst);

	if (stat(dst, &st) == 0) {
		/* previously used copyFile() function rewrote existing file */
		if (!S_ISREG(st.st_mode) && !S_ISLNK(st.st_mode))
			return putErr(MIG_ERR_SYSTEM, "%s already exist, "
				"buf is not a file or symlink", dst);
	}
	if (stat(src, &st))
		return putErr(MIG_ERR_SYSTEM, "stat(%s): %m", src);

#ifdef O_LARGEFILE
	if ((d = open(dst, O_WRONLY|O_CREAT|O_TRUNC|O_LARGEFILE, 0600)) == -1)
#else
	if ((d = open(dst, O_WRONLY|O_CREAT|O_TRUNC, 0600 )) == -1)
#endif
		return putErr(MIG_ERR_SYSTEM, "open(%s): %m", dst);

	if ((s = open(src, O_RDONLY)) == -1) {
		close(d);
		return putErr(MIG_ERR_SYSTEM, "open(%s): %m", src);
	}

	while ((rs = read(s, (void *)buf, sizeof(buf))) > 0) {
		if ((ws = write(d, (void *)buf, rs)) == -1)
			break;
	}
	close(s);
        close(d);
	if (ws == -1) {
		unlink(dst);
		return putErr(MIG_ERR_SYSTEM, "write() to %s: %m", src);
	} else if (rs == -1) {
		unlink(dst);
		return putErr(MIG_ERR_SYSTEM, "read() from %s: %m", dst);
	}
	ut.actime = st.st_atime;
	ut.modtime = st.st_mtime;

	if (lchown(dst, st.st_uid, st.st_gid))
		logger(LOG_ERR, "lchown(%s): %m", dst);
	if (chmod(dst, st.st_mode & 07777))
		logger(LOG_ERR, "chmod(%s): %m", dst);
	if (utime(dst, &ut))
		logger(LOG_ERR, "utime(%s): %m", dst);

	return 0;
}

/* move from file src to file dst */
int move_file(const char *dst, const char *src)
{
	int rc;

	if (access(dst, F_OK) == 0)
		return putErr(MIG_ERR_SYSTEM, "File %s already exist", dst);

	if (rename(src, dst) == 0)
		return 0;

	if (errno != EXDEV)
		return putErr(MIG_ERR_SYSTEM, "rename(%s, %s): %m", src, dst);

	/* src and dst are not on the same filesystem */
	/* try to copy */
	if ((rc = copy_file(dst, src)))
		return rc;

	/* remove source */
	unlink(src);

	return 0;
}

/* get temporary directory */
int get_tmp_dir(char *path, size_t sz)
{
	int i;
	struct stat st;
	char *tmp_dirs[] = {VZ_TMP_DIR, "/var/tmp/", "/tmp/", NULL};
	char *tmp;

	/* use TMP envdir if exist */
	if ((tmp = getenv("TMP"))) {
		strncpy(path, tmp, sz);
		if (stat(path, &st) == 0) {
			if (S_ISDIR(st.st_mode)) {
				return 0;
			}
		}
	}
	/* check available tmpdir */
	for (i = 0; tmp_dirs[i]; i++) {
		if (stat(tmp_dirs[i], &st))
			continue;
		if (!S_ISDIR(st.st_mode))
			continue;
		strncpy(path, tmp_dirs[i], sz);
		return 0;
	}
	return -1;
}

/* split path on mount point and path on device */
int split_path(	const char *path,
		char *mp,
		size_t msize,
		char *lpath,
		size_t lsize)
{
	struct stat st;
	dev_t dev;
	char buf[PATH_MAX+1];
	char *p;

	if (path[0] != '/')
		return putErr(MIG_ERR_SYSTEM,
			"%s is not a absolute path", path);

	strncpy(buf, path, sizeof(buf));
	/* skip non-exists part of path */
	while (1) {
		errno = 0;
		if (stat(buf, &st) == 0)
			break;
		if (errno != ENOENT)
			return putErr(MIG_ERR_SYSTEM, "stat(%s)", buf);

		p = strrchr(buf, '/');
		if (p <= buf) {
			/* p == buf or p == NULL
			   (though last is not possible for absolute path) */
			strcpy(buf, "/");
			break;
		}
		*p = '\0';
	}

	/* only for '/' case */
	if (stat(buf, &st))
		return putErr(MIG_ERR_SYSTEM, "stat(%s)", buf);

	dev = st.st_dev;
	while (1) {
		if (stat(buf[0] ? buf : "/", &st))
			return putErr(MIG_ERR_SYSTEM,
				"stat(%s)", buf[0] ? buf : "/");

		if (st.st_dev != dev)
			break;
		if ((p = strrchr(buf, '/')) == NULL) {
			strcpy(mp, "/");
			break;
		}
		strncpy(mp, buf, msize);
		*p = '\0';
	}

	for(p = (char *)(path + strlen(mp)); *p == '/'; p++) ;
	strncpy(lpath, p, lsize);

	return 0;
}

int get_ve_root(const char *ctid, char *root, size_t size)
{
	int err, rc;
	const char *ve_root;
	struct vzctl_env_handle *h;

	h = vzctl2_env_open(ctid,
		VZCTL_CONF_SKIP_GLOBAL | VZCTL_CONF_BASE_SET | VZCTL_CONF_SKIP_PARAM_ERRORS, &err);
	if (err)
		return putErr(MIG_ERR_VZCTL, "vectl_env_open(%s) error: %s",
				ctid, vzctl2_get_last_error());

	rc = vzctl2_env_get_ve_root_path(vzctl2_get_env_param(h), &ve_root);
	if (rc)
		rc = putErr(MIG_ERR_VZCTL,
			"can't read VE_ROOT from CT %s config", ctid);
	else
		strncpy(root, ve_root, size);

	vzctl2_env_close(h);

	return rc;
}

int check_exit_status(char *task, int status)
{
	int rc;

	if (WIFEXITED(status)) {
		if ((rc = WEXITSTATUS(status)))
			return putErr(MIG_ERR_SYSTEM,
				"%s exited with code %d", task, rc);
	} else if (WIFSIGNALED(status)) {
		return putErr(MIG_ERR_SYSTEM,
			"%s got signal %d", task, WTERMSIG(status));
	} else {
		return putErr(MIG_ERR_SYSTEM,
			"%s exited with status %d", task, status);
	}
	return 0;
}

void dump_args(const char *title, char * const *args)
{
	char buffer[BUFSIZ + 1];
	int i;

	buffer[0] = '\0';
	for (i = 0; args[i]; i++) {
		strncat(buffer, args[i], sizeof(buffer)-strlen(buffer)-1);
		strncat(buffer, " ", sizeof(buffer)-strlen(buffer)-1);
	}
	logger(LOG_DEBUG, "%s%s", title, buffer);
}

int check_fl_prls_release()
{
	struct stat file_stat;
	int fd, ret = 0;

	/* Open file */
	fd = open( fl_prls_release, O_RDONLY);
	if( fstat( fd, &file_stat) == 0)
	{
		close(fd);
		ret =  1;
	}
	return ret;
}

int vz_setiolimit()
{
	if (vzctl2_set_vzlimits("VZ_TOOLS"))
		return putErr(MIG_ERR_VZCTL,
				"Failed to set VZ_TOOLS limits: %s",
				vzctl2_get_last_error());
	return 0;
}

int bind_mount(const char *src, int extra_flags, char *dst, size_t size)
{
	int flags = MS_BIND | extra_flags;

	mkdir("/vz/tmp", 0755);
	snprintf(dst, size, "/vz/tmp/vzmigrate.XXXXXX");
	if (mkdtemp(dst) == NULL)
		return putErr(MIG_ERR_SYSTEM, "mkdtemp(%s) : %m", dst);
	if (mount(src, dst, "", flags, 0) < 0) {
		rmdir(dst);
		return putErr(MIG_ERR_SYSTEM, "mount(%s->%s) : %m", src, dst);
	}

	return 0;
}

void bind_umount(char *dir)
{
	if (umount(dir))
		logger(LOG_WARNING, "umount(%s) error : %m", dir);
	if (rmdir(dir))
		logger(LOG_WARNING, "rmdir(%s) error : %m", dir);
}

const char *get_full_path(const char *ve_private, const char *fname,
		char *out,int size)
{
	if (fname[0] == '/')
		snprintf(out, size, "%s", fname);
	else
		snprintf(out, size, "%s/%s", ve_private, fname);

	return out;
}

int is_external_disk(const char *delta)
{
	return (delta[0] == '/');
}

int get_disk_usage_ploop(const char *path, unsigned long long *bytes)
{
	char cmd[BUFSIZ];
	char buf[BUFSIZ];
	FILE *fd;
	char *p;

	snprintf(cmd, sizeof(cmd), "du -s -B 1 %s", path);

	if ((fd = popen(cmd, "r")) == NULL)
		return putErr(MIG_ERR_SYSTEM, "popen('%s') : %m", cmd);

	if (fgets(buf, sizeof(buf), fd) == NULL) {
		pclose(fd);
		return putErr(MIG_ERR_SYSTEM, "'%s' failed : %m", cmd);
	}
	pclose(fd);
	for (p = buf; isdigit(*p); p++);
	*p = '\0';
	*bytes = (unsigned long long)strtoll(buf, &p, 10);
	if (*p != '\0') {
		return putErr(MIG_ERR_SYSTEM, "Invalid '%s' output : '%s'", cmd, buf);
	}
	return 0;
}

int open_pipes(int pipefd[2])
{
	int rc;

	rc = pipe(pipefd);
	if (rc == -1)
		init_pipes(pipefd);
	return rc;
}

void init_pipes(int pipefd[2])
{
	pipefd[0] = -1;
	pipefd[1] = -1;
}

void close_safe(int *fd)
{
	int rc;

	if (!fd) {
		logger(LOG_ERR, "close_safe(NULL)");
		return;
	}

	if (*fd != -1) {
		while (((rc = close(*fd)) == -1) && (rc == EINTR));
		if (rc == -1)
			logger(LOG_ERR, "close(%i) : %m", *fd);
		*fd = -1;
	}
}

int get_fd(char *arg)
{
	int new_fd, fd = atoi(arg);

	if (fd < 1024)
		return fd;
	
	new_fd = dup(fd);
	if (new_fd < 0) {
		logger(LOG_ERR, "Unable to duplicate file descriptor %s: %m", arg);
		return new_fd;
	}
	close(fd);
	fcntl(new_fd, F_SETFD, ~FD_CLOEXEC);
	return new_fd;
}

void close_pipes(int pipefd[2])
{
	close_safe(&pipefd[0]);
	close_safe(&pipefd[1]);
}

void term_clean(pid_t pid, int timeout)
{
	int status, rc;

	kill(pid, SIGTERM);
	while (timeout > 0) {
		rc = waitpid(pid, &status, WNOHANG);
		if (rc == -1) {
			logger(LOG_ERR, "waitpid(%i) : %m", pid);
			return;
		}
		if (rc > 0)
			return;
		sleep(1);
		--timeout;
	}
	kill(pid, SIGKILL);
	rc = waitpid(pid, &status, 0);
	if (rc == -1) {
		logger(LOG_ERR, "waitpid(%i) : %m", pid);
		return;
	}
}

void gen_uuid(char *buf)
{
	uuid_t out;

	uuid_generate(out);
	uuid_unparse(out, buf);
}

int rmdir_recursively(const char *dirname)
{
	char path[PATH_MAX+1];
	DIR * dir;
	struct dirent * de;
	struct stat st;
	int rc = 0;

	if ((dir = opendir(dirname)) == NULL)
		return putErr(MIG_ERR_SYSTEM, "opendir(%s) error", dirname);

	while (1) {
		errno = 0;
		if ((de = readdir(dir)) == NULL) {
			if (errno)
				rc = putErr(MIG_ERR_SYSTEM,
					"readdir(%s) error", dirname);
			break;
		}

		if(!strcmp(de->d_name,"."))
			continue;

		if(!strcmp(de->d_name,".."))
			continue;

		snprintf(path, sizeof(path), "%s/%s", dirname, de->d_name);

		if (lstat(path, &st)) {
			rc = putErr(MIG_ERR_SYSTEM, "stat(%s) error", path);
			break;
		}

		if (S_ISDIR(st.st_mode)) {
			if ((rc = rmdir_recursively(path)))
				break;
			continue;
		}
		/* remove regfile, symlink, fifo, socket or device */
		if (unlink(path)) {
			rc = putErr(MIG_ERR_SYSTEM, "unlink(%s) error", path);
			break;
		}
	}
	closedir(dir);

	/* and remove directory */
	if (rc)
		return rc;

	if (rmdir(dirname))
		return putErr(MIG_ERR_SYSTEM, "rmdir(%s) error", dirname);
	return 0;
}

unsigned long long floor2digit(unsigned long long v)
{
	double e, e2;

	e = log10(v);
	e2 = floor(e) - 1;
	return floor(exp10(e - e2)) * exp10(e2);
}

unsigned long long ceil2digit(unsigned long long v)
{
	double e, e2;

	e = log10(v);
	e2 = floor(e) - 1;
	return ceil(exp10(e - e2)) * exp10(e2);
}

void copy_cstr(const char *str, char *buf, size_t buf_size)
{
	snprintf(buf, buf_size, "%s", str);
}

/* set 'trusted.pfcache' xattr on path to switch on checksum calculation */
int pfcache_set(const char *path, int on)
{
	int c;
	const char *args[4];
	int rc;

	c = 0;
	args[c++] = PFCACHE_BIN;
	args[c++] = on ? "set" : "clear";
	args[c++] = path;
	args[c] = NULL;

	if ((rc = vzm_execve((char *const*)args, NULL, -1, -1, NULL)))
		logger(LOG_ERR, PFCACHE_BIN " %s %s failed", on ? "set" : "clear", path);
	return rc;
}
