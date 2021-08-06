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

#include <stdlib.h>
#include <string.h>

#include "ct_config.h"
#include "common.h"
#include "veentry.h"

vz_data::vz_data()
	: root_orig(NULL)
	, priv_orig(NULL)
	, lockdir(NULL)
	, tmpldir(NULL)
	, dumpdir(NULL)
	, quota(0)
	, shaping(0)
	, removemigrated(0)
	, iolimit(0)
{
}

int vz_data_load(struct vz_data *vz)
{
	int err, rc = 0;
	const char *data;
	struct vzctl_env_handle *h;
	struct vzctl_env_param *env;

	h = vzctl2_env_open_conf(0, VZ_CONF, VZCTL_CONF_SKIP_GLOBAL | VZCTL_CONF_SKIP_PARAM_ERRORS, &err);
	if (err)
		return putErr(MIG_ERR_VZCTL, "vzctl2_env_open(%s) error: %s",
			VZ_CONF, vzctl2_get_last_error());

	env = vzctl2_get_env_param(h);

	/* read original root and private */
	if (vzctl2_env_get_ve_root_orig_path(env, &data)) {
		rc = putErr(MIG_ERR_SYSTEM, "Can't read VE_ROOT from " VZ_CONF);
		goto cleanup;
	}

	if ((vz->root_orig = strdup(data)) == NULL) {
		rc = putErr(MIG_ERR_SYSTEM, MIG_MSG_SYSTEM);
		goto cleanup;
	}

	if (vzctl2_env_get_ve_private_orig_path(env, &data)) {
		rc = putErr(MIG_ERR_SYSTEM, "Can't read VE_PRIVATE from " VZ_CONF);
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
		data = DEFAULT_DUMP_DIR;
		logger(LOG_WARNING, "Can't read " VZ_CONF_DUMPDIR " from " VZ_CONF
			"; default value (%s) will be used", data);
	}
	if ((vz->dumpdir = strdup(data)) == NULL) {
		rc = putErr(MIG_ERR_SYSTEM, MIG_MSG_SYSTEM);
		goto cleanup;
	}

	/* read DISK_QUOTA */
	if ((rc = vzctl2_env_get_param(h, VZ_CONF_QUOTA, &data)) == 0 && data != NULL)
		vz->quota = (strcasecmp(data, "yes") == 0);

	/* read TRAFFIC_SHAPING */
	if ((rc = vzctl2_env_get_param(h, VZ_CONF_SHAPING, &data)) == 0 && data != NULL)
		vz->shaping = (strcasecmp(data, "yes") == 0);

	/* read REMOVEMIGRATED */
	if ((rc = vzctl2_env_get_param(h, VZ_CONF_REMOVEMIGRATED, &data)) == 0 && data != NULL)
		vz->removemigrated = (strcasecmp(data, "yes") == 0);

cleanup:
	vzctl2_env_close(h);

	return rc;
}

ve_disk_data::ve_disk_data(const vzctl_disk_param& disk_param)
	: m_path(disk_param.path)
	, m_uuid(disk_param.uuid)
	, m_mnt((disk_param.mnt != NULL) ? disk_param.mnt : "")
{
}

ve_data::ve_data()
	: name(NULL)
	, uuid(NULL)
	, ostemplate(NULL)
	, technologies(0)
	, bindmount(NULL)
	, root(NULL)
	, root_orig(NULL)
	, priv(NULL)
	, priv_orig(NULL)
	, ve_type(NULL)
	, slmmode(NULL)
	, quotaugidlimit(0)
	, ha_enable(1)
	, ha_prio(0)
	, disk_raw_str(NULL)
{
	memset(diskspace, 0, sizeof(diskspace));
	memset(diskinodes, 0, sizeof(diskinodes));

	string_list_init(&ipaddr);
	string_list_init(&rate);
	string_list_init(&templates);
}

ve_data::~ve_data()
{
	free(name);
	free(uuid);
	free(ostemplate);
	free(bindmount);
	free(root);
	free(root_orig);
	free(priv);
	free(priv_orig);
	free(ve_type);
	free(slmmode);
	free(disk_raw_str);

	string_list_clean(&ipaddr);
	string_list_clean(&rate);
	string_list_clean(&templates);
}

static int do_ve_data_load(struct vzctl_env_handle *h, struct ve_data *ve)
{
	int rc = 0;
	const char *data;
	char *str, *token;
	struct vzctl_env_param *env;
	struct vzctl_disk_param disk;
	vzctl_disk_iterator it = NULL;


	env = vzctl2_get_env_param(h);

	/* read expanded and original root and private */
	if (vzctl2_env_get_ve_root_orig_path(env, &data))
		return putErr(MIG_ERR_SYSTEM,
			"Can't read VE_ROOT from CT config");
	if ((ve->root_orig = strdup(data)) == NULL)
		return putErr(MIG_ERR_SYSTEM, MIG_MSG_SYSTEM);
	if (vzctl2_env_get_ve_root_path(env, &data))
		return putErr(MIG_ERR_SYSTEM, "Can't read VE_ROOT from CT config");
	if ((ve->root = strdup(data)) == NULL)
		return putErr(MIG_ERR_SYSTEM, MIG_MSG_SYSTEM);
	if (vzctl2_env_get_ve_private_orig_path(env, &data))
		return putErr(MIG_ERR_SYSTEM,
				"Can't read VE_PRIVATE from CT config");
	if ((ve->priv_orig = strdup(data)) == NULL)
		return putErr(MIG_ERR_SYSTEM, MIG_MSG_SYSTEM);
	if (vzctl2_env_get_ve_private_path(env, &data))
		return putErr(MIG_ERR_SYSTEM, "Can't read VE_PRIVATE from CT config");
	if ((ve->priv = strdup(data)) == NULL)
		return putErr(MIG_ERR_SYSTEM, MIG_MSG_SYSTEM);
	remove_trail_slashes(ve->priv);

	/* read OSTEMPLATE */
	if ((rc = vzctl2_env_get_param(h, VE_CONF_OSTEMPLATE, &data)))
		return putErr(MIG_ERR_VZCTL, "vzctl2_env_get_param(%s) error: %s",
			VE_CONF_OSTEMPLATE, vzctl2_get_last_error());
	if (data == NULL)
		ve->ostemplate = strdup("");
	else
		ve->ostemplate = strdup(data);
	if (ve->ostemplate == NULL)
		return putErr(MIG_ERR_SYSTEM, MIG_MSG_SYSTEM);
	/* read UUID */
	if ((rc = vzctl2_env_get_param(h, VE_CONF_UUIDDIR, &data)))
		return putErr(MIG_ERR_VZCTL, "vzctl2_env_get_param(%s) error: %s",
			VE_CONF_UUIDDIR, vzctl2_get_last_error());
	if (data) {
		if ((ve->uuid = strdup(data)) == NULL)
			return putErr(MIG_ERR_SYSTEM, MIG_MSG_SYSTEM);
	}

	/* read TECHNOLOGIES */
	if ((rc = vzctl2_env_get_param(h, VE_CONF_TECHNOLOGIES, &data)))
		return putErr(MIG_ERR_VZCTL, "vzctl2_env_get_param(%s) error: %s",
			VE_CONF_TECHNOLOGIES, vzctl2_get_last_error());
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
			if ((tech = vzctl2_name2tech(token)) == 0)
				return putErr(MIG_ERR_TECHNOLOGIES,
				"Unknown technology in TECHNOLOGIES: %s",\
					token);
			ve->technologies |= tech;
		}
	}

	/* read NAME */
	if ((rc = vzctl2_env_get_param(h, VE_CONF_NAME, &data)))
		return putErr(MIG_ERR_VZCTL, "vzctl2_env_get_param(%s) error: %s",
			VE_CONF_NAME, vzctl2_get_last_error());
	if (data) {
		if ((ve->name = strdup(data)) == NULL)
			return putErr(MIG_ERR_SYSTEM, MIG_MSG_SYSTEM);
	}

	/* read BINDMOUNT */
	if ((rc = vzctl2_env_get_param(h, VE_CONF_BINDMOUNT, &data)))
		return putErr(MIG_ERR_VZCTL, "vzctl2_env_get_param(%s) error: %s",
			VE_CONF_BINDMOUNT, vzctl2_get_last_error());
	if (data) {
		if ((ve->bindmount = strdup(data)) == NULL)
			return putErr(MIG_ERR_SYSTEM, MIG_MSG_SYSTEM);
	}

	/* read IP_ADDRESS */
	if ((rc = vzctl2_env_get_param(h, VE_CONF_IPADDR, &data)))
		return putErr(MIG_ERR_VZCTL, "vzctl2_env_get_param(%s) error: %s",
			VE_CONF_IPADDR, vzctl2_get_last_error());
	if (data) {
		for (str = strdupa(data); ;str = NULL) {
			if ((token = strtok(str, "  ")) == NULL)
				break;
			if ((rc = string_list_add(&ve->ipaddr, token)))
				return rc;
		}
	}

	/* read RATE */
	if ((rc = vzctl2_env_get_param(h, VE_CONF_RATE, &data)))
		return putErr(MIG_ERR_VZCTL, "vzctl2_env_get_param(%s) error: %s",
			VE_CONF_RATE, vzctl2_get_last_error());
	if (data) {
		for (str = strdupa(data); ;str = NULL) {
			if ((token = strtok(str, "  ")) == NULL)
				break;
			if ((rc = string_list_add(&ve->rate, token)))
				return rc;
		}
	}

	/* read VE_TYPE */
	if ((rc = vzctl2_env_get_param(h, VE_CONF_VETYPE, &data)))
		return putErr(MIG_ERR_VZCTL, "vzctl2_env_get_param(%s) error: %s",
			VE_CONF_VETYPE, vzctl2_get_last_error());
	if (data) {
		if ((ve->ve_type = strdup(data)) == NULL)
			rc = putErr(MIG_ERR_SYSTEM, MIG_MSG_SYSTEM);
	}

	/* read DISKSPACE */
	if ((rc = vzctl2_env_get_param(h, VE_CONF_DISKSPACE , &data)))
		return putErr(MIG_ERR_VZCTL, "vzctl2_env_get_param(%s) error: %s",
			VE_CONF_DISKSPACE, vzctl2_get_last_error());
	if (data) {
		if ((str = (char*)strchr(data, ':'))) {
			*str = '\0';
			ve->diskspace[0] = atol(data);
			ve->diskspace[1] = atol(++str);
		}
	}

	/* read DISKINODES */
	if ((rc = vzctl2_env_get_param(h, VE_CONF_DISKINODES , &data)))
		return putErr(MIG_ERR_VZCTL, "vzctl2_env_get_param(%s) error: %s",
			VE_CONF_DISKINODES, vzctl2_get_last_error());
	if (data) {
		if ((str = (char*)strchr(data, ':'))) {
			*str = '\0';
			ve->diskinodes[0] = atol(data);
			ve->diskinodes[1] = atol(++str);
		}
	}

	/* read TEMPLATES */
	if ((rc = vzctl2_env_get_param(h, VE_CONF_TEMPLATES, &data)))
		return putErr(MIG_ERR_VZCTL, "vzctl2_env_get_param(%s) error: %s",
			VE_CONF_TEMPLATES, vzctl2_get_last_error());
	if (data) {
		for (str = strdupa(data); ;str = NULL) {
			if ((token = strtok(str, "  ")) == NULL)
				break;
			if ((rc = string_list_add(&ve->templates, token)))
				return rc;
		}
	}

	/* read SLMMODE */
	if ((rc = vzctl2_env_get_param(h, VE_CONF_SLMMODE, &data)))
		return putErr(MIG_ERR_VZCTL, "vzctl2_env_get_param(%s) error: %s",
			VE_CONF_SLMMODE, vzctl2_get_last_error());
	if (data) {
		if ((ve->slmmode = strdup(data)) == NULL)
			return putErr(MIG_ERR_SYSTEM, MIG_MSG_SYSTEM);
	}

	/* read HA_ENABLE */
	if ((rc = vzctl2_env_get_param(h, VE_CONF_HA_ENABLE, &data)))
		return putErr(MIG_ERR_VZCTL, "vzctl2_env_get_param(%s) error: %s",
			VE_CONF_HA_ENABLE, vzctl2_get_last_error());
	if (data)
		ve->ha_enable = !strcasecmp(data, "yes");

	/* read HA_PRIO */
	if ((rc = vzctl2_env_get_param(h, VE_CONF_HA_PRIO, &data)))
		return putErr(MIG_ERR_VZCTL, "vzctl2_env_get_param(%s) error: %s",
			VE_CONF_HA_PRIO, vzctl2_get_last_error());
	if (data) {
		errno = 0;
		unsigned long prio = strtoul(data, NULL, 10);
		if (errno == 0) {
			ve->ha_prio = prio;
		} else {
			logger(LOG_ERR, "Unable to parse from global config %s=%s (%s)",
				VE_CONF_HA_PRIO, data, strerror(errno));
		}
	}

	if (!(rc = vzctl2_env_get_param(h, VE_CONF_QUOTAUGIDLIMIT, &data)) && (data != NULL)) {
		errno = 0;
		unsigned long quotaugidlimit = strtoul(data, NULL, 10);
		if (errno == 0) {
			logger(LOG_INFO, "quotaugidlimit = %ld", quotaugidlimit);
			ve->quotaugidlimit = quotaugidlimit;
		} else {
			logger(LOG_ERR, "Unable to parse from global config %s=%s (%s)",
				VE_CONF_QUOTAUGIDLIMIT, data, strerror(errno));
		}
	}

	/* DISK */
	if (vzctl2_env_get_param(h, VE_CONF_DISK, &data) == 0 && data != NULL)
		ve->disk_raw_str = strdup(data);

	while ((it = vzctl2_env_get_disk(env, it)) != NULL) {

		vzctl2_env_get_disk_param(it, &disk, sizeof(disk));

		if (disk.use_device) {
			logger(LOG_DEBUG, "device %s", disk.path);
			ve->dev_disks.push_back(ve_disk_data(disk));
		/* FIXME: use normalized path */
		} else if (disk.storage_url != NULL) {
			logger(LOG_DEBUG, "non persistent disk %s", disk.path);
			ve->np_disks.push_back(ve_disk_data(disk));

		} else if (strncmp(ve->priv, disk.path, strlen(ve->priv)) == 0) {
			logger(LOG_DEBUG, "disk %s", disk.path);
			ve->disks.push_back(ve_disk_data(disk));

		} else if (disk.path[0] != '\0') {
			logger(LOG_DEBUG, "external disk %s", disk.path);
			ve->ext_disks.push_back(ve_disk_data(disk));
		} else {
			return putErr(MIG_ERR_VZCTL, "Unable to process disk %s:"
					" the image path is not specified", disk.uuid);
		}
	}

	return rc;
}

int ve_data_load_by_conf(const char *conf, struct ve_data *ve)
{
	int rc;
	struct vzctl_env_handle *h;

	h = vzctl2_env_open_conf(NULL, conf,
		VZCTL_CONF_SKIP_PARAM_ERRORS | VZCTL_CONF_UNREGISTERED, &rc);
	if (rc)
		return putErr(MIG_ERR_VZCTL, "vzctl2_env_open(%s) err: %d error: %s",
			conf, rc, vzctl2_get_last_error());

	rc = do_ve_data_load(h, ve);

	vzctl2_env_close(h);

	return rc;
}

int ve_data_load(const char *ctid, struct ve_data *ve)
{
	int rc;
	struct vzctl_env_handle *h;

	h = vzctl2_env_open(ctid, VZCTL_CONF_SKIP_PARAM_ERRORS, &rc);
	if (rc)
		return putErr(MIG_ERR_VZCTL, "vzctl2_env_open(%s) err: %d error: %s",
			ctid, rc, vzctl2_get_last_error());

	rc = do_ve_data_load(h, ve);
	vzctl2_env_close(h);

	return rc;
}
