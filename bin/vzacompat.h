/*
 * Copyright (c) 2008-2017, Parallels International GmbH
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
#ifndef __VZACOMPAT_H_
#define __VZACOMPAT_H_

int vza_init_cli(struct vzsock_ctx *ctx, void **conn);
int vza_send_data(
		struct vzsock_ctx *ctx,
		void *conn,
		const char * cmd,
		char * const *argv);
int vza_init_srv(
		struct vzsock_ctx *ctx,
		void **conn);
/* for vzagent mode: chdir to dst, connect to src SVE/node via ssh,
   run tar as server and unpack all from ssh stdout */
int vza_recv_data(
		struct vzsock_ctx *ctx,
		void *conn,
		char * const argv[]);

#endif
