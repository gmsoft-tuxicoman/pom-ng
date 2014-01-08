/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2013 Guy Martin <gmsoft@tuxicoman.be>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#ifndef __XMLRPCCMD_MONITOR_H__
#define __XMLRPCCMD_MONITOR_H__

#include "main.h"
#include <pom-ng/timer.h>

#define XMLRPCCMD_MONITOR_MAX_SESSION	32
#define XMLRPCCMD_MONITOR_TIMEOUT_MAX	3600
#define XMLRPCCMD_MONITOR_POLL_TIMEOUT	180

struct xmlrpccmd_monitor_session {

	unsigned int id;
	pthread_mutex_t lock;
	pthread_cond_t cond;
	struct main_timer *timer;
	time_t timeout;
	struct xmlrpccmd_monitor_evtreg_list *events_reg;
	struct xmlrpccmd_monitor_evt_list *events;

};

struct xmlrpccmd_monitor_evtreg_list {

	struct event_reg *evt;
	struct xmlrpccmd_monitor_evtreg_list *prev, *next;
};

struct xmlrpccmd_monitor_evt_list {

	struct event *evt;
	struct xmlrpccmd_monitor_evt_list *prev, *next;
};

int xmlrpccmd_monitor_register_all();
int xmlrpccmd_monitor_process_end(struct event *evt, void *obj);
int xmlrpccmd_monitor_timeout(void *priv);
int xmlrpccmd_monitor_session_cleanup(struct xmlrpccmd_monitor_session *sess);
int xmlrpccmd_monitor_cleanup();

xmlrpc_value *xmlrpccmd_monitor_start(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData);
xmlrpc_value *xmlrpccmd_monitor_event_add(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData);
xmlrpc_value *xmlrpccmd_monitor_event_remove(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData);
xmlrpc_value *xmlrpccmd_monitor_poll(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData);
xmlrpc_value *xmlrpccmd_monitor_stop(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData);

#endif

