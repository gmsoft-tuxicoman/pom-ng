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

#ifndef __XMLRPCCMD_EVTMON_H__
#define __XMLRPCCMD_EVTMON_H__

#include "main.h"
#include <pom-ng/timer.h>

#define XMLRPCCMD_EVTMON_MAX_SESSION	32
#define XMLRPCCMD_EVTMON_TIMEOUT_MAX	3600

struct xmlrpccmd_evtmon_session {

	unsigned int id;
	pthread_mutex_t lock;
	pthread_cond_t cond;
	struct main_timer *timer;
	time_t timeout;
	struct xmlrpccmd_evtmon_reg_list *events_reg;
	struct xmlrpccmd_evtmon_list *events;

};

struct xmlrpccmd_evtmon_reg_list {

	struct event_reg *evt;
	struct xmlrpccmd_evtmon_reg_list *prev, *next;
};

struct xmlrpccmd_evtmon_list {

	struct event *evt;
	struct xmlrpccmd_evtmon_list *prev, *next;
};

int xmlrpccmd_evtmon_register_all();
int xmlrpccmd_evtmon_process_end(struct event *evt, void *obj);
int xmlrpccmd_evtmon_timeout(void *priv);
int xmlrpccmd_evtmon_session_cleanup(struct xmlrpccmd_evtmon_session *sess);
int xmlrpccmd_evtmon_cleanup();

xmlrpc_value *xmlrpccmd_evtmon_start(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData);
xmlrpc_value *xmlrpccmd_evtmon_add(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData);
xmlrpc_value *xmlrpccmd_evtmon_poll(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData);
xmlrpc_value *xmlrpccmd_evtmon_stop(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData);

#endif

