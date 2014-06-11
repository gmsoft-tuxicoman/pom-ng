/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2013-2014 Guy Martin <gmsoft@tuxicoman.be>
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
#include <pom-ng/pload.h>

#define XMLRPCCMD_MONITOR_MAX_SESSION	32
#define XMLRPCCMD_MONITOR_TIMEOUT_MAX	3600
#define XMLRPCCMD_MONITOR_POLL_TIMEOUT	180

struct xmlrpccmd_monitor_session {

	unsigned int id;
	unsigned int polling;
	pthread_mutex_t lock;
	pthread_cond_t cond;
	struct timer_sys *timer;
	time_t timeout;
	int pload_events_listening;
	struct xmlrpccmd_monitor_event *events;
	struct xmlrpccmd_monitor_pload *ploads;
	struct xmlrpccmd_monitor_evtreg *events_reg;
	struct xmlrpccmd_monitor_pload_listener *pload_listeners;
	struct xmlrpccmd_monitor_httpd_pload *httpd_ploads;
};

struct xmlrpccmd_monitor_pload {

	uint64_t pload_id;
	struct pload *pload;
	unsigned int listeners_count;
	uint64_t *listeners;

	struct xmlrpccmd_monitor_pload *next;

};

struct xmlrpccmd_monitor_httpd_pload {

	uint64_t pload_id;
	uint32_t refcount;

	unsigned int listeners_count;
	uint64_t *listeners;

	UT_hash_handle hh;
};

struct xmlrpccmd_monitor_pload_listener {
	uint64_t id;
	struct filter_node *filter;
	struct xmlrpccmd_monitor_pload_listener *prev, *next;
};

struct xmlrpccmd_monitor_evt_listener {
	uint64_t id;
	struct filter_node *filter;
	struct xmlrpccmd_monitor_evt_listener *prev, *next;
};

struct xmlrpccmd_monitor_evtreg {

	struct xmlrpccmd_monitor_session *sess;
	struct event_reg *evt_reg;
	struct xmlrpccmd_monitor_evt_listener *listeners;
	struct xmlrpccmd_monitor_evtreg *prev, *next;
};

struct xmlrpccmd_monitor_event {

	struct event *evt;
	unsigned int listeners_count;
	uint64_t *listeners;
	struct xmlrpccmd_monitor_evtreg *event_reg;
	struct xmlrpccmd_monitor_event *prev, *next;
};

int xmlrpccmd_monitor_register_all();
int xmlrpccmd_monitor_evt_process_end(struct event *evt, void *obj);
int xmlrpccmd_monitor_pload_open(void *obj, void **priv, struct pload *pload);
int xmlrpccmd_monitor_pload_write(void *obj, void *priv, void *data, size_t len);
int xmlrpccmd_monitor_pload_close(void *obj, void *priv);
int xmlrpccmd_monitor_timeout(void *priv);
int xmlrpccmd_monitor_session_cleanup(struct xmlrpccmd_monitor_session *sess);
int xmlrpccmd_monitor_cleanup();

xmlrpc_value *xmlrpccmd_monitor_start(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData);
xmlrpc_value *xmlrpccmd_monitor_pload_add_listener(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData);
xmlrpc_value *xmlrpccmd_monitor_pload_remove_listener(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData);
xmlrpc_value *xmlrpccmd_monitor_event_add_listener(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData);
xmlrpc_value *xmlrpccmd_monitor_event_remove_listener(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData);
xmlrpc_value *xmlrpccmd_monitor_pload_events_listen(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData);
xmlrpc_value *xmlrpccmd_monitor_pload_discard(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData);
xmlrpc_value *xmlrpccmd_monitor_poll(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData);
xmlrpc_value *xmlrpccmd_monitor_build_pload(xmlrpc_env * const envP, struct pload *pload);
xmlrpc_value *xmlrpccmd_monitor_build_event(xmlrpc_env * const envP, struct event *evt);
xmlrpc_value *xmlrpccmd_monitor_build_data(xmlrpc_env * const envP, struct data_reg *dreg, struct data *data);
xmlrpc_value *xmlrpccmd_monitor_stop(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData);

#endif

