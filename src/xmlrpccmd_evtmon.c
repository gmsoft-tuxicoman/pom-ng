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

#include "common.h"
#include "xmlrpcsrv.h"
#include <pom-ng/event.h>

#include "xmlrpccmd.h"
#include "xmlrpccmd_evtmon.h"

static pthread_mutex_t xmlrpccmd_evtmon_session_lock = PTHREAD_MUTEX_INITIALIZER;
static struct xmlrpccmd_evtmon_session *xmlrpccmd_evtmon_sessions[XMLRPCCMD_EVTMON_MAX_SESSION] = { 0 };

#define XMLRPCCMD_EVTMON_NUM 5
static struct xmlrpcsrv_command xmlrpccmd_evtmon_commands[XMLRPCCMD_EVTMON_NUM] = {

	{
		.name = "evtmon.start",
		.callback_func = xmlrpccmd_evtmon_start,
		.signature = "i:i",
		.help = "Start a monitoring session",
	},

	{
		.name = "evtmon.add",
		.callback_func = xmlrpccmd_evtmon_add,
		.signature = "i:s",
		.help = "Add an event to a monitoring session",
	},

	{
		.name = "evtmon.remove",
		.callback_func = xmlrpccmd_evtmon_remove,
		.signature = "i:s",
		.help = "Remove an event from a monitoring session",
	},

	{
		.name = "evtmon.poll",
		.callback_func = xmlrpccmd_evtmon_poll,
		.signature = "A:s",
		.help = "Poll the monitoring session",
	},

	{
		.name = "evtmon.stop",
		.callback_func = xmlrpccmd_evtmon_stop,
		.signature = "i:i",
		.help = "Stop a monitoring session",
	},

};

int xmlrpccmd_evtmon_register_all() {

	int i;

	for (i = 0; i < XMLRPCCMD_EVTMON_NUM; i++) {
		if (xmlrpcsrv_register_command(&xmlrpccmd_evtmon_commands[i]) == POM_ERR)
			return POM_ERR;
	}
	return POM_OK;
}

int xmlrpccmd_evtmon_process_end(struct event *evt, void *obj) {

	struct xmlrpccmd_evtmon_session *sess = obj;

	struct xmlrpccmd_evtmon_list *lst = malloc(sizeof(struct xmlrpccmd_evtmon_list));
	if (!lst) {
		pom_oom(sizeof(struct xmlrpccmd_evtmon_list));
		return POM_ERR;
	}
	memset(lst, 0, sizeof(struct xmlrpccmd_evtmon_list));
	
	event_refcount_inc(evt);
	lst->evt = evt;

	pom_mutex_lock(&sess->lock);

	lst->next = sess->events;
	if (lst->next)
		lst->next->prev = lst;
	sess->events = lst;

	if (pthread_cond_broadcast(&sess->cond)) {
		pomlog("Error while signaling the session condition : %s", pom_strerror(errno));
		abort();
	}

	pom_mutex_unlock(&sess->lock);

	return POM_OK;

}

int xmlrpccmd_evtmon_timeout(void *priv) {
	struct xmlrpccmd_evtmon_session *sess = priv;

	pomlog(POMLOG_INFO "Monitoring session %u timed out", sess->id);

	pom_mutex_lock(&xmlrpccmd_evtmon_session_lock);
	xmlrpccmd_evtmon_sessions[sess->id] = NULL;
	pom_mutex_unlock(&xmlrpccmd_evtmon_session_lock);

	xmlrpccmd_evtmon_session_cleanup(sess);

	return POM_OK;
}

int xmlrpccmd_evtmon_session_cleanup(struct xmlrpccmd_evtmon_session *sess) {
	
	while (sess->events_reg) {
		struct xmlrpccmd_evtmon_reg_list *lst = sess->events_reg;
		sess->events_reg = lst->next;
		event_listener_unregister(lst->evt, sess);
		free(lst);
	}

	while (sess->events) {
		struct xmlrpccmd_evtmon_list *lst = sess->events;
		sess->events = lst->next;
		event_refcount_dec(lst->evt);
		free(lst);
	}

	main_timer_cleanup(sess->timer);
	pthread_mutex_destroy(&sess->lock);
	pthread_cond_destroy(&sess->cond);
	free(sess);

	return POM_OK;
}

int xmlrpccmd_evtmon_cleanup() {

	pom_mutex_lock(&xmlrpccmd_evtmon_session_lock);

	int i;
	for (i = 0; i < XMLRPCCMD_EVTMON_MAX_SESSION; i++) {
		if (!xmlrpccmd_evtmon_sessions[i])
			continue;

		struct xmlrpccmd_evtmon_session *sess = xmlrpccmd_evtmon_sessions[i];
		xmlrpccmd_evtmon_sessions[i] = NULL;

		pom_mutex_lock(&sess->lock);
		pthread_cond_broadcast(&sess->cond);
		pom_mutex_unlock(&sess->lock);

		xmlrpccmd_evtmon_session_cleanup(sess);

	}

	pom_mutex_unlock(&xmlrpccmd_evtmon_session_lock);

	return POM_OK;
}

xmlrpc_value *xmlrpccmd_evtmon_start(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	xmlrpc_int timeout = -1;

	xmlrpc_decompose_value(envP, paramArrayP, "(i)", &timeout);
	if (envP->fault_occurred || timeout < 0) {
		return NULL;
	}

	struct xmlrpccmd_evtmon_session *sess = malloc(sizeof(struct xmlrpccmd_evtmon_session));
	if (!sess) {
		xmlrpc_faultf(envP, "Not enough memory");
		return NULL;
	}
	memset(sess, 0, sizeof(struct xmlrpccmd_evtmon_session));

	sess->timer = main_timer_alloc(sess, xmlrpccmd_evtmon_timeout);
	sess->timeout = timeout;

	if (!sess->timer) {
		xmlrpc_faultf(envP, "Error while allocating the timer");
		free(sess);
		return NULL;
	}

	if (pthread_mutex_init(&sess->lock, NULL)) {
		main_timer_cleanup(sess->timer);
		free(sess);
		xmlrpc_faultf(envP, "Error while initializing session lock : %s", pom_strerror(errno));
		return NULL;
	}

	if (pthread_cond_init(&sess->cond, NULL)) {
		main_timer_cleanup(sess->timer);
		pthread_mutex_destroy(&sess->lock);
		free(sess);
		xmlrpc_faultf(envP, "Error while initializing session condition : %s", pom_strerror(errno));
		return NULL;
	}

	pom_mutex_lock(&xmlrpccmd_evtmon_session_lock);
	// Find a free session
	
	int i;
	for (i = 0; i < XMLRPCCMD_EVTMON_MAX_SESSION && xmlrpccmd_evtmon_sessions[i]; i++);

	if (i >= XMLRPCCMD_EVTMON_MAX_SESSION) {
		xmlrpc_faultf(envP, "No monitoring session available");
		main_timer_cleanup(sess->timer);
		pthread_mutex_destroy(&sess->lock);
		pthread_cond_destroy(&sess->cond);
		free(sess);
		pom_mutex_unlock(&xmlrpccmd_evtmon_session_lock);
		return NULL;
	}
	xmlrpccmd_evtmon_sessions[i] = sess;
	sess->id = i;

	pom_mutex_unlock(&xmlrpccmd_evtmon_session_lock);

	main_timer_queue(sess->timer, sess->timeout);

	pomlog(POMLOG_INFO "New event monitoring session started with id %u and timeout %u sec", i, timeout);

	return xmlrpc_int_new(envP, i);
}

xmlrpc_value *xmlrpccmd_evtmon_add(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {


	xmlrpc_int id = -1;
	char *evt_name = NULL;

	xmlrpc_decompose_value(envP, paramArrayP, "(is)", &id, &evt_name);
	if (envP->fault_occurred || id < 0) {
		free(evt_name);
		return NULL;
	}

	struct event_reg *evt = event_find(evt_name);
	if (!evt) {
		xmlrpc_faultf(envP, "Event %s does not exists", evt_name);
		free(evt_name);
		return NULL;
	}
	pomlog(POMLOG_DEBUG "Adding event %s to session %u", evt_name, id);
	free(evt_name);

	struct xmlrpccmd_evtmon_reg_list *lst = malloc(sizeof(struct xmlrpccmd_evtmon_reg_list));
	if (!lst) {
		pom_oom(sizeof(struct xmlrpccmd_evtmon_reg_list));
		xmlrpc_faultf(envP, "Not enough memory");
		return NULL;
	}
	memset(lst, 0, sizeof(struct xmlrpccmd_evtmon_reg_list));

	lst->evt = evt;


	// Find the right session and lock it

	pom_mutex_lock(&xmlrpccmd_evtmon_session_lock);
	struct xmlrpccmd_evtmon_session *sess = xmlrpccmd_evtmon_sessions[id];
	if (!sess) {
		pom_mutex_unlock(&xmlrpccmd_evtmon_session_lock);
		xmlrpc_faultf(envP, "Session %u not found", id);
		return NULL;
	}
	
	pom_mutex_lock(&sess->lock);
	pom_mutex_unlock(&xmlrpccmd_evtmon_session_lock);

	
	if (event_listener_register(evt, sess, NULL, xmlrpccmd_evtmon_process_end) != POM_OK) {
		pom_mutex_unlock(&sess->lock);
		free(lst);
		xmlrpc_faultf(envP, "Error while listening to the event.");
		return NULL;

	}

	lst->next = sess->events_reg;
	if (lst->next)
		lst->next->prev = lst;
	sess->events_reg = lst;
	pom_mutex_unlock(&sess->lock);


	return xmlrpc_int_new(envP, 0);
}

xmlrpc_value *xmlrpccmd_evtmon_remove(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {


	xmlrpc_int id = -1;
	char *evt_name = NULL;

	xmlrpc_decompose_value(envP, paramArrayP, "(is)", &id, &evt_name);
	if (envP->fault_occurred || id < 0) {
		free(evt_name);
		return NULL;
	}

	struct event_reg *evt = event_find(evt_name);
	if (!evt) {
		xmlrpc_faultf(envP, "Event %s does not exists", evt_name);
		free(evt_name);
		return NULL;
	}
	pomlog(POMLOG_DEBUG "Removing event %s from session %u", evt_name, id);
	free(evt_name);

	// Find the right session and lock it

	pom_mutex_lock(&xmlrpccmd_evtmon_session_lock);
	struct xmlrpccmd_evtmon_session *sess = xmlrpccmd_evtmon_sessions[id];
	if (!sess) {
		pom_mutex_unlock(&xmlrpccmd_evtmon_session_lock);
		xmlrpc_faultf(envP, "Session %u not found", id);
		return NULL;
	}
	
	pom_mutex_lock(&sess->lock);
	pom_mutex_unlock(&xmlrpccmd_evtmon_session_lock);

	struct xmlrpccmd_evtmon_reg_list *lst;
	for (lst = sess->events_reg; lst && lst->evt != evt; lst = lst->next);

	if (!lst) {
		pom_mutex_unlock(&sess->lock);
		xmlrpc_faultf(envP, "The event wasn't monitored by session %u", id);
		return NULL;
	}
	
	if (event_listener_unregister(evt, sess) != POM_OK) {
		pom_mutex_unlock(&sess->lock);
		free(lst);
		xmlrpc_faultf(envP, "Error while stopping to listen to the event.");
		return NULL;

	}

	if (lst->next) {
		lst->next->prev = lst->prev;
	} 
	if (lst->prev) {
		lst->prev->next = lst->next;
	} else {
		sess->events_reg = lst->next;
	}
	pom_mutex_unlock(&sess->lock);
	return xmlrpc_int_new(envP, 0);
}

xmlrpc_value *xmlrpccmd_evtmon_poll(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {


	xmlrpc_int id = -1;

	xmlrpc_decompose_value(envP, paramArrayP, "(i)", &id);
	if (envP->fault_occurred || id < 0) {
		return NULL;
	}

	pom_mutex_lock(&xmlrpccmd_evtmon_session_lock);
	struct xmlrpccmd_evtmon_session *sess = xmlrpccmd_evtmon_sessions[id];
	if (!sess) {
		pom_mutex_unlock(&xmlrpccmd_evtmon_session_lock);
		xmlrpc_faultf(envP, "Session %u not found", id);
		return NULL;
	}
	
	pom_mutex_lock(&sess->lock);
	pom_mutex_unlock(&xmlrpccmd_evtmon_session_lock);

	main_timer_dequeue(sess->timer);

	while (!sess->events) {
		// There is no event to return, wait for some
		
		int id = sess->id;
		struct timeval now;
		gettimeofday(&now, NULL);
		struct timespec then = { 0 };
		then.tv_sec = now.tv_sec + XMLRPCCMD_EVTMON_POLL_TIMEOUT;

		int res = pthread_cond_timedwait(&sess->cond, &sess->lock, &then);
		
		if (res == ETIMEDOUT) {
			pom_mutex_unlock(&sess->lock);
			main_timer_queue(sess->timer, sess->timeout);
			return xmlrpc_build_value(envP, "{}");
		} else if (res) {
			pomlog(POMLOG_ERR "Error while waiting for session condition : %s", pom_strerror(errno));
			abort();
		}

		// Check that the session still exists
		// No need to lock since it only occurs when we cleanup
		if (!xmlrpccmd_evtmon_sessions[id]) {
			pom_mutex_unlock(&sess->lock);
			return xmlrpc_build_value(envP, "{}");
		}
	}

	struct xmlrpccmd_evtmon_list *lst = sess->events;
	sess->events = NULL;
	pom_mutex_unlock(&sess->lock);


	xmlrpc_value *res = xmlrpc_array_new(envP);

	while (lst) {
		struct event *evt = lst->evt;
		struct xmlrpccmd_evtmon_list *tmp = lst;
		lst = lst->next;
		free(tmp);


		struct event_reg *evt_reg = event_get_reg(evt);
		struct event_reg_info *evt_reg_info = event_reg_get_info(evt_reg);

		struct data_reg *dreg = evt_reg_info->data_reg;
		struct data *evt_data = event_get_data(evt);

		xmlrpc_value *data = xmlrpc_struct_new(envP);

		int i;
		for (i = 0; i < dreg->data_count; i++) {
			
			struct data_item_reg *direg = &dreg->items[i];

			if (!data_is_set(evt_data[i]) && !(direg->flags & DATA_REG_FLAG_LIST))
				continue;
	
			xmlrpc_value *value = NULL;
			if (direg->flags & DATA_REG_FLAG_LIST) {
				
				value = xmlrpc_array_new(envP);

				struct data_item *itm = evt_data[i].items;
				while (itm) {
					xmlrpc_value *itm_val = xmlrpccmd_ptype_to_val(envP, itm->value);
					xmlrpc_value *itm_entry = xmlrpc_build_value(envP, "{s:s,s:V}", "key", itm->key, "value", itm_val);
					xmlrpc_DECREF(itm_val);
					xmlrpc_array_append_item(envP, value, itm_entry);
					xmlrpc_DECREF(itm_entry);
				}


			} else {
				value = xmlrpccmd_ptype_to_val(envP, evt_data[i].value);
			}
			
			xmlrpc_struct_set_value(envP, data, direg->name, value);
			xmlrpc_DECREF(value);
		
		}


		ptime evt_timestamp = event_get_timestamp(evt);
		xmlrpc_value *timestamp = xmlrpc_build_value(envP, "{s:i,s:i}", "sec", pom_ptime_sec(evt_timestamp), "usec", pom_ptime_usec(evt_timestamp));

		xmlrpc_value *item = xmlrpc_build_value(envP, "{s:s,s:S,s:S}",
						"event", evt_reg_info->name,
						"timestamp", timestamp,
						"data", data);
		xmlrpc_DECREF(timestamp);
		xmlrpc_DECREF(data);
		event_refcount_dec(evt);
		xmlrpc_array_append_item(envP, res, item);
		xmlrpc_DECREF(item);
	}

	main_timer_queue(sess->timer, sess->timeout);

	return res;
}

xmlrpc_value *xmlrpccmd_evtmon_stop(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	xmlrpc_int id = -1;

	xmlrpc_decompose_value(envP, paramArrayP, "(i)", &id);
	if (envP->fault_occurred || id < 0) {
		return NULL;
	}

	pomlog(POMLOG_INFO "Monitoring session %u stopped", id);

	pom_mutex_lock(&xmlrpccmd_evtmon_session_lock);
	struct xmlrpccmd_evtmon_session *sess = xmlrpccmd_evtmon_sessions[id];
	if (!sess) {
		pom_mutex_unlock(&xmlrpccmd_evtmon_session_lock);
		xmlrpc_faultf(envP, "Session %u not found", id);
		return NULL;
	}


	xmlrpccmd_evtmon_sessions[id] = NULL;

	pom_mutex_lock(&sess->lock);

	pom_mutex_unlock(&xmlrpccmd_evtmon_session_lock);
	
	if (pthread_cond_broadcast(&sess->cond)) {
		pomlog("Error while signaling the session condition : %s", pom_strerror(errno));
		abort();
	}

	pom_mutex_unlock(&sess->lock);
	xmlrpccmd_evtmon_session_cleanup(sess);
	
	return xmlrpc_int_new(envP, 0);
}
