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

#include "common.h"
#include "xmlrpcsrv.h"
#include <pom-ng/event.h>

#include "xmlrpccmd.h"
#include "xmlrpccmd_monitor.h"

static pthread_mutex_t xmlrpccmd_monitor_session_lock = PTHREAD_MUTEX_INITIALIZER;
static struct xmlrpccmd_monitor_session *xmlrpccmd_monitor_sessions[XMLRPCCMD_MONITOR_MAX_SESSION] = { 0 };

#define XMLRPCCMD_MONITOR_NUM 5
static struct xmlrpcsrv_command xmlrpccmd_monitor_commands[XMLRPCCMD_MONITOR_NUM] = {

	{
		.name = "monitor.start",
		.callback_func = xmlrpccmd_monitor_start,
		.signature = "i:i",
		.help = "Start a monitoring session",
	},

	{
		.name = "monitor.eventAddListener",
		.callback_func = xmlrpccmd_monitor_event_add_listener,
		.signature = "I:iss",
		.help = "Add an event listener to a monitoring session",
	},

	{
		.name = "monitor.eventRemoveListener",
		.callback_func = xmlrpccmd_monitor_event_remove_listener,
		.signature = "i:iI",
		.help = "Remove an event listener from a monitoring session",
	},

	{
		.name = "monitor.poll",
		.callback_func = xmlrpccmd_monitor_poll,
		.signature = "A:s",
		.help = "Poll the monitoring session",
	},

	{
		.name = "monitor.stop",
		.callback_func = xmlrpccmd_monitor_stop,
		.signature = "i:i",
		.help = "Stop a monitoring session",
	},

};

int xmlrpccmd_monitor_register_all() {

	int i;

	for (i = 0; i < XMLRPCCMD_MONITOR_NUM; i++) {
		if (xmlrpcsrv_register_command(&xmlrpccmd_monitor_commands[i]) == POM_ERR)
			return POM_ERR;
	}
	return POM_OK;
}

int xmlrpccmd_monitor_process_end(struct event *evt, void *obj) {

	struct xmlrpccmd_monitor_evtreg *evtreg = obj;
	struct xmlrpccmd_monitor_session *sess = evtreg->sess;

	struct xmlrpccmd_monitor_event *lst = malloc(sizeof(struct xmlrpccmd_monitor_event));
	if (!lst) {
		pom_oom(sizeof(struct xmlrpccmd_monitor_event));
		return POM_ERR;
	}
	memset(lst, 0, sizeof(struct xmlrpccmd_monitor_event));
	
	event_refcount_inc(evt);
	lst->evt = evt;
	lst->event_reg = evtreg;

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

int xmlrpccmd_monitor_timeout(void *priv) {
	struct xmlrpccmd_monitor_session *sess = priv;

	pomlog(POMLOG_INFO "Monitoring session %u timed out", sess->id);


	xmlrpccmd_monitor_session_cleanup(sess);

	return POM_OK;
}

int xmlrpccmd_monitor_session_cleanup(struct xmlrpccmd_monitor_session *sess) {
	
	pom_mutex_lock(&xmlrpccmd_monitor_session_lock);

	if (!xmlrpccmd_monitor_sessions[sess->id]) {
		pom_mutex_unlock(&xmlrpccmd_monitor_session_lock);
		return POM_OK;
	}

	xmlrpccmd_monitor_sessions[sess->id] = NULL;
	pom_mutex_lock(&sess->lock);
	pom_mutex_unlock(&xmlrpccmd_monitor_session_lock);

	while (sess->polling) {
		pthread_cond_broadcast(&sess->cond);
		pom_mutex_unlock(&sess->lock);
		sched_yield();

		pom_mutex_lock(&sess->lock);
	}

	while (sess->events_reg) {

		struct xmlrpccmd_monitor_evtreg *evtreg = sess->events_reg;
		sess->events_reg = evtreg->next;
		event_listener_unregister(evtreg->evt_reg, evtreg);
		free(evtreg);
	}

	while (sess->events) {
		struct xmlrpccmd_monitor_event *evt = sess->events;
		sess->events = evt->next;
		event_refcount_dec(evt->evt);
		free(evt);
	}


	pom_mutex_unlock(&sess->lock);
	main_timer_cleanup(sess->timer);
	pthread_cond_destroy(&sess->cond);
	pthread_mutex_destroy(&sess->lock);
	free(sess);

	return POM_OK;
}

int xmlrpccmd_monitor_cleanup() {


	int i;
	for (i = 0; i < XMLRPCCMD_MONITOR_MAX_SESSION; i++) {
		pom_mutex_lock(&xmlrpccmd_monitor_session_lock);		
		if (!xmlrpccmd_monitor_sessions[i]) {
			pom_mutex_unlock(&xmlrpccmd_monitor_session_lock);
			continue;
		}
		struct xmlrpccmd_monitor_session *sess = xmlrpccmd_monitor_sessions[i];
		pom_mutex_unlock(&xmlrpccmd_monitor_session_lock);

		xmlrpccmd_monitor_session_cleanup(sess);


	}


	return POM_OK;
}

xmlrpc_value *xmlrpccmd_monitor_start(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	xmlrpc_int timeout = -1;

	xmlrpc_decompose_value(envP, paramArrayP, "(i)", &timeout);
	if (envP->fault_occurred || timeout < 0) {
		return NULL;
	}

	struct xmlrpccmd_monitor_session *sess = malloc(sizeof(struct xmlrpccmd_monitor_session));
	if (!sess) {
		xmlrpc_faultf(envP, "Not enough memory");
		return NULL;
	}
	memset(sess, 0, sizeof(struct xmlrpccmd_monitor_session));

	sess->timer = main_timer_alloc(sess, xmlrpccmd_monitor_timeout);
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

	pom_mutex_lock(&xmlrpccmd_monitor_session_lock);
	// Find a free session
	
	int i;
	for (i = 0; i < XMLRPCCMD_MONITOR_MAX_SESSION && xmlrpccmd_monitor_sessions[i]; i++);

	if (i >= XMLRPCCMD_MONITOR_MAX_SESSION) {
		xmlrpc_faultf(envP, "No monitoring session available");
		main_timer_cleanup(sess->timer);
		pthread_mutex_destroy(&sess->lock);
		pthread_cond_destroy(&sess->cond);
		free(sess);
		pom_mutex_unlock(&xmlrpccmd_monitor_session_lock);
		return NULL;
	}
	xmlrpccmd_monitor_sessions[i] = sess;
	sess->id = i;

	pom_mutex_unlock(&xmlrpccmd_monitor_session_lock);

	main_timer_queue(sess->timer, sess->timeout);

	pomlog(POMLOG_INFO "New event monitoring session started with id %u and timeout %u sec", i, timeout);

	return xmlrpc_int_new(envP, i);
}

xmlrpc_value *xmlrpccmd_monitor_event_add_listener(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {


	xmlrpc_int id = -1;
	char *evt_name = NULL;
	char *filter = NULL;

	xmlrpc_decompose_value(envP, paramArrayP, "(iss)", &id, &evt_name, &filter);
	if (envP->fault_occurred)
		return NULL;

	if (id < 0 || id >= XMLRPCCMD_MONITOR_MAX_SESSION) {
		free(evt_name);
		xmlrpc_faultf(envP, "Invalid session id");
		return NULL;
	}

	struct event_reg *evt = event_find(evt_name);
	if (!evt) {
		xmlrpc_faultf(envP, "Event %s does not exists", evt_name);
		free(evt_name);
		return NULL;
	}

	struct xmlrpccmd_monitor_evt_listener *l = malloc(sizeof(struct xmlrpccmd_monitor_evt_listener));
	if (!l) {
		pom_oom(sizeof(struct xmlrpccmd_monitor_evt_listener));
		xmlrpc_faultf(envP, "Not enough memory");
		return NULL;
	}
	memset(l, 0, sizeof(struct xmlrpccmd_monitor_evt_listener));

	pomlog(POMLOG_DEBUG "Adding event %s to session %u", evt_name, id);
	free(evt_name);

	// Find the right session and lock it

	pom_mutex_lock(&xmlrpccmd_monitor_session_lock);
	struct xmlrpccmd_monitor_session *sess = xmlrpccmd_monitor_sessions[id];
	if (!sess) {
		pom_mutex_unlock(&xmlrpccmd_monitor_session_lock);
		xmlrpc_faultf(envP, "Session %u not found", id);
		return NULL;
	}
	
	pom_mutex_lock(&sess->lock);
	pom_mutex_unlock(&xmlrpccmd_monitor_session_lock);


	// Check if we already monitor this event

	struct xmlrpccmd_monitor_evtreg *lst;
	
	for (lst = sess->events_reg; lst && lst->evt_reg != evt; lst = lst->next);
	
	if (!lst) {

		// In case we are not listening to this event yet, do it
		lst = malloc(sizeof(struct xmlrpccmd_monitor_evtreg));
		if (!lst) {
			pom_mutex_unlock(&sess->lock);
			free(l);
			pom_oom(sizeof(struct xmlrpccmd_monitor_evtreg));
			xmlrpc_faultf(envP, "Not enough memory");
			return NULL;
		}
		memset(lst, 0, sizeof(struct xmlrpccmd_monitor_evtreg));

		lst->evt_reg = evt;
		lst->sess = sess;

		
		if (event_listener_register(evt, lst, NULL, xmlrpccmd_monitor_process_end) != POM_OK) {
			pom_mutex_unlock(&sess->lock);
			free(l);
			free(lst);
			xmlrpc_faultf(envP, "Error while listening to the event.");
			return NULL;

		}

		lst->next = sess->events_reg;
		if (lst->next)
			lst->next->prev = lst;
		sess->events_reg = lst;
	}


	l->id = (uint64_t) l;
	l->next = lst->listeners;
	if (l->next)
		l->next->prev = l;
	lst->listeners = l;


	pom_mutex_unlock(&sess->lock);

	return xmlrpc_i8_new(envP, l->id);
}

xmlrpc_value *xmlrpccmd_monitor_event_remove_listener(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {


	xmlrpc_int sess_id = -1;
	uint64_t listener_id = -1;

	xmlrpc_decompose_value(envP, paramArrayP, "(iI)", &sess_id, &listener_id);
	if (envP->fault_occurred)
		return NULL;

	if (sess_id < 0 || sess_id >= XMLRPCCMD_MONITOR_MAX_SESSION) {
		xmlrpc_faultf(envP, "Invalid session id");
		return NULL;
	}

	// Find the right session and lock it

	pom_mutex_lock(&xmlrpccmd_monitor_session_lock);
	struct xmlrpccmd_monitor_session *sess = xmlrpccmd_monitor_sessions[sess_id];
	if (!sess) {
		pom_mutex_unlock(&xmlrpccmd_monitor_session_lock);
		xmlrpc_faultf(envP, "Session %u not found", sess_id);
		return NULL;
	}
	
	pom_mutex_lock(&sess->lock);
	pom_mutex_unlock(&xmlrpccmd_monitor_session_lock);

	// This is an expensive search but I don't think there is a point to optimise
	struct xmlrpccmd_monitor_evtreg *evt_lst;
	struct xmlrpccmd_monitor_evt_listener *listener_lst = NULL;
	for (evt_lst = sess->events_reg; evt_lst && !listener_lst; evt_lst = evt_lst->next) {
		for (listener_lst = evt_lst->listeners; listener_lst && listener_lst->id != listener_id; listener_lst = listener_lst->next);
		if (listener_lst)
			break;
	}

	if (!listener_lst) {
		pom_mutex_unlock(&sess->lock);
		xmlrpc_faultf(envP, "Listener %"PRIu64" wasn't found in session %u", listener_id, sess_id);
		return NULL;
	}

	// Dequeue the listener
	if (listener_lst->next)
		listener_lst->next->prev = listener_lst->prev;
		
	if (listener_lst->prev)
		listener_lst->prev->next = listener_lst->next;
	else
		evt_lst->listeners = listener_lst->next;

	free(listener_lst);

	if (!evt_lst->listeners) {
		// No need to listener to the event anymore

		if (event_listener_unregister(evt_lst->evt_reg, evt_lst) != POM_OK) {
			pom_mutex_unlock(&sess->lock);
			xmlrpc_faultf(envP, "Error while stopping to listen to the event.");
			return NULL;

		}

		// Remove any pending event pointing to this evt_reg

		struct xmlrpccmd_monitor_event *evt = sess->events;
		while (evt) {
			struct xmlrpccmd_monitor_event *tmp = evt;
			evt = evt->next;

			if (tmp->event_reg == evt_lst) {
				if (tmp->next)
					tmp->next->prev = tmp->prev;

				if (tmp->prev)
					tmp->prev->next = tmp->next;
				else
					sess->events = tmp->next;

				event_refcount_dec(tmp->evt);
				free(tmp);
			}
		}

		if (evt_lst->next)
			evt_lst->next->prev = evt_lst->prev;

		if (evt_lst->prev)
			evt_lst->prev->next = evt_lst->next;
		else
			sess->events_reg = evt_lst->next;

		free(evt_lst);
	}

	pom_mutex_unlock(&sess->lock);
	return xmlrpc_int_new(envP, 0);
}

xmlrpc_value *xmlrpccmd_monitor_poll(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {


	xmlrpc_int id = -1;

	xmlrpc_decompose_value(envP, paramArrayP, "(i)", &id);
	if (envP->fault_occurred)
		return NULL;
	
	if (id < 0 || id >= XMLRPCCMD_MONITOR_MAX_SESSION) {
		xmlrpc_faultf(envP, "Invalid session id");
		return NULL;
	}

	pom_mutex_lock(&xmlrpccmd_monitor_session_lock);
	struct xmlrpccmd_monitor_session *sess = xmlrpccmd_monitor_sessions[id];
	if (!sess) {
		pom_mutex_unlock(&xmlrpccmd_monitor_session_lock);
		xmlrpc_faultf(envP, "Session %u not found", id);
		return NULL;
	}
	pom_mutex_lock(&sess->lock);
	pom_mutex_unlock(&xmlrpccmd_monitor_session_lock);
	

	main_timer_dequeue(sess->timer);

	struct xmlrpccmd_monitor_event *lst = NULL;

	while (xmlrpccmd_monitor_sessions[id]) {


		// There is no event to return, wait for some
		
		struct timeval now;
		gettimeofday(&now, NULL);
		struct timespec then = { 0 };
		then.tv_sec = now.tv_sec + XMLRPCCMD_MONITOR_POLL_TIMEOUT;

		sess->polling++;
		int res = pthread_cond_timedwait(&sess->cond, &sess->lock, &then);
		sess->polling--;

		if (res == ETIMEDOUT) {
			pom_mutex_unlock(&sess->lock);
			main_timer_queue(sess->timer, sess->timeout);
			return xmlrpc_build_value(envP, "{}");
		} else if (res) {
			pomlog(POMLOG_ERR "Error while waiting for session condition : %s", pom_strerror(errno));
			abort();
		}


		if (sess->events) {
			lst = sess->events;
			sess->events = NULL;
			break;
		}
	}
	pom_mutex_unlock(&sess->lock);
	
	// Check that the session still exists
	if (!xmlrpccmd_monitor_sessions[id]) {
		return xmlrpc_build_value(envP, "{}");
	}

	pom_mutex_unlock(&xmlrpccmd_monitor_session_lock);

	xmlrpc_value *res = xmlrpc_array_new(envP);

	while (lst) {
		struct event *evt = lst->evt;
		struct xmlrpccmd_monitor_evt_listener *listeners = lst->event_reg->listeners;
		struct xmlrpccmd_monitor_event *tmp = lst;
		lst = lst->next;
		free(tmp);

		xmlrpc_value *listener_lst = NULL;
		for (; listeners; listeners = listeners->next) {
			
			if (listeners->filter) {
				// TODO
				continue;
			}
			
			if (!listener_lst)
				listener_lst = xmlrpc_array_new(envP);
		
			xmlrpc_value *id = xmlrpc_i8_new(envP, listeners->id);
			xmlrpc_array_append_item(envP, listener_lst, id);
			xmlrpc_DECREF(id);

		}

		// No listener matched this even
		if (!listener_lst)
			continue;


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

		xmlrpc_value *item = xmlrpc_build_value(envP, "{s:s,s:A,s:S,s:S}",
						"event", evt_reg_info->name,
						"listeners", listener_lst,
						"timestamp", timestamp,
						"data", data);
		xmlrpc_DECREF(listener_lst);
		xmlrpc_DECREF(timestamp);
		xmlrpc_DECREF(data);
		event_refcount_dec(evt);
		xmlrpc_array_append_item(envP, res, item);
		xmlrpc_DECREF(item);
	}

	main_timer_queue(sess->timer, sess->timeout);

	return res;
}

xmlrpc_value *xmlrpccmd_monitor_stop(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	xmlrpc_int id = -1;

	xmlrpc_decompose_value(envP, paramArrayP, "(i)", &id);
	if (envP->fault_occurred)
		return NULL;

	if (id < 0 || id >= XMLRPCCMD_MONITOR_MAX_SESSION) {
		xmlrpc_faultf(envP, "Invalid session id");
		return NULL;
	}


	pom_mutex_lock(&xmlrpccmd_monitor_session_lock);
	struct xmlrpccmd_monitor_session *sess = xmlrpccmd_monitor_sessions[id];
	if (!sess) {
		pom_mutex_unlock(&xmlrpccmd_monitor_session_lock);
		xmlrpc_faultf(envP, "Session %u not found", id);
		return NULL;
	}

	pomlog(POMLOG_INFO "Monitoring session %u stopped", id);

	pom_mutex_unlock(&xmlrpccmd_monitor_session_lock);
	
	xmlrpccmd_monitor_session_cleanup(sess);
	
	return xmlrpc_int_new(envP, 0);
}
