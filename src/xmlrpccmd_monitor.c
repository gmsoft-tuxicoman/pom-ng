/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2013-2015 Guy Martin <gmsoft@tuxicoman.be>
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
#include "filter.h"
#include "httpd.h"

#include "xmlrpccmd.h"
#include "xmlrpccmd_monitor.h"

static pthread_mutex_t xmlrpccmd_monitor_session_lock = PTHREAD_MUTEX_INITIALIZER;
static struct xmlrpccmd_monitor_session *xmlrpccmd_monitor_sessions[XMLRPCCMD_MONITOR_MAX_SESSION] = { 0 };


static int xmlrpccmd_monitor_pload_listeners_count = 0;

#define XMLRPCCMD_MONITOR_NUM 9
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
		.signature = "I:issbb",
		.help = "Add an event listener to a monitoring session",
	},

	{
		.name = "monitor.eventRemoveListener",
		.callback_func = xmlrpccmd_monitor_event_remove_listener,
		.signature = "i:iI",
		.help = "Remove an event listener from a monitoring session",
	},

	{
		.name = "monitor.ploadAddListener",
		.callback_func = xmlrpccmd_monitor_pload_add_listener,
		.signature = "I:is",
		.help = "Add a payload listener to a monitoring session",
	},

	{
		.name = "monitor.ploadRemoveListener",
		.callback_func = xmlrpccmd_monitor_pload_remove_listener,
		.signature = "i:iI",
		.help = "Remove a payload listener from a monitoring session",
	},

	{
		.name = "monitor.ploadEventsListen",
		.callback_func = xmlrpccmd_monitor_pload_events_listen,
		.signature = "i:ib",
		.help = "Start or stop listening to events generating payloads",
	},

	{
		.name = "monitor.ploadDiscard",
		.callback_func = xmlrpccmd_monitor_pload_discard,
		.signature = "i:iII",
		.help = "Discard a payload that has been received",
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

int xmlrpccmd_monitor_evt_process_begin (struct event *evt, void *obj, struct proto_process_stack *stack, unsigned int stack_index) {

	return xmlrpccmd_monitor_evt_process(evt, obj, XMLRPCCMD_MONITOR_EVT_LISTEN_END);
}

int xmlrpccmd_monitor_evt_process_end(struct event *evt, void *obj) {

	return xmlrpccmd_monitor_evt_process(evt, obj, XMLRPCCMD_MONITOR_EVT_LISTEN_END);
}

int xmlrpccmd_monitor_evt_process(struct event *evt, void *obj, unsigned int flags) {

	struct xmlrpccmd_monitor_evtreg *evtreg = obj;
	struct xmlrpccmd_monitor_session *sess = evtreg->sess;

	struct xmlrpccmd_monitor_event *lst = malloc(sizeof(struct xmlrpccmd_monitor_event));
	if (!lst) {
		pom_oom(sizeof(struct xmlrpccmd_monitor_event));
		return POM_ERR;
	}
	memset(lst, 0, sizeof(struct xmlrpccmd_monitor_event));
	
	lst->evt = evt;
	lst->event_reg = evtreg;
	evtreg->flags = flags;

	pom_mutex_lock(&sess->lock);


	struct xmlrpccmd_monitor_evt_listener *listeners;

	for (listeners = evtreg->listeners; listeners; listeners = listeners->next) {

		if (!(listeners->flags & flags))
			continue;
			
		if (listeners->filter && (filter_event_match(listeners->filter, evt) != FILTER_MATCH_YES))
			continue;

		lst->listeners_count++;
		uint64_t *new_lst = realloc(lst->listeners, sizeof(uint64_t) * lst->listeners_count);
		if (!new_lst) {
			pom_oom(sizeof(uint64_t) * lst->listeners_count);
			// Simply ignore this one
			continue;
		}
		lst->listeners = new_lst;
		new_lst[lst->listeners_count - 1] = listeners->id;
	}

	if (!lst->listeners_count) {
		// Nobody wants this event
		pom_mutex_unlock(&sess->lock);
		free(lst);
		return POM_OK;
	}

	
	event_refcount_inc(evt);

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

int xmlrpccmd_monitor_pload_open(void *obj, void **priv, struct pload *pload) {


	// Check if we need this payload
	pom_mutex_lock(&xmlrpccmd_monitor_session_lock);

	int i;
	for (i = 0; i < XMLRPCCMD_MONITOR_MAX_SESSION; i++) {

		struct xmlrpccmd_monitor_session *sess = xmlrpccmd_monitor_sessions[i];
		if (!sess)
			continue;

		pom_mutex_lock(&sess->lock);

		uint64_t pload_id = -1;

		struct xmlrpccmd_monitor_pload *lst = NULL;

		struct xmlrpccmd_monitor_pload_listener *tmp;

		for (tmp = sess->pload_listeners; tmp; tmp = tmp->next) {

			// Check of this listener wants this payload
			int matched = 0;
			if (!tmp->filter)
				matched = 1;
			else {
				int res = filter_pload_match(tmp->filter, pload);
				if (res == POM_ERR) {
					pomlog(POMLOG_ERR "Error while matching filter");
					continue;
				}

				if (res == FILTER_MATCH_YES)
					matched = 1;
			}

			if (!matched)
				continue;

			// Add the payload to httpd since we need it
			if (pload_id == -1) {
				pload_id = httpd_pload_add(pload);
				if (pload_id == -1) {
					pom_mutex_unlock(&xmlrpccmd_monitor_session_lock);
					pom_mutex_unlock(&sess->lock);
					return POM_ERR;
				}
			}

			// Create the list of matched listeners
			if (!lst) {
				lst = malloc(sizeof(struct xmlrpccmd_monitor_pload));
				if (!lst) {
					pom_oom(sizeof(struct xmlrpccmd_monitor_pload));
					break;
				}
				memset(lst, 0, sizeof(struct xmlrpccmd_monitor_pload));
				lst->pload_id = pload_id;
				lst->pload = pload;
				pload_refcount_inc(pload);
			}

			// Add this listener to the list
			lst->listeners_count++;
			uint64_t *new_lst = realloc(lst->listeners, sizeof(uint64_t) * lst->listeners_count);
			if (!new_lst) {
				pom_oom(sizeof(uint64_t) * lst->listeners_count);
				// Simply ignore this one
				continue;
			}
			lst->listeners = new_lst;
			new_lst[lst->listeners_count - 1] = tmp->id;

		}

		if (lst) {

			// Save this payload in the session with all it's listeners
			struct xmlrpccmd_monitor_httpd_pload *httpd_lst = malloc(sizeof(struct xmlrpccmd_monitor_httpd_pload));
			if (!httpd_lst) {
				pom_mutex_unlock(&sess->lock);
				pom_mutex_unlock(&xmlrpccmd_monitor_session_lock);
				pom_oom(sizeof(struct xmlrpccmd_monitor_httpd_pload));
				httpd_pload_remove(pload_id);
				free(lst->listeners);
				free(lst);
				return PLOAD_OPEN_ERR;
			}
			memset(httpd_lst, 0, sizeof(struct xmlrpccmd_monitor_httpd_pload));

			httpd_lst->listeners = lst->listeners;
			httpd_lst->listeners_count = lst->listeners_count;
			httpd_lst->pload_id = pload_id;
			
			HASH_ADD(hh, sess->httpd_ploads, pload_id, sizeof(httpd_lst->pload_id), httpd_lst);

			lst->next = sess->ploads;
			sess->ploads = lst;

			if (pthread_cond_broadcast(&sess->cond)) {
				pomlog("Error while signaling the session condition : %s", pom_strerror(errno));
				abort();
			}
		}

		pom_mutex_unlock(&sess->lock);

	}

	pom_mutex_unlock(&xmlrpccmd_monitor_session_lock);

	return PLOAD_OPEN_STOP;
}

int xmlrpccmd_monitor_pload_write(void *obj, void *priv, void *data, size_t len) {

	return POM_OK;
}

int xmlrpccmd_monitor_pload_close(void *obj, void *priv) {

	return POM_OK;
}

int xmlrpccmd_monitor_timeout(void *priv) {
	struct xmlrpccmd_monitor_session *sess = priv;

	pomlog(POMLOG_INFO "Monitoring session %u timed out", sess->id);


	xmlrpccmd_monitor_session_cleanup(sess);

	return POM_OK;
}

int xmlrpccmd_monitor_session_cleanup(struct xmlrpccmd_monitor_session *sess) {

	int sess_id = sess->id;

	pom_mutex_lock(&xmlrpccmd_monitor_session_lock);

	if (!xmlrpccmd_monitor_sessions[sess_id]) {
		pom_mutex_unlock(&xmlrpccmd_monitor_session_lock);
		return POM_OK;
	}

	xmlrpccmd_monitor_sessions[sess_id] = NULL;
	pom_mutex_lock(&sess->lock);
	pom_mutex_unlock(&xmlrpccmd_monitor_session_lock);

	// Mark that the session is being deleted
	sess->id = -1;

	while (sess->polling) {
		pthread_cond_broadcast(&sess->cond);
		pom_mutex_unlock(&sess->lock);
		sched_yield();
		pom_mutex_lock(&sess->lock);
	}
	pom_mutex_unlock(&sess->lock);

	while (sess->events_reg) {

		struct xmlrpccmd_monitor_evtreg *evtreg = sess->events_reg;
		sess->events_reg = evtreg->next;
		core_pause_processing();
		event_listener_unregister(evtreg->evt_reg, evtreg);
		core_resume_processing();


		while (evtreg->listeners) {
			struct xmlrpccmd_monitor_evt_listener *tmp = evtreg->listeners;
			evtreg->listeners = tmp->next;

			if (tmp->filter)
				filter_cleanup(tmp->filter);
			free(tmp);

		}

		free(evtreg);
	}

	while (sess->events) {
		struct xmlrpccmd_monitor_event *evt = sess->events;
		sess->events = evt->next;
		event_refcount_dec(evt->evt);

		if (evt->listeners)
			free(evt->listeners);

		free(evt);
	}


	// Remove the payload listeners
	while (sess->pload_listeners) {

		struct xmlrpccmd_monitor_pload_listener *tmp = sess->pload_listeners;
		sess->pload_listeners = tmp->next;

		filter_cleanup(tmp->filter);
		free(tmp);

		if (!__sync_sub_and_fetch(&xmlrpccmd_monitor_pload_listeners_count, 1)) {
			core_pause_processing();
			pload_listen_stop(xmlrpccmd_monitor_pload_open, NULL);
			core_resume_processing();
		}

	}

	while (sess->ploads) {
		struct xmlrpccmd_monitor_pload *pload = sess->ploads;
		sess->ploads = pload->next;
		// Don't free listeners here as the same list is used for the httpd_pload structure
		pload_refcount_dec(pload->pload);
		free(pload);

	}

	if (sess->pload_events_listening)
		event_payload_listen_stop();

	struct xmlrpccmd_monitor_httpd_pload *cur_pload, *tmp_pload;
	HASH_ITER(hh, sess->httpd_ploads, cur_pload, tmp_pload) {
		HASH_DEL(sess->httpd_ploads, cur_pload);
		
		httpd_pload_remove(cur_pload->pload_id);
		free(cur_pload->listeners);
		free(cur_pload);
	}

	timer_sys_cleanup(sess->timer);
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

	sess->timer = timer_sys_alloc(sess, xmlrpccmd_monitor_timeout);
	sess->timeout = timeout;

	if (!sess->timer) {
		xmlrpc_faultf(envP, "Error while allocating the timer");
		free(sess);
		return NULL;
	}

	if (pthread_mutex_init(&sess->lock, NULL)) {
		timer_sys_cleanup(sess->timer);
		free(sess);
		xmlrpc_faultf(envP, "Error while initializing session lock : %s", pom_strerror(errno));
		return NULL;
	}

	if (pthread_cond_init(&sess->cond, NULL)) {
		timer_sys_cleanup(sess->timer);
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
		timer_sys_cleanup(sess->timer);
		pthread_mutex_destroy(&sess->lock);
		pthread_cond_destroy(&sess->cond);
		free(sess);
		pom_mutex_unlock(&xmlrpccmd_monitor_session_lock);
		return NULL;
	}
	xmlrpccmd_monitor_sessions[i] = sess;
	sess->id = i;

	pom_mutex_unlock(&xmlrpccmd_monitor_session_lock);

	timer_sys_queue(sess->timer, sess->timeout);

	pomlog(POMLOG_INFO "New event monitoring session started with id %u and timeout %u sec", i, timeout);

	return xmlrpc_int_new(envP, i);
}

xmlrpc_value *xmlrpccmd_monitor_pload_add_listener(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {
	
	xmlrpc_int id = -1;
	char *filter_expr = NULL;

	xmlrpc_decompose_value(envP, paramArrayP, "(is)", &id, &filter_expr);

	if (envP->fault_occurred)
		return NULL;

	if (id < 0 || id >= XMLRPCCMD_MONITOR_MAX_SESSION) {
		free(filter_expr);
		xmlrpc_faultf(envP, "Invalid session id");
		return NULL;
	}

	struct filter_node *filter = NULL;

	// Attempt to parse the filter
	if (filter_pload(filter_expr, &filter) != POM_OK) {
		free(filter_expr);
		xmlrpc_faultf(envP, "Error while parsing the filter");
		return NULL;
	}

	free(filter_expr);

	struct xmlrpccmd_monitor_pload_listener *l = malloc(sizeof(struct xmlrpccmd_monitor_pload_listener));
	if (!l) {
		pom_oom(sizeof(struct xmlrpccmd_monitor_pload_listener));
		xmlrpc_faultf(envP, "Not enough memory");
		return NULL;
	}
	memset(l, 0, sizeof(struct xmlrpccmd_monitor_pload_listener));
	
	l->filter = filter;
	l->id = (uint64_t) l;

	// Make sure the session is valid

	pom_mutex_lock(&xmlrpccmd_monitor_session_lock);
	struct xmlrpccmd_monitor_session *sess = xmlrpccmd_monitor_sessions[id];
	if (!sess) {
		filter_cleanup(filter);
		free(l);
		pom_mutex_unlock(&xmlrpccmd_monitor_session_lock);
		xmlrpc_faultf(envP, "Session %u not found", id);
		return NULL;
	}
	pom_mutex_lock(&sess->lock);
	pom_mutex_unlock(&xmlrpccmd_monitor_session_lock);


	l->next = sess->pload_listeners;
	if (l->next)
		l->next->prev = l;

	sess->pload_listeners = l;
	pom_mutex_unlock(&sess->lock);

	// Start listening outside the lock to avoir locking issue
	if (!__sync_fetch_and_add(&xmlrpccmd_monitor_pload_listeners_count, 1)) {


		core_pause_processing();
		if (pload_listen_start(xmlrpccmd_monitor_pload_open, NULL, NULL, xmlrpccmd_monitor_pload_open, xmlrpccmd_monitor_pload_write, xmlrpccmd_monitor_pload_close) != POM_OK) {
			core_resume_processing();
			xmlrpc_faultf(envP, "Error while listening to payloads");
			return NULL;
		}
		core_resume_processing();
	}

	return xmlrpc_i8_new(envP, l->id);

}

xmlrpc_value *xmlrpccmd_monitor_pload_remove_listener(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	xmlrpc_int sess_id = -1;
	uint64_t listener_id = -1;

	xmlrpc_decompose_value(envP, paramArrayP, "(iI)", &sess_id, &listener_id);

	if (sess_id < 0 || sess_id >= XMLRPCCMD_MONITOR_MAX_SESSION) {
		xmlrpc_faultf(envP, "Invalid session id");
		return NULL;
	}

	if (envP->fault_occurred)
		return NULL;

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

	struct xmlrpccmd_monitor_pload_listener *tmp = sess->pload_listeners;
	for (tmp = sess->pload_listeners; tmp && tmp->id != listener_id; tmp = tmp->next);

	if (!tmp) {
		pom_mutex_unlock(&sess->lock);
		xmlrpc_faultf(envP, "Listner %"PRIu64" not found in session %u", listener_id, sess_id);
		return NULL;
	}

	if (tmp->next)
		tmp->next->prev = tmp->prev;

	if (tmp->prev)
		tmp->prev->next = tmp->next;
	else
		sess->pload_listeners = tmp->next;

	pom_mutex_unlock(&sess->lock);

	if (!__sync_sub_and_fetch(&xmlrpccmd_monitor_pload_listeners_count, 1)) {
		core_pause_processing();
		pload_listen_stop(xmlrpccmd_monitor_pload_open, NULL);
		core_resume_processing();
	}

	if (tmp->filter)
		filter_cleanup(tmp->filter);
	
	free(tmp);

	return xmlrpc_int_new(envP, 0);

}

xmlrpc_value *xmlrpccmd_monitor_event_add_listener(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {


	xmlrpc_int id = -1;
	char *evt_name = NULL;
	char *filter_expr = NULL;
	xmlrpc_bool begin = 0;
	xmlrpc_bool end = 0;

	xmlrpc_decompose_value(envP, paramArrayP, "(issbb)", &id, &evt_name, &filter_expr, &begin, &end);
	if (envP->fault_occurred)
		return NULL;

	if (id < 0 || id >= XMLRPCCMD_MONITOR_MAX_SESSION) {
		free(evt_name);
		free(filter_expr);
		xmlrpc_faultf(envP, "Invalid session id");
		return NULL;
	}

	if (!begin && !end) {
		free(evt_name);
		free(filter_expr);
		xmlrpc_faultf(envP, "Either begining and/or end of the event must be listened to.");
		return NULL;
	}

	struct event_reg *evt = event_find(evt_name);
	if (!evt) {
		xmlrpc_faultf(envP, "Event %s does not exists", evt_name);
		free(evt_name);
		free(filter_expr);
		return NULL;
	}

	struct filter_node *filter = NULL;
	// Attempt to parse the filter
	
	if (filter_event(filter_expr, evt, &filter) != POM_OK) {

		xmlrpc_faultf(envP, "Error while parsing the filter");
		free(evt_name);
		free(filter_expr);
		return NULL;
	}


	struct xmlrpccmd_monitor_evt_listener *l = malloc(sizeof(struct xmlrpccmd_monitor_evt_listener));
	if (!l) {
		free(evt_name);
		free(filter_expr);
		filter_cleanup(filter);
		pom_oom(sizeof(struct xmlrpccmd_monitor_evt_listener));
		xmlrpc_faultf(envP, "Not enough memory");
		return NULL;
	}
	memset(l, 0, sizeof(struct xmlrpccmd_monitor_evt_listener));

	pomlog(POMLOG_DEBUG "Adding event %s to session %u", evt_name, id);
	free(evt_name);
	free(filter_expr);

	l->filter = filter;
	l->flags = (begin ? XMLRPCCMD_MONITOR_EVT_LISTEN_BEGIN : 0) | (end ? XMLRPCCMD_MONITOR_EVT_LISTEN_END : 0);

	// Find the right session and lock it

	pom_mutex_lock(&xmlrpccmd_monitor_session_lock);
	struct xmlrpccmd_monitor_session *sess = xmlrpccmd_monitor_sessions[id];
	if (!sess) {
		filter_cleanup(filter);
		free(l);
		pom_mutex_unlock(&xmlrpccmd_monitor_session_lock);
		xmlrpc_faultf(envP, "Session %u not found", id);
		return NULL;
	}
	
	pom_mutex_lock(&sess->lock);
	pom_mutex_unlock(&xmlrpccmd_monitor_session_lock);

	// Check if we already monitor this event

	int (*process_begin) (struct event *evt, void *obj, struct proto_process_stack *stack, unsigned int stack_index) = NULL;
	struct xmlrpccmd_monitor_evtreg *lst;
	
	for (lst = sess->events_reg; lst && lst->evt_reg != evt; lst = lst->next);

	if (!lst) {

		// In case we are not listening to this event yet, do it
		lst = malloc(sizeof(struct xmlrpccmd_monitor_evtreg));
		if (!lst) {
			pom_mutex_unlock(&sess->lock);
			filter_cleanup(filter);
			free(l);
			pom_oom(sizeof(struct xmlrpccmd_monitor_evtreg));
			xmlrpc_faultf(envP, "Not enough memory");
			return NULL;
		}
		memset(lst, 0, sizeof(struct xmlrpccmd_monitor_evtreg));

		lst->evt_reg = evt;
		lst->sess = sess;

		if (l->flags & XMLRPCCMD_MONITOR_EVT_LISTEN_BEGIN)
			process_begin = xmlrpccmd_monitor_evt_process_begin;
		int (*process_end) (struct event *evt, void *obj) = NULL;
		if (l->flags & XMLRPCCMD_MONITOR_EVT_LISTEN_END)
			process_end = xmlrpccmd_monitor_evt_process_end;

		// We process ourselves the filter since we only register one listener for all the web listeners
		core_pause_processing();
		if (event_listener_register(evt, lst, process_begin, process_end, NULL) != POM_OK) {
			core_resume_processing();
			pom_mutex_unlock(&sess->lock);
			filter_cleanup(filter);
			free(l);
			free(lst);
			xmlrpc_faultf(envP, "Error while listening to the event.");
			return NULL;

		}
		core_resume_processing();

		lst->next = sess->events_reg;
		if (lst->next)
			lst->next->prev = lst;
		sess->events_reg = lst;
	} else if ((lst->flags & l->flags) != l->flags) {
		// Add the begin or end process function to the event if needed
		unsigned int all_flags = l->flags | lst->flags;
		if (all_flags & XMLRPCCMD_MONITOR_EVT_LISTEN_BEGIN)
			process_begin = xmlrpccmd_monitor_evt_process_begin;
		int (*process_end) (struct event *evt, void *obj) = NULL;
		if (all_flags & XMLRPCCMD_MONITOR_EVT_LISTEN_END)
			process_end = xmlrpccmd_monitor_evt_process_end;

		core_pause_processing();
		if (event_listener_unregister(evt, lst) != POM_OK) {
			core_resume_processing();
			pom_mutex_unlock(&sess->lock);
			free(l);
			free(lst);
			xmlrpc_faultf(envP, "Error while stopping to listen to the event.");
			return NULL;

		}
		lst->flags = 0;
		if (event_listener_register(evt, lst, process_begin, process_end, NULL) != POM_OK) {
			core_resume_processing();
			pom_mutex_unlock(&sess->lock);
			filter_cleanup(filter);
			free(l);
			free(lst);
			xmlrpc_faultf(envP, "Error while listening to the event.");
			return NULL;

		}
		core_resume_processing();
		lst->flags = all_flags;
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

	if (listener_lst->filter)
		filter_cleanup(listener_lst->filter);

	free(listener_lst);

	if (!evt_lst->listeners) {
		// No need to listener to the event anymore

		core_pause_processing();
		if (event_listener_unregister(evt_lst->evt_reg, evt_lst) != POM_OK) {
			core_resume_processing();
			pom_mutex_unlock(&sess->lock);
			xmlrpc_faultf(envP, "Error while stopping to listen to the event.");
			return NULL;

		}
		core_resume_processing();

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

xmlrpc_value *xmlrpccmd_monitor_pload_events_listen(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	xmlrpc_int id = -1;
	xmlrpc_bool value = 0;

	xmlrpc_decompose_value(envP, paramArrayP, "(ib)", &id, &value);

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

	if (value && sess->pload_events_listening) {
		xmlrpc_faultf(envP, "This session is already listening to the payload generating events");
		pom_mutex_unlock(&sess->lock);
		return NULL;
	} else if (!value && !sess->pload_events_listening) {
		xmlrpc_faultf(envP, "This session is already not listening to the payload generating events");
		pom_mutex_unlock(&sess->lock);
		return NULL;
	}


	core_pause_processing();
	if (value) {
		if (event_payload_listen_start() != POM_OK) {
			core_resume_processing();
			xmlrpc_faultf(envP, "Error while listening to the payload generating events");
			pom_mutex_unlock(&sess->lock);
			return NULL;
		}
	} else {
		if (event_payload_listen_stop() != POM_OK) {
			core_resume_processing();
			xmlrpc_faultf(envP, "Error while stopping to listen to the payload generating events");
			pom_mutex_unlock(&sess->lock);
			return NULL;
		}

	}
	core_resume_processing();

	sess->pload_events_listening = value;
	pom_mutex_unlock(&sess->lock);

	return xmlrpc_int_new(envP, 0);
}

xmlrpc_value *xmlrpccmd_monitor_pload_discard(xmlrpc_env * const envP, xmlrpc_value * const paramArrayP, void * const userData) {

	xmlrpc_int sess_id = -1;
	uint64_t listener_id = 0, pload_id = 0;

	xmlrpc_decompose_value(envP, paramArrayP, "(iII)", &sess_id, &listener_id, &pload_id);
	if (envP->fault_occurred)
		return NULL;

	if (sess_id < 0 || sess_id >= XMLRPCCMD_MONITOR_MAX_SESSION) {
		xmlrpc_faultf(envP, "Invalsess_id session sess_id");
		return NULL;
	}

	pom_mutex_lock(&xmlrpccmd_monitor_session_lock);
	struct xmlrpccmd_monitor_session *sess = xmlrpccmd_monitor_sessions[sess_id];
	if (!sess) {
		pom_mutex_unlock(&xmlrpccmd_monitor_session_lock);
		xmlrpc_faultf(envP, "Session %u not found", sess_id);
		return NULL;
	}
	pom_mutex_lock(&sess->lock);
	pom_mutex_unlock(&xmlrpccmd_monitor_session_lock);

	struct xmlrpccmd_monitor_httpd_pload *tmp = NULL;
	HASH_FIND(hh, sess->httpd_ploads, &pload_id, sizeof(pload_id), tmp);

	if (!tmp) {
		xmlrpc_faultf(envP, "Pload id %"PRIu64" not found", pload_id);
		pom_mutex_unlock(&sess->lock);
		return xmlrpc_int_new(envP, 0);
	}

	int i;
	for (i = 0; i < tmp->listeners_count && tmp->listeners[i] != listener_id; i++);
	if (i >= tmp->listeners_count) {
		xmlrpc_faultf(envP, "Listener %"PRIu64" not monitoring pload %"PRIu64, listener_id, pload_id);
		pom_mutex_unlock(&sess->lock);
		return xmlrpc_int_new(envP, 0);
	}

	if (tmp->listeners_count > 1) {
		if (i < tmp->listeners_count - 1)
			memmove(&tmp->listeners[i], &tmp->listeners[i + 1], sizeof(uint64_t) * (tmp->listeners_count - i));
		tmp->listeners_count--;
	} else {
		HASH_DEL(sess->httpd_ploads, tmp);
		free(tmp->listeners);
		free(tmp);
		httpd_pload_remove(pload_id);
		tmp = NULL;
		HASH_FIND(hh, sess->httpd_ploads, &pload_id, sizeof(pload_id), tmp);
		if (tmp)
			printf("WTF\n");
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
	

	timer_sys_dequeue(sess->timer);



	struct xmlrpccmd_monitor_event *lst_evt = NULL;
	struct xmlrpccmd_monitor_pload *lst_pload = NULL;

	while (!sess->events && !sess->ploads) {


		// There is no event or payload to return, wait for some
		
		struct timeval now;
		gettimeofday(&now, NULL);
		struct timespec then = { 0 };
		then.tv_sec = now.tv_sec + XMLRPCCMD_MONITOR_POLL_TIMEOUT;

		sess->polling++;
		int res = pthread_cond_timedwait(&sess->cond, &sess->lock, &then);
		sess->polling--;

		if (res == ETIMEDOUT) {
			pom_mutex_unlock(&sess->lock);
			timer_sys_queue(sess->timer, sess->timeout);
			return xmlrpc_array_new(envP);
		} else if (res) {
			pomlog(POMLOG_ERR "Error while waiting for session condition : %s", pom_strerror(errno));
			abort();
		}

		if (sess->id == -1) {
			// The session has been removed while polling
			pom_mutex_unlock(&sess->lock);
			return xmlrpc_array_new(envP);
		}
		
	}


	lst_evt = sess->events;
	sess->events = NULL;
	lst_pload = sess->ploads;
	sess->ploads = NULL;
	pom_mutex_unlock(&sess->lock);
	


	xmlrpc_value *xml_evt_lst = xmlrpc_array_new(envP);

	while (lst_evt) {
		struct event *evt = lst_evt->evt;
		struct xmlrpccmd_monitor_event *tmp = lst_evt;
		lst_evt = lst_evt->next;

		xmlrpc_value *listener_lst = xmlrpc_array_new(envP);

		int i;
		for (i = 0; i < tmp->listeners_count; i++) {

			xmlrpc_value *id = xmlrpc_i8_new(envP, tmp->listeners[i]);
			xmlrpc_array_append_item(envP, listener_lst, id);
			xmlrpc_DECREF(id);
		}

		free(tmp->listeners);
		free(tmp);

		xmlrpc_value *xml_evt = xmlrpccmd_monitor_build_event(envP, evt);
		event_refcount_dec(evt);

		xmlrpc_struct_set_value(envP, xml_evt, "listeners", listener_lst);
		xmlrpc_DECREF(listener_lst);

		xmlrpc_array_append_item(envP, xml_evt_lst, xml_evt);
		xmlrpc_DECREF(xml_evt);
	}


	xmlrpc_value *xml_pload_lst = xmlrpc_array_new(envP);
	while (lst_pload) {

		xmlrpc_value *listener_lst = xmlrpc_array_new(envP);
		int i;
		for (i = 0; i < lst_pload->listeners_count; i++) {
			xmlrpc_value *id = xmlrpc_i8_new(envP, lst_pload->listeners[i]);
			xmlrpc_array_append_item(envP, listener_lst, id);
			xmlrpc_DECREF(id);
		}

		xmlrpc_value *xml_pload = xmlrpccmd_monitor_build_pload(envP, lst_pload->pload);
		pload_refcount_dec(lst_pload->pload);

		xmlrpc_struct_set_value(envP, xml_pload, "listeners", listener_lst);
		xmlrpc_DECREF(listener_lst);

		xmlrpc_value *xml_pload_id = xmlrpc_i8_new(envP, lst_pload->pload_id);
		xmlrpc_struct_set_value(envP, xml_pload, "id", xml_pload_id);
		xmlrpc_DECREF(xml_pload_id);

		xmlrpc_array_append_item(envP, xml_pload_lst, xml_pload);
		xmlrpc_DECREF(xml_pload);

		struct xmlrpccmd_monitor_pload *tmp = lst_pload;
		lst_pload = lst_pload->next;
		// Don't free listeners here as the same list is used for the httpd_pload structure
		free(tmp);

	}

	xmlrpc_value *res = xmlrpc_build_value(envP, "{s:A,s:A}", "events", xml_evt_lst, "ploads", xml_pload_lst);
	xmlrpc_DECREF(xml_evt_lst);
	xmlrpc_DECREF(xml_pload_lst);


	timer_sys_queue(sess->timer, sess->timeout);

	return res;
}

xmlrpc_value *xmlrpccmd_monitor_build_pload(xmlrpc_env * const envP, struct pload *pload) {

	xmlrpc_value *xml_pload = xmlrpc_struct_new(envP);

	struct data *data = pload_get_data(pload);
	if (data) {
		xmlrpc_value *xml_data = xmlrpccmd_monitor_build_data(envP, pload_get_data_reg(pload), data);
		xmlrpc_struct_set_value(envP, xml_pload, "data", xml_data);
		xmlrpc_DECREF(xml_data);
	}

	struct mime_type *mime_type = pload_get_mime_type(pload);
	if (mime_type) {
		struct mime_type *mime_type = pload_get_mime_type(pload);
		xmlrpc_value *xml_mime_type = xmlrpc_string_new(envP, mime_type->name);
		xmlrpc_struct_set_value(envP, xml_pload, "mime_type", xml_mime_type);
		xmlrpc_DECREF(xml_mime_type);
	}

	char *filename = pload_get_filename(pload);
	if (filename) {
		xmlrpc_value *xml_filename = xmlrpc_string_new(envP, filename);
		xmlrpc_struct_set_value(envP, xml_pload, "filename", xml_filename);
		xmlrpc_DECREF(xml_filename);
	}

	struct event *evt = pload_get_related_event(pload);
	if (evt) {
		xmlrpc_value *xml_evt = xmlrpccmd_monitor_build_event(envP, evt);
		xmlrpc_struct_set_value(envP, xml_pload, "rel_event", xml_evt);
		xmlrpc_DECREF(xml_evt);
	}

	return xml_pload;

}

xmlrpc_value *xmlrpccmd_monitor_build_event(xmlrpc_env * const envP, struct event *evt) {

	struct event_reg *evt_reg = event_get_reg(evt);
	struct event_reg_info *evt_reg_info = event_reg_get_info(evt_reg);

	xmlrpc_value *data = xmlrpccmd_monitor_build_data(envP, evt_reg_info->data_reg, event_get_data(evt));

	ptime evt_timestamp = event_get_timestamp(evt);
	xmlrpc_value *timestamp = xmlrpc_build_value(envP, "{s:i,s:i}", "sec", pom_ptime_sec(evt_timestamp), "usec", pom_ptime_usec(evt_timestamp));

	xmlrpc_value *xml_evt = xmlrpc_build_value(envP, "{s:s,s:S,s:S,s:b}",
					"event", evt_reg_info->name,
					"timestamp", timestamp,
					"data", data,
					"done", event_is_done(evt));
	xmlrpc_DECREF(timestamp);
	xmlrpc_DECREF(data);

	return xml_evt;
}

xmlrpc_value *xmlrpccmd_monitor_build_data(xmlrpc_env * const envP, struct data_reg *dreg, struct data *data) {


	xmlrpc_value *xml_data = xmlrpc_struct_new(envP);

	int i;
	for (i = 0; i < dreg->data_count; i++) {
		
		struct data_item_reg *direg = &dreg->items[i];

		if (!data_is_set(data[i]) && !(direg->flags & DATA_REG_FLAG_LIST))
			continue;

		xmlrpc_value *value = NULL;
		if (direg->flags & DATA_REG_FLAG_LIST) {
			
			value = xmlrpc_array_new(envP);

			struct data_item *itm;
			for (itm = data[i].items; itm; itm = itm->next) {
				xmlrpc_value *itm_val = xmlrpccmd_ptype_to_val(envP, itm->value);
				xmlrpc_value *itm_entry = xmlrpc_build_value(envP, "{s:s,s:V}", "key", itm->key, "value", itm_val);
				xmlrpc_DECREF(itm_val);
				xmlrpc_array_append_item(envP, value, itm_entry);
				xmlrpc_DECREF(itm_entry);
			}


		} else {
			value = xmlrpccmd_ptype_to_val(envP, data[i].value);
		}
		
		xmlrpc_struct_set_value(envP, xml_data, direg->name, value);
		xmlrpc_DECREF(value);
	
	}


	return xml_data;

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
