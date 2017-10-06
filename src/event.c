/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2011-2015 Guy Martin <gmsoft@tuxicoman.be>
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
#include <pom-ng/event.h>
#include "event.h"
#include "registry.h"
#include "core.h"
#include "filter.h"

#if 0
#define debug_event(x ...) pomlog(POMLOG_DEBUG x)
#else
#define debug_event(x ...)
#endif

static struct event_reg *event_reg_head = NULL;

static unsigned int event_pload_listener_ref = 0;

static struct registry_class *event_registry_class = NULL;

int event_init() {

	event_registry_class = registry_add_class(EVENT_REGISTRY);
	if (!event_registry_class)
		return POM_ERR;

	return POM_OK;

}

int event_finish() {

	while (event_reg_head) {
		pomlog(POMLOG_ERR "Event %s is still registered", event_reg_head->info->name);
		event_unregister(event_reg_head);
	}

	if (event_registry_class)
		registry_remove_class(event_registry_class);
	event_registry_class = NULL;

	return POM_OK;
}


struct event_reg *event_register(struct event_reg_info *reg_info) {

	struct event_reg *evt;

	// Check if an event with the same name has already been registered
	for (evt = event_reg_head; evt && strcmp(evt->info->name, reg_info->name); evt = evt->next);
	if (evt) {
		pomlog(POMLOG_ERR "An event named %s has already been registered", reg_info->name);
		return NULL;
	}

	// Allocate the event_reg
	evt = malloc(sizeof(struct event_reg));
	if (!evt) {
		pom_oom(sizeof(struct event_reg));
		return NULL;
	}
	memset(evt, 0, sizeof(struct event_reg));

	int res = pthread_mutex_init(&evt->evts_lock, NULL);
	if (res) {
		pomlog(POMLOG_ERR "Error while initializing the event list lock : %s", pom_strerror(res));
		free(evt);
		return NULL;
	}

	evt->reg_instance = registry_add_instance(event_registry_class, reg_info->name);
	if (!evt->reg_instance) {
		free(evt);
		return NULL;
	}

	struct ptype *param = ptype_alloc("string");
	if (!param) {
		free(evt);
		return NULL;
	}

	struct registry_param *p = registry_new_param("description", reg_info->description, param, "Event description", REGISTRY_PARAM_FLAG_CLEANUP_VAL | REGISTRY_PARAM_FLAG_IMMUTABLE);
	if (registry_instance_add_param(evt->reg_instance, p) != POM_OK) {
		free(evt);
		return NULL;
	}

	evt->perf_listeners = registry_instance_add_perf(evt->reg_instance, "listeners", registry_perf_type_gauge, "Number of event listeners", "listeners");
	evt->perf_ongoing = registry_instance_add_perf(evt->reg_instance, "ongoing", registry_perf_type_gauge, "Number of ongoing events", "events");
	evt->perf_processed = registry_instance_add_perf(evt->reg_instance, "processed", registry_perf_type_counter, "Number of events fully processed", "events");
	if (!evt->perf_listeners || !evt->perf_ongoing || !evt->perf_processed) {
		registry_remove_instance(evt->reg_instance);
		free(evt);
		return NULL;
	}

	evt->info = reg_info;

	evt->next = event_reg_head;
	if (evt->next)
		evt->next->prev = evt;
	event_reg_head = evt;

	pomlog(POMLOG_DEBUG "Event %s registered", reg_info->name);

	return evt;
}

int event_unregister(struct event_reg *reg) {
	
	if (reg->next)
		reg->next->prev = reg->prev;

	if (reg->prev)
		reg->prev->next =reg->next;
	else
		event_reg_head = reg->next;

	struct event_reg_events *cur_evt, *tmp_evt;
	HASH_ITER(hh, reg->evts, cur_evt, tmp_evt) {
		pomlog(POMLOG_WARN "Some events were not cleanup correctly !");
		event_cleanup(cur_evt->evt);
		free(cur_evt);
	}

	registry_remove_instance(reg->reg_instance);

	int res = pthread_mutex_destroy(&reg->evts_lock);
	if (res)
		pomlog(POMLOG_WARN "Error while destroying event list lock : %s", pom_strerror(res));

	free(reg);

	return POM_OK;
}

struct event *event_alloc(struct event_reg *evt_reg) {

	struct event *evt = malloc(sizeof(struct event));
	if (!evt) {
		pom_oom(sizeof(struct event));
		return NULL;
	}
	memset(evt, 0, sizeof(struct event));

	struct event_reg_info *info = evt_reg->info;
	evt->reg = evt_reg;

	evt->data = data_alloc_table(info->data_reg);
	if (!evt->data) {
		free(evt);
		return NULL;
	}

	debug_event("Event %p (%s) allocated", evt, evt_reg->info->name);

	return evt;
}

int event_cleanup(struct event *evt) {

	if (evt->refcount) {
		pomlog(POMLOG_ERR "Internal error: cannot cleanup event %p as refcount is not 0 : %u", evt, evt->refcount);
		return POM_ERR;
	}

	if (evt->flags & EVENT_FLAG_PROCESS_BEGAN && !(evt->flags & EVENT_FLAG_PROCESS_DONE)) {
		pomlog(POMLOG_ERR "Internal error: event %p (%s) processing began but never ended", evt, evt->reg->info->name);
		return POM_ERR;
	}

	if (evt->reg->info->cleanup && evt->reg->info->cleanup(evt) != POM_OK) {
		pomlog(POMLOG_ERR "Error while cleaning up the event %p (%s)", evt, evt->reg->info->name);
		return POM_ERR;
	}

	while (evt->tmp_listeners) {
		struct event_listener *lst = evt->tmp_listeners;
		evt->tmp_listeners = lst->next;
		free(lst);
	}

	if (evt->priv && evt->reg->info->priv_cleanup) {
		evt->reg->info->priv_cleanup(evt->priv);
		evt->priv = NULL;
	}

	debug_event("Event %p (%s) cleaned up", evt, evt->reg->info->name);
	data_cleanup_table(evt->data, evt->reg->info->data_reg);
	free(evt);
	return POM_OK;
}

struct event_reg *event_find(const char *name) {

	struct event_reg *tmp;
	for (tmp = event_reg_head; tmp && strcmp(tmp->info->name, name); tmp = tmp->next);
	return tmp;
}

int event_payload_listen_start() {

	if (event_pload_listener_ref) {
		event_pload_listener_ref++;
		return POM_OK;
	}

	__sync_add_and_fetch(&event_pload_listener_ref, 1);

	struct event_reg *tmp;
	for (tmp = event_reg_head; tmp; tmp = tmp->next) {
		if (tmp->info->flags & EVENT_REG_FLAG_PAYLOAD) {
			// Register a dummy listener for events that generate payload
			if (event_listener_register(tmp, &event_pload_listener_ref, NULL, NULL, NULL) != POM_OK)
				goto err;
		}
	}


	return POM_OK;

err:
	event_payload_listen_stop();

	return POM_ERR;
}

int event_payload_listen_stop() {

	if (!event_pload_listener_ref) {
		pomlog(POMLOG_ERR, "Payload listener not started yet !");
		return POM_ERR;
	}

	if (__sync_sub_and_fetch(&event_pload_listener_ref, 1))
		return POM_OK;

	struct event_reg *tmp;
	for (tmp = event_reg_head; tmp; tmp = tmp->next) {
		if (!(tmp->info->flags & EVENT_REG_FLAG_PAYLOAD))
			continue;
		event_listener_unregister(tmp, &event_pload_listener_ref);
	}
	
	return POM_OK;
}

int event_listener_register(struct event_reg *evt_reg, void *obj, int (*process_begin) (struct event *evt, void *obj, struct proto_process_stack *stack, unsigned int stack_index), int (*process_end) (struct event *evt, void *obj), struct filter *f) {

	core_assert_is_paused();

	struct event_listener *lst;
	for (lst = evt_reg->listeners; lst && lst->obj != obj; lst = lst->next);

	if (lst) {
		if (f)
			filter_cleanup(f);
		pomlog(POMLOG_ERR "Event %s is already being listened to by obj %p", evt_reg->info->name, obj);
		return POM_ERR;
	}
	
	
	lst = malloc(sizeof(struct event_listener));
	if (!lst) {
		if (f)
			filter_cleanup(f);
		pom_oom(sizeof(struct event_listener));
		return POM_ERR;

	}
	memset(lst, 0, sizeof(struct event_listener));
	
	lst->obj = obj;
	lst->process_begin = process_begin;
	lst->process_end = process_end;
	lst->filter = f;
	
	lst->next = evt_reg->listeners;
	if (lst->next)
		lst->next->prev = lst;

	evt_reg->listeners = lst;

	if (evt_reg->info->listeners_notify && !lst->next) {
		// Got a listener now, notify
		if (evt_reg->info->listeners_notify(evt_reg->info->source_obj, evt_reg, 1) != POM_OK) {
			pomlog(POMLOG_ERR "Error while notifying event object about new listener");
			evt_reg->listeners = NULL;
			free(lst);
			if (f)
				filter_cleanup(f);
			return POM_ERR;
		}
	}

	registry_perf_inc(evt_reg->perf_listeners, 1);
	
	return POM_OK;
}

int event_listener_unregister(struct event_reg *evt_reg, void *obj) {

	core_assert_is_paused();

	struct event_listener *lst;
	for (lst = evt_reg->listeners; lst && lst->obj != obj; lst = lst->next);

	if (!lst) {
		pomlog(POMLOG_ERR "Object %p not found in the listeners list of event %s",  obj, evt_reg->info->name);
		return POM_ERR;
	}

	if (lst->process_end) {
		struct event_reg_events *cur_evt, *tmp_evt;

		HASH_ITER(hh, evt_reg->evts, cur_evt, tmp_evt) {
			lst->process_end(cur_evt->evt, lst->obj);
		}
	}

	if (lst->filter)
		filter_cleanup(lst->filter);

	if (lst->next)
		lst->next->prev = lst->prev;
	
	if (lst->prev)
		lst->prev->next = lst->next;
	else
		evt_reg->listeners = lst->next;

	free(lst);

	if (evt_reg->info->listeners_notify && !evt_reg->listeners) {
		if (evt_reg->info->listeners_notify(evt_reg->info->source_obj, evt_reg, 0) != POM_OK) {
			pomlog(POMLOG_WARN "Error while notifying event object that it has no listeners");
		}
	}

	registry_perf_dec(evt_reg->perf_listeners, 1);

	return POM_OK;
}

int event_add_listener(struct event *evt, void *obj, int (*process_begin) (struct event *evt, void *obj, struct proto_process_stack *stack, unsigned int stack_index), int (*process_end) (struct event *evt, void *obj)) {

	if (process_begin && process_begin(evt, obj, NULL, 0) != POM_OK)
		return POM_ERR;

	struct event_listener *tmp = malloc(sizeof(struct event_listener));
	if (!tmp) {
		pom_oom(sizeof(struct event_listener));
		return POM_ERR;
	}
	memset(tmp, 0, sizeof(struct event_listener));
	
	tmp->obj = obj;
	tmp->process_end = process_end;

	tmp->next = evt->tmp_listeners;
	if (tmp->next)
		tmp->next->prev = tmp;
	evt->tmp_listeners = tmp;
	
	registry_perf_inc(evt->reg->perf_listeners, 1);

	return POM_OK;

}

int event_has_listener(struct event_reg *evt_reg) {
	return (evt_reg->listeners ? 1 : 0);
}

int event_process(struct event *evt, struct proto_process_stack *stack, int stack_index, ptime ts) {


	debug_event("Processing event %p (%s)", evt, evt->reg->info->name);
	if (evt->flags & EVENT_FLAG_PROCESS_BEGAN) {
		pomlog(POMLOG_ERR "Internal error: event %s already processed", evt->reg->info->name);
		return POM_ERR;
	}

	event_refcount_inc(evt);

	if (stack)
		evt->ce = stack[stack_index].ce;

	evt->ts = ts;

	__sync_fetch_and_or(&evt->flags, EVENT_FLAG_PROCESS_BEGAN);

	struct event_listener *lst;
	for (lst = evt->reg->listeners; lst; lst = lst->next) {

		if (lst->filter && event_filter_match(lst->filter, evt) != FILTER_MATCH_YES)
			continue;

		if (lst->process_begin && lst->process_begin(evt, lst->obj, stack, stack_index) != POM_OK) {
			pomlog(POMLOG_WARN "An error occured while processing begining of event %s", evt->reg->info->name);
		}
		if (lst->process_end && lst->process_end(evt, lst->obj) != POM_OK) {
			pomlog(POMLOG_WARN "An error occured while processing event %s", evt->reg->info->name);
		}
	}

	for (lst = evt->tmp_listeners; lst; lst = lst->next) {
		if (lst->process_end && lst->process_end(evt, lst->obj) != POM_OK) {
			pomlog(POMLOG_WARN "An error occured while processing event %s", evt->reg->info->name);
		}
		registry_perf_dec(evt->reg->perf_listeners, 1);
	}

	if (evt->priv && evt->reg->info->priv_cleanup) {
		evt->reg->info->priv_cleanup(evt->priv);
		evt->priv = NULL;
	}

	evt->ce = NULL;
	__sync_fetch_and_or(&evt->flags, EVENT_FLAG_PROCESS_DONE);

	registry_perf_inc(evt->reg->perf_processed, 1);

	return event_refcount_dec(evt);
}

int event_process_begin(struct event *evt, struct proto_process_stack *stack, int stack_index, ptime ts) {

	debug_event("Processing event begin %p (%s)", evt,  evt->reg->info->name);

	if (evt->flags & EVENT_FLAG_PROCESS_BEGAN) {
		pomlog(POMLOG_ERR "Internal error: event %s already processed", evt->reg->info->name);
		return POM_ERR;
	}

	struct event_reg_events *revt = malloc(sizeof(struct event_reg_events));
	if (!revt) {
		pom_oom(sizeof(struct event_reg_events));
		return POM_ERR;
	}
	memset(revt, 0, sizeof(struct event_reg_events));

	event_refcount_inc(evt);

	if (stack)
		evt->ce = stack[stack_index].ce;

	evt->ts = ts;

	struct event_listener *lst;
	for (lst = evt->reg->listeners; lst; lst = lst->next) {

		if (!lst->process_begin)
			continue;

		if (lst->filter && event_filter_match(lst->filter, evt) != FILTER_MATCH_YES)
			continue;

		if (lst->process_begin(evt, lst->obj, stack, stack_index) != POM_OK) {
			pomlog(POMLOG_WARN "An error occured while processing begining of event %s", evt->reg->info->name);
		}
	}

	pom_mutex_lock(&evt->reg->evts_lock);
	revt->evt = evt;
	HASH_ADD(hh, evt->reg->evts, evt, sizeof(evt), revt);
	pom_mutex_unlock(&evt->reg->evts_lock);

	__sync_fetch_and_or(&evt->flags, EVENT_FLAG_PROCESS_BEGAN);

	registry_perf_inc(evt->reg->perf_ongoing, 1);

	return POM_OK;
}

int event_process_end(struct event *evt) {

	debug_event("Processing event end %p (%s)", evt, evt->reg->info->name);

	if (!(evt->flags & EVENT_FLAG_PROCESS_BEGAN)) {
		pomlog(POMLOG_ERR "Internal error: event %s processing hasn't begun", evt->reg->info->name);
		event_cleanup(evt);
		return POM_ERR;
	}

	if (evt->flags & EVENT_FLAG_PROCESS_DONE) {
		pomlog(POMLOG_ERR "Internal error: event %s has already been processed entirely", evt->reg->info->name);
		event_cleanup(evt);
		return POM_ERR;
	}


	struct event_listener *lst;

	struct event_reg_events *revt;
	pom_mutex_lock(&evt->reg->evts_lock);
	HASH_FIND(hh, evt->reg->evts, &evt, sizeof(evt), revt);
	if (!revt) {
		pomlog(POMLOG_ERR "Event not found in the event_reg events");
	} else {
		HASH_DEL(evt->reg->evts, revt);
		pom_mutex_unlock(&evt->reg->evts_lock);
		free(revt);
	}

	for (lst = evt->reg->listeners; lst; lst = lst->next) {
		if (!lst->process_end)
			continue;

		if (lst->filter && event_filter_match(lst->filter, evt) != FILTER_MATCH_YES)
			continue;

		if (lst->process_end(evt, lst->obj) != POM_OK) {
			pomlog(POMLOG_WARN "An error occured while processing event %s", evt->reg->info->name);
		}
	}

	for (lst = evt->tmp_listeners; lst; lst = lst->next) {
		if (lst->process_end && lst->process_end(evt, lst->obj) != POM_OK) {
			pomlog(POMLOG_WARN "An error occured while processing event %s", evt->reg->info->name);
		}
		registry_perf_dec(evt->reg->perf_listeners, 1);
	}

	if (evt->priv && evt->reg->info->priv_cleanup) {
		evt->reg->info->priv_cleanup(evt->priv);
		evt->priv = NULL;
	}
	evt->ce = NULL;

	__sync_fetch_and_or(&evt->flags, EVENT_FLAG_PROCESS_DONE);

	registry_perf_dec(evt->reg->perf_ongoing, 1);
	registry_perf_inc(evt->reg->perf_processed, 1);

	return event_refcount_dec(evt);
}

int event_refcount_inc(struct event *evt) {

	__sync_add_and_fetch(&evt->refcount, 1);
	return POM_OK;
}

int event_refcount_dec(struct event *evt) {

	if (!__sync_sub_and_fetch(&evt->refcount, 1))
		return event_cleanup(evt);
	
	return POM_OK;
}

struct event_reg_info *event_get_info(struct event *evt) {
	return evt->reg->info;
}

struct data *event_get_data(struct event *evt) {
	return evt->data;
}

struct event_reg *event_get_reg(struct event *evt) {
	return evt->reg;
}

struct event_reg_info *event_reg_get_info(struct event_reg *evt_reg) {
	return evt_reg->info;
}
struct ptype *event_data_item_add(struct event *evt, unsigned int id, const char *key) {
	return data_item_add(evt->data, evt->reg->info->data_reg, id, key);
}

void *event_get_priv(struct event *evt) {
	return evt->priv;
}

void event_set_priv(struct event *evt, void *priv) {
	evt->priv = priv;
}

struct conntrack_entry *event_get_conntrack(struct event *evt) {
	return evt->ce;
}

unsigned int event_is_started(struct event *evt) {
	return (evt->flags & EVENT_FLAG_PROCESS_BEGAN ? 1 : 0);
}

unsigned int event_is_done(struct event *evt) {
	return (evt->flags & EVENT_FLAG_PROCESS_DONE ? 1 : 0);
}

ptime event_get_timestamp(struct event *evt) {
	return evt->ts;
}

int event_filter_prop_compile(struct filter *f, char *prop_str, struct filter_value *v) {

	if (!strncmp(prop_str, "data.", strlen("data."))) {
		prop_str += strlen("data.");
		struct event_reg_info *info = event_reg_get_info(f->priv);

		struct data_reg *dr = info->data_reg;

		char *key = strchr(prop_str, '[');
		if (key) {
			*key = 0;
			key++;
			char *key_end = strchr(key, ']');
			if (!key_end) {
				pomlog(POMLOG_ERR "Missing ] for data key in filter for item %s", prop_str);
				return POM_ERR;
			}
			*key_end = 0;
		}

		int i;
		for (i = 0;i < dr->data_count && strcmp(dr->items[i].name, prop_str); i ++);

		if (i >= dr->data_count) {
			pomlog(POMLOG_ERR "Data item %s not found", prop_str);
			return POM_ERR;
		}

		struct data_item_reg *item = &dr->items[i];

		struct event_filter_prop *prop = malloc(sizeof(struct event_filter_prop));
		if (!prop) {
			pom_oom(sizeof(struct event_filter_prop));
			return POM_ERR;
		}
		memset(prop, 0, sizeof(struct event_filter_prop));
		prop->field_id = i;

		if (key) {
			if (!(item->flags & DATA_REG_FLAG_LIST)) {
				pomlog(POMLOG_ERR "Key provided for item %s while it's not a list", prop_str);
				return POM_ERR;
			}
			prop->key = strdup(key);
			if (!prop->key) {
				free(prop);
				pom_oom(strlen(key) + 1);
				return POM_ERR;
			}
		} else if (item->flags & DATA_REG_FLAG_LIST) {
			free(prop);
			pomlog(POMLOG_ERR "Key not provided for filter value %s", prop_str);
			return POM_ERR;
		}


		v->type = filter_value_type_prop;
		v->val.prop.priv = prop;

		if (!item->value_type) {
			v->val.prop.out_type = filter_value_type_unknown;
		} else if (filter_ptype_is_integer(item->value_type)) {
			v->val.prop.out_type = filter_value_type_int;
		} else if (filter_ptype_is_string(item->value_type)) {
			v->val.prop.out_type = filter_value_type_string;
		} else {
			v->val.prop.out_type = filter_value_type_ptype;
			v->val.prop.out_ptype = item->value_type;
		}

	} else {
		pomlog(POMLOG_ERR "Unknown property %s", prop_str);
		return POM_ERR;
	}

	return POM_OK;
}

int event_filter_prop_get_val(struct filter_value *inval, struct filter_value *outval, void *obj) {

	struct event *evt = obj;
	struct event_filter_prop *prop = inval->val.prop.priv;

	struct data *d = event_get_data(evt);
	if (!data_is_set(d[prop->field_id]))
		return POM_OK;

	struct ptype *value = NULL;

	if (prop->key) {
		struct data_item *itm;
		for (itm = d[prop->field_id].items; itm && strcmp(itm->key, prop->key); itm = itm->next);
		if (!itm)
			return POM_OK;
		value = itm->value;
	} else {
		value = d[prop->field_id].value;
	}

	filter_ptype_to_value(outval, value);

	return POM_OK;
}

void event_filter_prop_cleanup(void *prop) {

	struct event_filter_prop *p = prop;
	if (p->key)
		free(p->key);

	free(p);

}

struct filter *event_filter_compile(char *filter_expr, struct event_reg *evt) {

	struct filter *f = filter_alloc(event_filter_prop_compile, evt, event_filter_prop_get_val, event_filter_prop_cleanup);
	if (!f)
		return NULL;
	if (filter_compile(filter_expr, f) != POM_OK) {
		filter_cleanup(f);
		return NULL;
	}
	return f;
}

int event_filter_match(struct filter *f, struct event *evt) {

	return filter_match(f, evt);
}
