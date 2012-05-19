/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2011-2012 Guy Martin <gmsoft@tuxicoman.be>
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

#if 0
#define debug_event(x ...) pomlog(POMLOG_DEBUG x)
#else
#define debug_event(x ...)
#endif

struct event_reg *event_reg_head = NULL;


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

	evt->info = reg_info;

	evt->next = event_reg_head;
	if (evt->next)
		evt->next->prev = evt;
	event_reg_head = evt;

	pomlog(POMLOG_DEBUG "Event %s registered", reg_info->name);

	return evt;
}

int event_unregister(struct event_reg *evt) {
	
	if (evt->next)
		evt->next->prev = evt->prev;

	if (evt->prev)
		evt->prev->next = evt->next;
	else
		event_reg_head = evt->next;

	free(evt);

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

	debug_event("Event %s allocated", evt_reg->info->name);

	return evt;
}

int event_cleanup(struct event *evt) {

	if (evt->refcount) {
		pomlog(POMLOG_ERR "Internal error: cannot cleanup event as refcount is not 0 : %u", evt->refcount);
		return POM_ERR;
	}

	if (evt->flags & EVENT_FLAG_PROCESS_BEGAN && !(evt->flags & EVENT_FLAG_PROCESS_DONE)) {
		pomlog(POMLOG_ERR "Internal error: event %s processing began but never ended", evt->reg->info->name);
		return POM_ERR;
	}
	if (evt->reg->info->cleanup && evt->reg->info->cleanup(evt) != POM_OK) {
		pomlog(POMLOG_ERR "Error while cleaning up the event %s", evt->reg->info->name);
		return POM_ERR;
	}

	data_cleanup_table(evt->data, evt->reg->info->data_reg);
	free(evt);
	return POM_OK;
}

struct event_reg *event_find(char *name) {

	struct event_reg *tmp;
	for (tmp = event_reg_head; tmp && strcmp(tmp->info->name, name); tmp = tmp->next);
	return tmp;
}

int event_listener_register(struct event_reg *evt_reg, struct event_listener *listener) {
	
	struct event_listener_list *lst = malloc(sizeof(struct event_listener_list));
	if (!lst) {
		pom_oom(sizeof(struct event_listener_list));
		return POM_ERR;

	}
	memset(lst, 0, sizeof(struct event_listener_list));
	
	lst->l = listener;
	
	lst->next = evt_reg->listeners;
	if (lst->next)
		lst->next->prev = lst;

	evt_reg->listeners = lst;

	if (!lst->next) {
		// Got a listener now, notify
		if (evt_reg->info->listeners_notify && evt_reg->info->listeners_notify(evt_reg->info->source_obj, evt_reg, 1) != POM_OK) {
			pomlog(POMLOG_ERR "Error while notifying event object about new listener");
			evt_reg->listeners = NULL;
			free(lst);
			return POM_ERR;
		}
	}
	

	return POM_OK;
}

int event_listener_unregister(struct event_reg *evt_reg, void *obj) {

	struct event_listener_list *lst;
	for (lst = evt_reg->listeners; lst && lst->l->obj != obj; lst = lst->next);

	if (!lst) {
		pomlog(POMLOG_ERR "Object %p not found in the listeners list of event %s",  obj, evt_reg->info->name);
		return POM_ERR;
	}

	if (lst->next)
		lst->next->prev = lst->prev;
	
	if (lst->prev)
		lst->prev->next = lst->next;
	else
		evt_reg->listeners = lst->next;

	free(lst);

	if (!evt_reg->listeners) {
		if (evt_reg->info->listeners_notify && evt_reg->info->listeners_notify(evt_reg->info->source_obj, evt_reg, 0) != POM_OK) {
			pomlog(POMLOG_WARN "Error while notifying event object that it has no listeners");
		}
	}

	return POM_OK;
}

int event_process_begin(struct event *evt, struct proto_process_stack *stack, int stack_index) {

	debug_event("Processing event begin %s", evt->reg->info->name);

	if (evt->flags & EVENT_FLAG_PROCESS_BEGAN) {
		pomlog(POMLOG_ERR "Internal error: event %s already processed", evt->reg->info->name);
		return POM_ERR;
	}

	evt->ce = stack[stack_index].ce;

	struct event_listener_list *lst;
	for (lst = evt->reg->listeners; lst; lst = lst->next) {
		struct event_listener *l = lst->l;
		if (l->process_begin && l->process_begin(evt, l->obj, stack, stack_index) != POM_OK) {
			pomlog(POMLOG_WARN "An error occured while processing begining of event %s", evt->reg->info->name);
		}
	}

	evt->flags |= EVENT_FLAG_PROCESS_BEGAN;

	return POM_OK;
}

int event_process_end(struct event *evt) {

	debug_event("Processing event end %s", evt->reg->info->name);

	if (!(evt->flags & EVENT_FLAG_PROCESS_BEGAN)) {
		pomlog(POMLOG_ERR "Internal error: event %s processing hasn't begun", evt->reg->info->name);
		return POM_ERR;
	}

	if (evt->flags & EVENT_FLAG_PROCESS_DONE) {
		pomlog(POMLOG_ERR "Internal error: event %s has already been processed entirely", evt->reg->info->name);
		return POM_ERR;
	}

	event_refcount_inc(evt);

	struct event_listener_list *lst;
	for (lst = evt->reg->listeners; lst; lst = lst->next) {
		struct event_listener *l = lst->l;
		if (l->process_end && l->process_end(evt, l->obj) != POM_OK) {
			pomlog(POMLOG_WARN "An error occured while processing event %s", evt->reg->info->name);
		}
	}
	
	evt->ce = NULL;

	evt->flags |= EVENT_FLAG_PROCESS_DONE;

	return event_refcount_dec(evt);
}

int event_refcount_inc(struct event *evt) {

	evt->refcount++;
	return POM_OK;
}

int event_refcount_dec(struct event *evt) {

	evt->refcount--;

	if (!evt->refcount)
		return event_cleanup(evt);
	
	return POM_OK;
}
