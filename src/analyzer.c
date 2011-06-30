/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2011 Guy Martin <gmsoft@tuxicoman.be>
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

#include "analyzer.h"
#include "output.h"
#include "mod.h"
#include "input_server.h"

static struct analyzer_reg *analyzer_head = NULL;
static pthread_mutex_t analyzer_lock = PTHREAD_MUTEX_INITIALIZER;

int analyzer_register(struct analyzer_reg_info *reg_info) {

	if (reg_info->api_ver != ANALYZER_API_VER) {
		pomlog(POMLOG_ERR "Cannot register analyzer as API version differ : expected %u got %u", ANALYZER_API_VER, reg_info->api_ver);
		return POM_ERR;
	}

	if (input_server_is_current_process()) {
		pomlog(POMLOG_DEBUG "Not loading analyzer %s in the input process", reg_info->name);
		return POM_OK;
	}

	pom_mutex_lock(&analyzer_lock);

	// Allocate the analyzer
	struct analyzer_reg *analyzer = malloc(sizeof(struct analyzer_reg));
	if (!analyzer) {
		pom_mutex_unlock(&analyzer_lock);
		pom_oom(sizeof(struct analyzer_reg));
		return POM_ERR;
	}
	memset(analyzer, 0, sizeof(struct analyzer_reg));
	analyzer->info = reg_info;

	// Update the analyzer pointer for the events
	int i;
	for (i = 0; reg_info->events[i].name; i++)
		reg_info->events[i].analyzer = analyzer;

	if (reg_info->init) {
		if (reg_info->init(analyzer) != POM_OK) {
			pom_mutex_unlock(&analyzer_lock);
			free(analyzer);
			pomlog(POMLOG_ERR "Error while initializing analyzer %s", reg_info->name);
			return POM_ERR;
		}
	}

	analyzer->next = analyzer_head;
	if (analyzer->next)
		analyzer->next->prev = analyzer;
	analyzer_head = analyzer;
	pom_mutex_unlock(&analyzer_lock);
	
	mod_refcount_inc(reg_info->mod);

	return POM_OK;
}

int analyzer_unregister(char *name) {

	pom_mutex_lock(&analyzer_lock);
	struct analyzer_reg *tmp;
	for (tmp = analyzer_head; tmp && strcmp(tmp->info->name, name); tmp = tmp->next);

	if (!tmp) {
		pom_mutex_unlock(&analyzer_lock);
		pomlog(POMLOG_DEBUG "Analyzer %s is not registered, cannot unregister it", name);
		return POM_OK;
	}

	if (tmp->info->cleanup) {
		if (tmp->info->cleanup(tmp) != POM_OK) {
			pomlog(POMLOG_ERR "Error while cleaning up analyzer %s", name);
			return POM_ERR;
		}
	}

	if (tmp->prev)
		tmp->prev->next = tmp->next;
	else
		analyzer_head = tmp->next;

	if (tmp->next)
		tmp->next->prev = tmp->prev;

	mod_refcount_dec(tmp->info->mod);
	
	free(tmp);

	pom_mutex_unlock(&analyzer_lock);

	return POM_OK;
}

int analyzer_cleanup() {
	
	pom_mutex_lock(&analyzer_lock);

	while (analyzer_head) {

		struct analyzer_reg *tmp = analyzer_head;
		analyzer_head = tmp->next;

		if (tmp->info->cleanup) {
			if (tmp->info->cleanup(tmp))
				pomlog(POMLOG_WARN "Error while cleaning up analyzer %s", tmp->info->name);
		}

		mod_refcount_dec(tmp->info->mod);

		free(tmp);
	}

	pom_mutex_unlock(&analyzer_lock);

	return POM_OK;

}


struct analyzer_event_reg *analyzer_event_get(char *name) {

	struct analyzer_reg *tmp;
	for (tmp = analyzer_head; tmp; tmp = tmp->next) {

		struct analyzer_event_reg *evt = tmp->info->events;
		unsigned int i;
		for (i = 0; evt[i].name; i++) {
			if (!strcmp(name, evt[i].name))
				return &evt[i];
		}
	}

	return NULL;
}



int analyzer_event_register_listener(struct analyzer_event_reg *evt, struct analyzer_event_listener *listener) {

	if (!evt->listeners && evt->listeners_notify) {
		// Notify the analyzer that the event has a listener now
		if (evt->listeners_notify(evt->analyzer, evt, 1) != POM_OK) {
			pomlog(POMLOG_ERR "Error while notifying the analyzer %s about new listeners for event %s", evt->analyzer->info->name, evt->name);
			return POM_ERR;
		}
	}

	struct analyzer_event_listener_list *listener_list = malloc(sizeof(struct analyzer_event_listener_list));
	if (!listener_list) {
		pom_oom(sizeof(struct analyzer_event_listener_list));
		return POM_ERR;
	}
	memset(listener_list, 0, sizeof(struct analyzer_event_listener_list));

	listener_list->listener = listener;
	listener_list->next = evt->listeners;
	if (listener_list->next)
		listener_list->next->prev = listener_list;
	evt->listeners = listener_list;

	return POM_OK;
}

int analyzer_event_unregister_listener(struct analyzer_event_reg *evt, char *listener_name) {

	struct analyzer_event_listener_list *tmp = evt->listeners;

	for (; tmp && strcmp(tmp->listener->name, listener_name); tmp = tmp->next);

	if (!tmp) {
		pomlog(POMLOG_ERR "Listener %s is not registered to event %s", listener_name, evt->name);
		return POM_ERR;
	}

	if (tmp->next)
		tmp->next->prev = tmp->prev;
	if (tmp->prev)
		tmp->prev->next = tmp->next;
	else
		evt->listeners = tmp->next;
	
	free(tmp);

	if (!evt->listeners && evt->listeners_notify) {
		// Notify the analyzer that the event has a listener now
		if (evt->listeners_notify(evt->analyzer, evt, 0) != POM_OK) {
			pomlog(POMLOG_ERR "Error while notifying the analyzer %s about lack of listeners for event %s", evt->analyzer->info->name, evt->name);
			return POM_ERR;
		}
	}

	return POM_OK;
}


int analyzer_event_process(struct analyzer_event *evt) {

	struct analyzer_event_listener_list *tmp = evt->info->listeners;
	while (tmp) {
		if (tmp->listener->process(tmp->listener->obj, evt) != POM_OK) {
			pomlog(POMLOG_ERR "Error while processing event %s for listener %s", evt->info->name, tmp->listener->name);
			return POM_ERR;
		}
		tmp = tmp->next;
	}

	return POM_OK;

}

