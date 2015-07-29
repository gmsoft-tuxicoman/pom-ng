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

#ifndef __EVENT_H__
#define __EVENT_H__

#define EVENT_REGISTRY "event"

#include <pom-ng/event.h>
#include <uthash.h>

// Indicate that the event processing has started
#define EVENT_FLAG_PROCESS_BEGAN	0x1
// Indicate that the event processing is done
#define EVENT_FLAG_PROCESS_DONE		0x2

struct event {
	struct event_reg *reg;
	unsigned int flags;
	struct conntrack_entry *ce;
	void *priv;
	unsigned int refcount;
	struct data *data;
	ptime ts;

	struct event_listener* tmp_listeners;
};

struct event_reg {

	struct event_reg_info *info;
	struct event_listener *listeners;
	struct event_reg *prev, *next;
	struct event_reg_events *evts;
	struct registry_instance *reg_instance;
	struct registry_perf *perf_listeners;
	struct registry_perf *perf_ongoing;
	struct registry_perf *perf_processed;
	pthread_mutex_t evts_lock;
};

struct event_reg_events {

	struct event *evt;
	UT_hash_handle hh;
};

struct event_listener {
	void *obj;
	int (*process_begin) (struct event *evt, void *obj, struct proto_process_stack *stack, unsigned int stack_index);
	int (*process_end) (struct event *evt, void *obj);

	struct event_listener *prev, *next;
};

int event_init();
int event_finish();
int event_add_listener(struct event *evt, void *obj, int (*process_begin) (struct event *evt, void *obj, struct proto_process_stack *stack, unsigned int stack_index), int (*process_end) (struct event *evt, void *obj));

#endif
