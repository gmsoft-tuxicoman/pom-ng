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


#ifndef __POM_NG_EVENT_H__
#define __POM_NG_EVENT_H__

#include <pom-ng/proto.h>
#include <pom-ng/conntrack.h>
#include <pom-ng/data.h>

// Indicate that the event processing has started
#define EVENT_FLAG_PROCESS_BEGAN	0x1
// Indicate that the event processing is done
#define EVENT_FLAG_PROCESS_DONE		0x2

// Indicate that the event generates a payload
#define EVENT_REG_FLAG_PAYLOAD		0x1

struct event {
	struct event_reg *reg;
	unsigned int flags;
	struct conntrack_entry *ce;
	void *priv;
	unsigned int refcount;
	struct data *data;

	struct event_listener* tmp_listeners;
};

struct event_reg_info {
	char *source_name;
	void *source_obj;
	char *name;
	char *description;
	struct data_reg *data_reg;
	unsigned int flags;
	int (*listeners_notify) (void *obj, struct event_reg *evt_reg, int has_listeners);
	int (*cleanup) (struct event *evt);
};

struct event_reg {
	struct event_reg_info *info;
	struct event_listener *listeners;
	struct event_reg *prev, *next;
};

struct event_reg *event_register(struct event_reg_info *reg_info);
int event_unregister(struct event_reg *evt);

struct event *event_alloc(struct event_reg *evt_reg);
int event_cleanup(struct event *evt);

struct event_reg *event_find(const char *name);

int event_payload_listen_start();
int event_payload_listen_stop();

int event_listener_register(struct event_reg *evt_reg, void *obj, int (*process_begin) (struct event *evt, void *obj, struct proto_process_stack *stack, unsigned int stack_index), int (*process_end) (struct event *evt, void *obj));
int event_listener_unregister(struct event_reg *evt_reg, void *obj);
int event_add_listener(struct event *evt, void *obj, int (*process_begin) (struct event *evt, void *obj, struct proto_process_stack *stack, unsigned int stack_index), int (*process_end) (struct event *evt, void *obj));
int event_has_listener(struct event_reg *evt_reg);

int event_process(struct event *evt, struct proto_process_stack *stack, int stack_index);
int event_process_begin(struct event *evt, struct proto_process_stack *stack, int stack_index);
int event_process_end(struct event *evt);

int event_refcount_inc(struct event *evt);
int event_refcount_dec(struct event *evt);

#endif

