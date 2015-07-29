/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2011-2014 Guy Martin <gmsoft@tuxicoman.be>
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

// Indicate that the event generates a payload
#define EVENT_REG_FLAG_PAYLOAD		0x1

struct event_reg;
struct event;

struct event_reg_info {
	char *source_name;
	void *source_obj;
	char *name;
	char *description;
	struct data_reg *data_reg;
	unsigned int flags;
	int (*listeners_notify) (void *obj, struct event_reg *evt_reg, int has_listeners);
	int (*priv_cleanup) (void *priv);
	int (*cleanup) (struct event *evt);
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
int event_has_listener(struct event_reg *evt_reg);

int event_process(struct event *evt, struct proto_process_stack *stack, int stack_index, ptime ts);
int event_process_begin(struct event *evt, struct proto_process_stack *stack, int stack_index, ptime ts);
int event_process_end(struct event *evt);

int event_refcount_inc(struct event *evt);
int event_refcount_dec(struct event *evt);

struct event_reg_info *event_get_info(struct event *evt);
struct event_reg *event_get_reg(struct event *evt);
struct data *event_get_data(struct event *evt);
struct event_reg_info *event_reg_get_info(struct event_reg *evt_reg);
struct ptype *event_data_item_add(struct event *evt, unsigned int id, const char *key);
void *event_get_priv(struct event *evt);
void event_set_priv(struct event *evt, void *priv);
struct conntrack_entry *event_get_conntrack(struct event *evt);
unsigned int event_is_started(struct event *evt);
unsigned int event_is_done(struct event *evt);
ptime event_get_timestamp(struct event *evt);
#endif

