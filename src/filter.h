/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2012-2014 Guy Martin <gmsoft@tuxicoman.be>
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


#ifndef __FILTER_H__
#define __FILTER_H__

#include <pom-ng/filter.h>
#include <pom-ng/event.h>
#include "core.h"

struct filter_proto {
	struct proto *proto; // If there is a proto, then it's a single match. Else it's a branch

	int op;
	struct filter_proto *a, *b;

	int field_id;
	struct ptype *value;
};


enum filter_evt_prop_type {
	filter_evt_prop_type_time,
	filter_evt_prop_type_name,
	filter_evt_prop_type_source,
	filter_evt_prop_type_descr,
};

struct filter_data {

	int op;
	char *op_str;
	char *name;
	char *key;

	int field_id;
	char *value_str;
	struct ptype *value;

};

enum filter_type {
	filter_type_payload,
	filter_type_event,
};

enum filter_node_type {
	filter_node_type_event_prop,
	filter_node_type_event_data,
	filter_node_type_pload_type,
	filter_node_type_pload_data,
	filter_node_type_proto,
	filter_node_type_branch
};

struct filter_branch {
	struct filter_node *a;
	struct filter_node *b;
	int op;
};

struct filter_node {

	enum filter_node_type type;
	union {
		struct filter_data data;
		struct filter_branch branch;
	};

	int not;

};


int filter_proto_match(struct proto_process_stack *stack, struct filter_proto *f);
int filter_proto_parse_block(char *expr, unsigned int len, struct filter_proto **f);

int filter_parse(char *expr, unsigned int len, struct filter_node **n, enum filter_type type);
int filter_parse_block(char *expr, unsigned int len, struct filter_node **n, enum filter_type type);
int filter_event_parse_block(char *expr, unsigned int len, struct filter_node *n);
int filter_pload_parse_block(char *expr, unsigned int len, struct filter_node *n);

void filter_cleanup(struct filter_node *filter);

int filter_event_compile(struct filter_node *filter, struct event_reg *evt);
int filter_event_match(struct filter_node *filter, struct event *evt);
int filter_event(char *filter_expr, struct event_reg *evt_reg, struct filter_node **filter);

#endif

