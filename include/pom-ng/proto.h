/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2010-2012 Guy Martin <gmsoft@tuxicoman.be>
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


#ifndef __POM_NG_PROTO_H__
#define __POM_NG_PROTO_H__

#include <pom-ng/base.h>
#include <pom-ng/mod.h>
#include <pom-ng/ptype.h>
#include <pom-ng/packet.h>
#include <pom-ng/registry.h>

// Current proto API version
#define PROTO_API_VER	1

// The listener needs the payload of the specified protocol
#define PROTO_PACKET_LISTENER_PLOAD_ONLY	0x2


// Error code definition
#define PROTO_OK	0
#define PROTO_ERR	-1
#define PROTO_STOP	-2
#define PROTO_INVALID	-3

struct proto {

	struct proto_reg_info *info;
	
	/// Conntrack tables
	struct conntrack_tables *ct;

	// Packet info pool
	struct packet_info_pool pkt_info_pool;

	struct registry_instance *reg_instance;

	void *priv;

	struct proto_packet_listener *packet_listeners;
	struct proto_packet_listener *payload_listeners;

	pthread_rwlock_t expectation_lock;
	struct proto_expectation *expectations;

	struct proto *next, *prev;

};

struct proto_process_stack {
	struct proto *proto;
	void *pload;
	uint32_t plen;
	int direction; // Used to pass direction to the next proto if he can't find out

	struct packet_info *pkt_info;

	struct conntrack_entry *ce;

};

struct proto_pkt_field {
	char *name;
	struct ptype_reg *value_type;
	char *description;

};

struct proto_reg_info {
	unsigned int api_ver;
	char *name;
	struct mod_reg *mod;
	struct proto_pkt_field *pkt_fields;
	struct conntrack_info *ct_info;
	struct proto_event_reg *events;

	int (*init) (struct proto *proto, struct registry_instance *i);
	int (*process) (struct proto *proto, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index);
	int (*post_process) (struct proto *proto, struct packet *p, struct proto_process_stack *s, unsigned int stack_index);
	int (*cleanup) (struct proto *proto);
};

struct proto_packet_listener {

	int flags;
	struct proto *proto;
	void *object;
	int (*process) (void *object, struct packet *p, struct proto_process_stack *s, unsigned int stack_index);
	struct filter_proto *filter;
	struct proto_packet_listener *prev, *next;
};

/// Register a new protocol
int proto_register(struct proto_reg_info *reg);

/// Process the packet
int proto_process(struct packet *p, struct proto_process_stack *s, unsigned int stack_index);

/// Post process the packet
int proto_post_process(struct packet *p, struct proto_process_stack *s, unsigned int stack_index);

/// Unregister a protocol
int proto_unregister(char *name);

/// Get a struct proto from the name
struct proto *proto_get(char *name);

// Register a packet listener
struct proto_packet_listener *proto_packet_listener_register(struct proto *proto, unsigned int flags, void *object,  int (*process) (void *object, struct packet *p, struct proto_process_stack *s, unsigned int stack_index));

// Unregister a packet listener
int proto_packet_listener_unregister(struct proto_packet_listener *l);

// Set a filter on a packet listener
void proto_packet_listener_set_filter(struct proto_packet_listener *l, struct filter_proto *f);



struct proto_expectation *proto_expectation_alloc(struct proto *proto, void *priv);
int proto_expectation_append(struct proto_expectation *e, struct proto *p, struct ptype *fwd_value, struct ptype *rev_value);
int proto_expectation_prepend(struct proto_expectation *e, struct proto *p, struct ptype *fwd_value, struct ptype *rev_value);
struct proto_expectation *proto_expectation_alloc_from_conntrack(struct conntrack_entry *ce, struct proto *proto, void *priv);
void proto_expectation_cleanup(struct proto_expectation *e);
int proto_expectation_set_field(struct proto_expectation *e, int stack_index, struct ptype *value, int direction);
int proto_expectation_add(struct proto_expectation *e);

#endif
