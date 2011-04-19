/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2010 Guy Martin <gmsoft@tuxicoman.be>
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
#include <pom-ng/conntrack.h>
#include <pom-ng/registry.h>

// Current proto API version
#define PROTO_API_VER	1


#define PROTO_FLAG_HAS_CONNTRACK	0x1

#define PROTO_OK	0
#define PROTO_ERR	-1
#define PROTO_STOP	-2
#define PROTO_INVALID	-3


// Full decl is private
struct proto_reg;

struct proto_dependency {
	char *name;
	unsigned int refcount;
	struct proto_reg *proto;
	struct proto_dependency *next, *prev;
};

struct proto_process_stack {
	struct proto_reg *proto;
	void *pload;
	uint32_t plen;

	struct packet_info *pkt_info;

	struct conntrack_entry *ce;

};

// Packet needs process_stack
#include <pom-ng/packet.h>

struct proto_pkt_field {
	char *name;
	struct ptype *value_template;
	char *description;

};

struct proto_reg_info {

	unsigned int api_ver;
	char *name;
	struct mod_reg *mod;
	struct proto_pkt_field *pkt_fields;
	struct conntrack_info ct_info;

	int (*init) (struct registry_instance *i);
	int (*process) (struct packet *p, struct proto_process_stack *s, unsigned int stack_index);
	int (*cleanup) ();

};


/// Register a new protocol
int proto_register(struct proto_reg_info *reg);

/// Process the packet
int proto_process(struct packet *p, struct proto_process_stack *s, unsigned int stack_index);

/// Unregister a protocol
int proto_unregister(char *name);

/// Get a dependency for a specific protocol
struct proto_dependency *proto_add_dependency(char *dep);

/// Release a dependency record
int proto_remove_dependency(struct proto_dependency *dep);
#endif
