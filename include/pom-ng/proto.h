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
#include <pom-ng/packet.h>

#include <stdint.h>

// Current proto API version
#define PROTO_API_VER	1


#define PROTO_FLAG_HAS_CONNTRACK	0x1

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
	size_t plen;

	struct packet_info *pkt_info;

	struct proto_conntrack_entry *ce;

	struct ptype *ct_field_fwd;
	struct ptype *ct_field_rev;
};

struct proto_conntrack_entry {

	uint32_t fwd_hash, rev_hash; ///< Full hash prior to modulo
	struct ptype *fwd_value, *rev_value;
	char *buff;
	size_t buffsize;
};

struct proto_conntrack_list {
	struct proto_conntrack_entry *ce; ///< Corresponding connection
	struct proto_conntrack_list *prev, *next; ///< Next and previous connection in the list
	struct proto_conntrack_list *rev; ///< Reverse connection
};

struct proto_pkt_field {
	char *name;
	struct ptype *value_template;
	char *description;

};

struct proto_ct_info {
	unsigned int default_table_size;
	int fwd_pkt_field_id, rev_pkt_field_id;

};

struct proto_reg_info {

	unsigned int api_ver;
	char *name;
	struct mod_reg *mod;
	struct proto_pkt_field *pkt_fields;
	struct proto_ct_info ct_info;

	int (*init) ();
	size_t (*parse) (struct packet *p, struct proto_process_stack *s, unsigned int stack_index);
	int (*cleanup) ();

};


/// Register a new protocol
int proto_register(struct proto_reg_info *reg);

/// Process part of a packet with a protocol
int proto_parse(struct packet *p, struct proto_process_stack *s, unsigned int stack_index);

/// Unregister a protocol
int proto_unregister(char *name);

/// Get a dependency for a specific protocol
struct proto_dependency *proto_add_dependency(char *dep);

/// Release a dependency record
int proto_remove_dependency(struct proto_dependency *dep);
#endif
