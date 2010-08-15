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

// Current proto API version
#define PROTO_API_VER	1

// Full decl is private
struct proto_reg;

struct proto_dependency {
	char *name;
	unsigned int refcount;
	struct proto_reg *proto;
	struct proto_dependency *next, *prev;
};

struct proto_process_state {
	// Set before calling process
	void *pload;
	size_t plen;

	// Set by the processing function
	size_t processed_size;
	struct proto_reg *next_proto;

};

struct proto_reg_info {

	unsigned int api_ver;
	char *name;
	struct mod_reg *mod;

	int (*init) ();
	size_t (*process) (struct packet *p, struct proto_process_state *s);
	int (*cleanup) ();

};


/// Register a new protocol
int proto_register(struct proto_reg_info *reg);

/// Process part of a packet with a protocol
int proto_process(struct proto_reg *proto, struct packet *p, struct proto_process_state *s);

/// Unregister a protocol
int proto_unregister(char *name);

/// Get a dependency for a specific protocol
struct proto_dependency *proto_add_dependency(char *dep);

/// Release a dependency record
int proto_remove_dependency(struct proto_dependency *dep);
#endif
