/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2010-2013 Guy Martin <gmsoft@tuxicoman.be>
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

#ifndef __PROTO_IPV6_H__
#define __PROTO_IPV6_H__

#include <stdint.h>
#include <pom-ng/proto.h>

#define PROTO_IPV6_FLAG_GOT_LAST	0x1
#define PROTO_IPV6_FLAG_PROCESSED	0x2


#define PROTO_IPV6_FIELD_NUM 4

enum proto_ipv6_fields {
	proto_ipv6_field_src = 0,
	proto_ipv6_field_dst,
	proto_ipv6_field_hlim,

};

struct proto_ipv6_fragment {

	uint32_t id;
	unsigned int count;
	struct packet_multipart *multipart;
	unsigned int flags;
	struct conntrack_timer *t;
	struct proto_ipv6_fragment *prev, *next;
	uint8_t nxthdr;
};


struct mod_reg_info* proto_ipv6_reg_info();
static int proto_ipv6_init(struct proto *proto, struct registry_instance *i);
static int proto_ipv6_mod_register(struct mod_reg *mod);
static int proto_ipv6_process(void *proto_priv, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index);
static int proto_ipv6_fragment_cleanup(struct conntrack_entry *ce, void *priv);
static int proto_ipv6_conntrack_cleanup(void *ce_priv);
static int proto_ipv6_cleanup(void *proto_priv);
static int proto_ipv6_mod_unregister();

#endif
