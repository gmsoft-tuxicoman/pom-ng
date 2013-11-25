/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2013 Guy Martin <gmsoft@tuxicoman.be>
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

#ifndef __PROTO_PPP_H__
#define __PROTO_PPP_H__

#include <stdint.h>

struct gre_header
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t flg_recur_ctrl:3;
	uint8_t flg_strict_src_route:1;
	uint8_t flg_seq:1;
	uint8_t flg_key:1;
	uint8_t flg_routing:1;
	uint8_t flg_cksum:1;

	uint8_t version:3;
	uint8_t flags:4;
	uint8_t flg_ack:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t flg_cksum:1;
	uint8_t flg_routing:1;
	uint8_t flg_key:1;
	uint8_t flg_seq:1;
	uint8_t flg_strict_src_route:1;
	uint8_t flg_recur_ctrl:3;

	uint8_t flg_ack:1;
	uint8_t flags:4;
	uint8_t version:3;
#else
# error "Please fix <endian.h>"
#endif  

	uint16_t proto;

} __attribute__ ((__packed__));

struct gre_routing_header
{
	uint16_t addr_family;
	uint8_t offset;
	uint8_t len;
} __attribute__ ((__packed__));

struct mod_reg_info* proto_gre_reg_info();
static int proto_gre_init(struct proto *proto, struct registry_instance *i);
static int proto_gre_mod_register(struct mod_reg *mod);
static int proto_gre_process(void *proto_priv, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index);
static int proto_gre_mod_unregister();

#endif
