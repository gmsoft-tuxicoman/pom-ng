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

#ifndef __PROTO_PPPOE_H__
#define __PROTO_PPPOE_H__

#include <stdint.h>

struct pppoe_header
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t version:4;
	uint8_t type:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t type:4;
	uint8_t version:4;
#else
# error "Please fix <bits/endian.h>"
#endif
	uint8_t code;
	uint16_t session_id;
	uint16_t len;
} __attribute__ ((__packed__));

#define PROTO_PPPOE_FIELD_NUM 2

enum proto_pppoe_fields {
	proto_pppoe_field_code = 0,
	proto_pppoe_field_session_id,
};

struct mod_reg_info* proto_pppoe_reg_info();
static int proto_pppoe_init(struct proto *proto, struct registry_instance *i);
static int proto_pppoe_mod_register(struct mod_reg *mod);
static int proto_pppoe_process(struct proto *proto, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index);
static int proto_pppoe_mod_unregister();

#endif
