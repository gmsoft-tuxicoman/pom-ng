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

#ifndef __PROTO_TCP_H__
#define __PROTO_TCP_H__

#include <stdint.h>

#define PROTO_TCP_FIELD_NUM 5

enum proto_tcp_fields {
	proto_tcp_field_sport = 0,
	proto_tcp_field_dport,
	proto_tcp_field_flags,
	proto_tcp_field_seq,
	proto_tcp_field_ack,
	proto_tcp_field_win,
};

struct mod_reg_info* proto_tcp_reg_info();
static int proto_tcp_init();
static int proto_tcp_mod_register(struct mod_reg *mod);
static size_t proto_tcp_parse(struct packet *p, struct proto_process_stack *stack, unsigned int stack_index);
static int proto_tcp_cleanup();
static int proto_tcp_mod_unregister();

#endif
