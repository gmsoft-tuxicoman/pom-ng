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

#ifndef __PROTO_MPEG_H__
#define __PROTO_MPEG_H__

#include <stdint.h>

#define MPEG_TS_LEN 188

#define MPEG_TS_DOCSIS_PID 0x1FFE
#define MPEG_TS_NULL_PID 0x1FFF

#define PROTO_MPEG_TS_FIELD_NUM 1

enum proto_mpeg_ts_fields {
	proto_mpeg_ts_field_pid,
};

struct mod_reg_info* proto_mpeg_reg_info();
static int proto_mpeg_mod_register(struct mod_reg *mod);
static int proto_mpeg_mod_unregister();

static int proto_mpeg_ts_init();
static ssize_t proto_mpeg_ts_parse(struct packet *p, struct proto_process_stack *stack, unsigned int stack_index);
static ssize_t proto_mpeg_ts_process(struct packet *p, struct proto_process_stack *stack, unsigned int stack_index, int hdr_len);
static int proto_mpeg_ts_cleanup();

#endif
