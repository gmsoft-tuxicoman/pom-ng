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

#include <pom-ng/ptype.h>
#include <pom-ng/proto.h>
#include <pom-ng/ptype_uint16.h>

#include "proto_mpeg.h"

#include <string.h>
#include <arpa/inet.h>


static struct proto_dependency *proto_docsis = NULL;

// ptype for fields value template
static struct ptype *ptype_uint16 = NULL;

struct mod_reg_info* proto_mpeg_reg_info() {

	static struct mod_reg_info reg_info;
	memset(&reg_info, 0, sizeof(struct mod_reg_info));
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = proto_mpeg_mod_register;
	reg_info.unregister_func = proto_mpeg_mod_unregister;

	return &reg_info;
}


static int proto_mpeg_mod_register(struct mod_reg *mod) {

	ptype_uint16 = ptype_alloc("uint16");
	if (!ptype_uint16)
		return POM_ERR;
	
	ptype_uint16->flags |= PTYPE_UINT16_PRINT_HEX;

	static struct proto_pkt_field fields[PROTO_MPEG_TS_FIELD_NUM + 1];
	memset(fields, 0, sizeof(struct proto_pkt_field) * (PROTO_MPEG_TS_FIELD_NUM + 1));
	fields[0].name = "pid";
	fields[0].value_template = ptype_uint16;
	fields[0].description = "PID";

	static struct proto_reg_info proto_mpeg_ts;
	memset(&proto_mpeg_ts, 0, sizeof(struct proto_reg_info));
	proto_mpeg_ts.name = "mpeg_ts";
	proto_mpeg_ts.api_ver = PROTO_API_VER;
	proto_mpeg_ts.mod = mod;
	proto_mpeg_ts.pkt_fields = fields;

	// No contrack here

	proto_mpeg_ts.init = proto_mpeg_ts_init;
	proto_mpeg_ts.parse = proto_mpeg_ts_parse;
	proto_mpeg_ts.process = proto_mpeg_ts_process;
	proto_mpeg_ts.cleanup = proto_mpeg_ts_cleanup;

	if (proto_register(&proto_mpeg_ts) == POM_OK)
		return POM_OK;


	return POM_ERR;

}


static int proto_mpeg_ts_init() {


	proto_docsis = proto_add_dependency("docsis");

	if (!proto_docsis) {
		proto_mpeg_ts_cleanup();
		return POM_ERR;
	}


	return POM_OK;

}

static ssize_t proto_mpeg_ts_parse(struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct proto_process_stack *s = &stack[stack_index];
	unsigned char *buff = s->pload;

	uint16_t pid = ((buff[1] & 0x1F) << 8) | buff[2];

	PTYPE_UINT16_SETVAL(s->pkt_info->fields_value[proto_mpeg_ts_field_pid], pid);


	if (buff[1] & 0x40) { // Check PUSI
		if (buff[4] > 183)
			return PROTO_INVALID;
		return 5; // Header is 5 bytes long, including the unit start pointer
	}

	return 4; // Header is 4 bytes without the pointer

}

static ssize_t proto_mpeg_ts_process(struct packet *p, struct proto_process_stack *stack, unsigned int stack_index, int hdr_len) {

	struct proto_process_stack *s = &stack[stack_index];
	struct proto_process_stack *s_next = &stack[stack_index + 1];

	uint16_t *pid; PTYPE_UINT16_GETVAL(s->pkt_info->fields_value[proto_mpeg_ts_field_pid], pid);
	switch (*pid) {
		case MPEG_TS_DOCSIS_PID:
			s_next->proto = proto_docsis->proto;
			break;

		case MPEG_TS_NULL_PID: // No need to process NULL packets any further
			return PROTO_STOP;

		default:
			s_next->proto = NULL;
			break;

	}

	return s->plen - hdr_len;

}

static int proto_mpeg_ts_cleanup() {

	int res = POM_OK;

	res += proto_remove_dependency(proto_docsis);

	return res;
}

static int proto_mpeg_mod_unregister() {

	int res = proto_unregister("mpeg");

	ptype_cleanup(ptype_uint16);
	ptype_uint16 = NULL;

	return res;
}
