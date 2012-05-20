/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2011-2012 Guy Martin <gmsoft@tuxicoman.be>
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


#include <pom-ng/proto.h>
#include <pom-ng/ptype_uint8.h>

#include "proto_mpeg_sect.h"

static struct proto *proto_mpeg_dvb_mpe = NULL;

int proto_mpeg_sect_init(struct proto *proto, struct registry_instance *i) {

	proto_mpeg_dvb_mpe = proto_get("mpeg_dvb_mpe");
	if (!proto_mpeg_dvb_mpe)
		return POM_ERR;

	return POM_OK;
}

int proto_mpeg_sect_process(struct proto *proto, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct proto_process_stack *s = &stack[stack_index];
	struct proto_process_stack *s_next = &stack[stack_index + 1];

	unsigned char *buff = s->pload;

	if (s->plen < 3)
		return PROTO_INVALID;

	unsigned int len = (((buff[1] & 0xF) << 8) | buff[2]) + 3;
	if (len > s->plen)
		return PROTO_INVALID;

	PTYPE_UINT8_SETVAL(s->pkt_info->fields_value[proto_mpeg_sect_field_table_id], buff[0]);

	// We usually pass the whole payload including the table_id
	switch (buff[0]) {
		case 0x3E: // ETSI EN 301 192 | ISO 13818-6 (DVB MPE)
			s_next->proto = proto_mpeg_dvb_mpe;
			s_next->pload = s->pload;
			s_next->plen = s->plen;
			break;
	}


	return PROTO_OK;

}

