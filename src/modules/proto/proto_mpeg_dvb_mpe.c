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
#include <pom-ng/ptype_mac.h>

#include "proto_mpeg_dvb_mpe.h"

static struct proto *proto_ipv4 = NULL;

int proto_mpeg_dvb_mpe_init(struct proto *proto, struct registry_instance *i) {

	proto_ipv4 = proto_get("ipv4");
	if (!proto_ipv4)
		return POM_ERR;

	return POM_OK;
}

int proto_mpeg_dvb_mpe_process(struct proto *proto, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct proto_process_stack *s = &stack[stack_index];
	struct proto_process_stack *s_next = &stack[stack_index + 1];

	unsigned char *buff = s->pload;

	if (s->plen < 12)
		return PROTO_INVALID;

	// See ESTI EN 301 192 Table 3

	// Check reserved fields
	if ((buff[1] & 0x30) != 0x30 || (buff[5] & 0xC0) != 0xC0)
		return PROTO_INVALID;

	// Check length
	unsigned int len = (((buff[1] & 0xF) << 8) | buff[2]) + 3;
	if (len > s->plen)
		return PROTO_INVALID;

	// Check scrambling
	if (buff[5] & 0x3C) {
		// Packet is scrambled
		return PROTO_OK;
	}

	
	char mac[6];
	mac[0] = buff[11];
	mac[1] = buff[10];
	mac[2] = buff[9];
	mac[3] = buff[8];
	mac[4] = buff[4];
	mac[5] = buff[3];

	PTYPE_MAC_SETADDR(s->pkt_info->fields_value[proto_mpeg_dvb_mpe_field_dst], mac);

	if (buff[5] & 0x2) {
		// Payload is LLC SNAP
		// Not yet handled
		return PROTO_OK;
	}

	if (buff[7]) {
		// Fragmented payload not supported yet
		return PROTO_OK;

	}

	s_next->proto = proto_ipv4;
	s_next->pload = s->pload + 12;
	s_next->plen = s->plen - 12;

	return PROTO_OK;

}
