/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2014 Guy Martin <gmsoft@tuxicoman.be>
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


#include <rtp.h>
#include <pom-ng/ptype.h>
#include <pom-ng/proto.h>
#include <pom-ng/conntrack.h>
#include <pom-ng/ptype_uint8.h>
#include <pom-ng/ptype_uint16.h>
#include <pom-ng/ptype_uint32.h>
#include <arpa/inet.h>


#include "proto_rtp.h"

static struct ptype *param_conntrack_timeout = NULL;

struct mod_reg_info* proto_rtp_reg_info() {

	static struct mod_reg_info reg_info = { 0 };
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = proto_rtp_mod_register;
	reg_info.unregister_func = proto_rtp_mod_unregister;
	reg_info.dependencies = "ptype_uint16, ptype_uint32";

	return &reg_info;
}

static int proto_rtp_mod_register(struct mod_reg *mod) {

	static struct proto_reg_info proto_rtp = { 0 };
	proto_rtp.name = "rtp";
	proto_rtp.api_ver = PROTO_API_VER;
	proto_rtp.mod = mod;
	proto_rtp.number_class = "rtp";

	static struct proto_pkt_field fields[PROTO_RTP_FIELD_NUM + 1] = { { 0 } };
	fields[0].name = "pt";
	fields[0].value_type = ptype_get_type("uint8");
	fields[0].description = "Payload Type";
	fields[1].name = "ssrc";
	fields[1].value_type = ptype_get_type("uint32");
	fields[1].description = "Synchronization source";
	fields[2].name = "seq";
	fields[2].value_type = ptype_get_type("uint16");
	fields[2].description = "Sequence";
	fields[3].name = "ts";
	fields[3].value_type = ptype_get_type("uint32");
	fields[3].description = "Timestamp";
	proto_rtp.pkt_fields = fields;

	static struct conntrack_info ct_info = { 0 };
	ct_info.default_table_size = 8;
	ct_info.fwd_pkt_field_id = proto_rtp_field_ssrc;
	ct_info.rev_pkt_field_id = CONNTRACK_PKT_FIELD_NONE;
	proto_rtp.ct_info = &ct_info;

	proto_rtp.init = proto_rtp_init;
	proto_rtp.cleanup = proto_rtp_cleanup;
	proto_rtp.process = proto_rtp_process;

	if (proto_register(&proto_rtp) == POM_OK)
		return POM_OK;


	return POM_ERR;

}

static int proto_rtp_init(struct proto *proto, struct registry_instance *i) {

	param_conntrack_timeout = ptype_alloc_unit("uint32", "seconds");
	if (!param_conntrack_timeout)
		return POM_ERR;

	struct registry_param *p = registry_new_param("conntrack_timeout", "600", param_conntrack_timeout, "Timeout for RTP connections", 0);
	if (!p)
		goto err;
	if (proto_add_param(proto, p) != POM_OK)
		goto err;

	return POM_OK;
err:
	if (p)
		registry_cleanup_param(p);

	if (param_conntrack_timeout) {
		ptype_cleanup(param_conntrack_timeout);
		param_conntrack_timeout = NULL;
	}

	return POM_ERR;
}

static int proto_rtp_cleanup(void *proto_priv) {

	if (param_conntrack_timeout) {
		ptype_cleanup(param_conntrack_timeout);
		param_conntrack_timeout = NULL;
	}

	return POM_OK;
}

static int proto_rtp_process(void *proto_priv, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct proto_process_stack *s = &stack[stack_index];
	struct proto_process_stack *s_next = &stack[stack_index + 1];

	if (sizeof(struct rtphdr) > s->plen)
		return PROTO_INVALID;

	struct rtphdr *hdr = s->pload;

	if (hdr->version != 2)
		return PROTO_INVALID;

	size_t hdr_len = sizeof(struct rtphdr);
	hdr_len += hdr->csrc_count * 4;

	if (hdr_len > s->plen)
		return PROTO_INVALID;

	PTYPE_UINT8_SETVAL(s->pkt_info->fields_value[proto_rtp_field_pt], hdr->payload_type);
	PTYPE_UINT32_SETVAL(s->pkt_info->fields_value[proto_rtp_field_ssrc], hdr->ssrc);
	PTYPE_UINT16_SETVAL(s->pkt_info->fields_value[proto_rtp_field_seq], ntohs(hdr->seq_num));
	PTYPE_UINT32_SETVAL(s->pkt_info->fields_value[proto_rtp_field_timestamp], ntohl(hdr->timestamp));

	if (conntrack_get(stack, stack_index) != POM_OK)
		return POM_ERR;

	conntrack_unlock(s->ce);

	if (hdr->extension) {
		struct rtphdrext *exthdr;
		exthdr = s->pload + hdr_len;
		size_t extlen = ntohs(exthdr->length);
		if (s->plen < hdr_len + sizeof(struct rtphdrext) || hdr_len + extlen > s->plen)
			return PROTO_INVALID;

		hdr_len += extlen;
	}

	s_next->pload = s->pload + hdr_len;
	s_next->plen = s->plen - hdr_len;

	if (hdr->padding) {
		// The last padding byte indicate the number of padded bytes
		uint8_t pad_len = *((uint8_t*) (s->pload + s->plen - 1));
		if (pad_len > s_next->plen)
			return PROTO_INVALID;
		s_next->plen -= pad_len;
	}

	return PROTO_OK;

}

static int proto_rtp_mod_unregister() {

	return proto_unregister("rtp");
}
