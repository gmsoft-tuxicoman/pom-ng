/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2011-2013 Guy Martin <gmsoft@tuxicoman.be>
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
#include <pom-ng/ptype_bool.h>
#include <pom-ng/ptype_mac.h>
#include <pom-ng/ptype_uint8.h>

#include <string.h>
#include <stddef.h>
#include <arpa/inet.h>

#include "proto_docsis.h"

struct mod_reg_info* proto_docsis_reg_info() {

	static struct mod_reg_info reg_info = { 0 };
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = proto_docsis_mod_register;
	reg_info.unregister_func = proto_docsis_mod_unregister;
	reg_info.dependencies = "proto_ethernet, ptype_bool, ptype_mac, ptype_uint8";

	return &reg_info;
}


static int proto_docsis_mod_register(struct mod_reg *mod) {


	static struct proto_pkt_field docsis_mgmt_fields[PROTO_DOCSIS_MGMT_FIELD_NUM + 1] = { { 0 } };
	docsis_mgmt_fields[0].name = "src";
	docsis_mgmt_fields[0].value_type = ptype_get_type("mac");
	docsis_mgmt_fields[0].description = "Source address";
	docsis_mgmt_fields[1].name = "dst";
	docsis_mgmt_fields[1].value_type = ptype_get_type("mac");
	docsis_mgmt_fields[1].description = "Destination address";
	docsis_mgmt_fields[2].name = "dsap";
	docsis_mgmt_fields[2].value_type = ptype_get_type("uint8");
	docsis_mgmt_fields[2].description = "DSAP";
	docsis_mgmt_fields[3].name = "ssap";
	docsis_mgmt_fields[3].value_type = ptype_get_type("uint8");
	docsis_mgmt_fields[3].description = "SSAP";
	docsis_mgmt_fields[4].name = "control";
	docsis_mgmt_fields[4].value_type = ptype_get_type("uint8");
	docsis_mgmt_fields[4].description = "Control";
	docsis_mgmt_fields[5].name = "version";
	docsis_mgmt_fields[5].value_type = ptype_get_type("uint8");
	docsis_mgmt_fields[5].description = "Version";
	docsis_mgmt_fields[6].name = "type";
	docsis_mgmt_fields[6].value_type = ptype_get_type("uint8");
	docsis_mgmt_fields[6].description = "Type";

	static struct proto_reg_info proto_docsis_mgmt = { 0 };
	proto_docsis_mgmt.name = "docsis_mgmt";
	proto_docsis_mgmt.api_ver = PROTO_API_VER;
	proto_docsis_mgmt.mod = mod;
	proto_docsis_mgmt.pkt_fields = docsis_mgmt_fields;
	proto_docsis_mgmt.process = proto_docsis_mgmt_process;

	if (proto_register(&proto_docsis_mgmt) != PROTO_OK)
		return POM_ERR;

	static struct proto_pkt_field docsis_fields[PROTO_DOCSIS_FIELD_NUM + 1] = { { 0 } };
	docsis_fields[0].name = "fc_type";
	docsis_fields[0].value_type = ptype_get_type("uint8");
	docsis_fields[0].description = "Frame control type";
	docsis_fields[1].name = "fc_parm";
	docsis_fields[1].value_type = ptype_get_type("uint8");
	docsis_fields[1].description = "Frame parameters";
	docsis_fields[2].name = "ehdr_on";
	docsis_fields[2].value_type = ptype_get_type("bool");
	docsis_fields[2].description = "Extended header present";
	docsis_fields[3].name = "crypted";
	docsis_fields[3].value_type = ptype_get_type("bool");
	docsis_fields[3].description = "Packet encrypted";

	static struct proto_reg_info proto_docsis = { 0 };
	proto_docsis.name = "docsis";
	proto_docsis.api_ver = PROTO_API_VER;
	proto_docsis.mod = mod;
	proto_docsis.pkt_fields = docsis_fields;
	proto_docsis.init = proto_docsis_init;
	proto_docsis.cleanup = proto_docsis_cleanup;
	proto_docsis.process = proto_docsis_process;

	if (proto_register(&proto_docsis) != POM_OK) {
		proto_unregister("docsis_mgmt");
		return POM_ERR;
	}

	return POM_OK;
}

static int proto_docsis_mod_unregister() {

	int res = POM_OK;
	res += proto_unregister("docsis");
	res += proto_unregister("docsis_mgmt");

	return (res == POM_OK ? POM_OK : POM_ERR);
}

static int proto_docsis_init(struct proto *proto, struct registry_instance *i) {

	if (proto_number_register("ppp", 0x4009, proto) != POM_OK)
		return POM_ERR;

	struct proto_docsis_priv *priv = malloc(sizeof(struct proto_docsis_priv));
	if (!priv) {
		pom_oom(sizeof(struct proto_docsis_priv));
		return POM_ERR;
	}
	memset(priv, 0, sizeof(struct proto_docsis_priv));
	proto_set_priv(proto, priv);

	priv->p_filter_docsis3 = ptype_alloc("bool");
	if (!priv->p_filter_docsis3)
		return POM_ERR;

	struct registry_param *p = registry_new_param("filter_docsis3", "yes", priv->p_filter_docsis3, "Filter DOCSIS 3 packets sent on multiple streams", 0);
	if (proto_add_param(proto, p) != POM_OK)
		return POM_ERR;


	priv->proto_ethernet = proto_get("ethernet");
	priv->proto_docsis_mgmt = proto_get("docsis_mgmt");
	priv->perf_encrypted_pkts = registry_instance_add_perf(i, "encrypted_pkts", registry_perf_type_counter, "Number of encrypted packets", "pkts");
	priv->perf_encrypted_bytes = registry_instance_add_perf(i, "encrypted_bytes", registry_perf_type_counter, "Number of bytes in encrypted packets", "bytes");

	if (!priv->proto_ethernet || !priv->proto_docsis_mgmt || !priv->perf_encrypted_pkts || !priv->perf_encrypted_bytes) {
		free(priv);
		return POM_ERR;
	}

	return POM_OK;

}

static int proto_docsis_cleanup(void *proto_priv) {

	if (proto_priv)
		free(proto_priv);
	
	return POM_OK;
}

static int proto_docsis_process(void *proto_priv, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct proto_process_stack *s = &stack[stack_index];
	struct proto_process_stack *s_next = &stack[stack_index + 1];
	struct docsis_hdr *dhdr = s->pload;
	struct proto_docsis_priv *priv = proto_priv;

	if (s->plen < sizeof(struct docsis_hdr) || ntohs(dhdr->len) > s->plen)
		return PROTO_INVALID;

	uint16_t hdr_len = sizeof(struct docsis_hdr);


	PTYPE_UINT8_SETVAL(s->pkt_info->fields_value[proto_docsis_field_fc_type], dhdr->fc_type);
	PTYPE_UINT8_SETVAL(s->pkt_info->fields_value[proto_docsis_field_fc_parm], dhdr->fc_parm);
	PTYPE_BOOL_SETVAL(s->pkt_info->fields_value[proto_docsis_field_ehdr_on], dhdr->ehdr_on);

	if (dhdr->ehdr_on) {
		
		if (dhdr->mac_parm > ntohs(dhdr->len))
			return PROTO_INVALID;

		hdr_len += dhdr->mac_parm;

		uint8_t ehdr_len = dhdr->mac_parm;

		void *ehdr_p = (s->pload + offsetof(struct docsis_hdr, hcs));

		while (ehdr_len) {

			struct docsis_ehdr *ehdr = ehdr_p;

			if (ehdr->eh_len > ehdr_len)
				return PROTO_INVALID;

			if (ehdr->eh_type == EH_TYPE_BP_DOWN || ehdr->eh_type == EH_TYPE_BP_UP) {
				registry_perf_inc(priv->perf_encrypted_pkts, 1);
				registry_perf_inc(priv->perf_encrypted_bytes, s->plen);
				PTYPE_BOOL_SETVAL(s->pkt_info->fields_value[proto_docsis_field_crypted], 1);
				return PROTO_OK;
			}

			if (ehdr->eh_type == EH_TYPE_DOWN_SVC && ehdr->eh_len == 5 && *PTYPE_BOOL_GETVAL(priv->p_filter_docsis3)) {
				return PROTO_STOP;
			}

			ehdr_len -= ehdr->eh_len + 1;
			ehdr_p += ehdr->eh_len + 1;

		}
			
	}

	// Encryption is not enabled
	PTYPE_BOOL_SETVAL(s->pkt_info->fields_value[proto_docsis_field_crypted], 0);

	s_next->pload = s->pload + hdr_len;
	s_next->plen = s->plen - hdr_len;

	switch (dhdr->fc_type) {
		case FC_TYPE_PKT_MAC:
		case FC_TYPE_ISOLATION_PKT_MAC:

			// 2 ethernet addresses + type + hcs
			if (s_next->plen < 6 + 6 + 2 +4)
				return PROTO_INVALID;

			// We don't need the 4 bytes of ethernet checksum
			s_next->plen -= 4;
			s_next->proto = priv->proto_ethernet;
			break;
		case FC_TYPE_MAC_SPC:
			if (dhdr->fc_parm == FCP_MGMT) {
				s_next->proto = priv->proto_docsis_mgmt;
				break;
			}
			break;
		default:
			s_next->proto = NULL;
			break;

	}

#ifdef FIX_PACKET_ALIGNMENT

	if (!s_next->proto)
		return PROTO_OK;

	char offset = (int)s_next->pload & 3;
	if (offset != 2) {
		struct packet_multipart *tmp = packet_multipart_alloc(s_next->proto, 0, 2);
		if (packet_multipart_add_packet(tmp, p, 0, s->plen, s_next->pload - p->buff) != POM_OK) {
			packet_multipart_cleanup(tmp);
			return PROTO_ERR;
		}
		if (packet_multipart_process(tmp, stack, stack_index + 1) != POM_OK)
			return PROTO_ERR;
		return PROTO_STOP;
	}
#endif

	return PROTO_OK;

}

static int proto_docsis_mgmt_process(void *proto_priv, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct proto_process_stack *s = &stack[stack_index];
	struct proto_process_stack *s_next = &stack[stack_index + 1];
	struct docsis_mgmt_hdr *dmhdr = s->pload;

	if ((s->plen < sizeof(struct docsis_mgmt_hdr) + (sizeof(uint16_t))) ||
		(ntohs(dmhdr->len) + offsetof(struct docsis_mgmt_hdr, dsap) + (sizeof(uint16_t)) > s->plen))
		return PROTO_INVALID;

	s_next->pload = s->pload + sizeof(struct docsis_mgmt_hdr);
	s_next->plen = ntohs(dmhdr->len) - (sizeof(struct docsis_mgmt_hdr) - offsetof(struct docsis_mgmt_hdr, dsap));

	PTYPE_MAC_SETADDR(s->pkt_info->fields_value[proto_docsis_mgmt_field_src], dmhdr->saddr);
	PTYPE_MAC_SETADDR(s->pkt_info->fields_value[proto_docsis_mgmt_field_dst], dmhdr->daddr);
	PTYPE_UINT8_SETVAL(s->pkt_info->fields_value[proto_docsis_mgmt_field_dsap], dmhdr->dsap);
	PTYPE_UINT8_SETVAL(s->pkt_info->fields_value[proto_docsis_mgmt_field_ssap], dmhdr->ssap);
	PTYPE_UINT8_SETVAL(s->pkt_info->fields_value[proto_docsis_mgmt_field_control], dmhdr->control);
	PTYPE_UINT8_SETVAL(s->pkt_info->fields_value[proto_docsis_mgmt_field_version], dmhdr->version);
	PTYPE_UINT8_SETVAL(s->pkt_info->fields_value[proto_docsis_mgmt_field_type], dmhdr->type);

	return PROTO_OK;
}
