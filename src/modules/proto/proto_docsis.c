/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2011 Guy Martin <gmsoft@tuxicoman.be>
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
#include <pom-ng/ptype_uint8.h>

#include <string.h>
#include <stddef.h>
#include <arpa/inet.h>

#include "proto_docsis.h"

// ptype for fields value template
static struct ptype *ptype_bool = NULL, *ptype_uint8 = NULL;

struct mod_reg_info* proto_docsis_reg_info() {
	static struct mod_reg_info reg_info;
	memset(&reg_info, 0, sizeof(struct mod_reg_info));
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = proto_docsis_mod_register;
	reg_info.unregister_func = proto_docsis_mod_unregister;
	reg_info.dependencies = "ptype_bool, ptype_uint8";

	return &reg_info;
}


static int proto_docsis_mod_register(struct mod_reg *mod) {

	ptype_bool = ptype_alloc("bool");
	if (!ptype_bool)
		return POM_ERR;

	ptype_uint8 = ptype_alloc("uint8");
	if (!ptype_uint8) {
		ptype_cleanup(ptype_bool);
		return POM_ERR;
	}

	static struct proto_pkt_field fields[PROTO_DOCSIS_FIELD_NUM + 1];
	memset(fields, 0, sizeof(struct proto_pkt_field) * (PROTO_DOCSIS_FIELD_NUM + 1));
	fields[0].name = "fc_type";
	fields[0].value_template = ptype_uint8;
	fields[0].description = "Frame control type";
	fields[1].name = "fc_parm";
	fields[1].value_template = ptype_uint8;
	fields[1].description = "Frame parameters";
	fields[2].name = "ehdr_on";
	fields[2].value_template = ptype_bool;
	fields[2].description = "Extended header present";

	static struct proto_reg_info proto_docsis;
	memset(&proto_docsis, 0, sizeof(struct proto_reg_info));
	proto_docsis.name = "docsis";
	proto_docsis.api_ver = PROTO_API_VER;
	proto_docsis.mod = mod;
	proto_docsis.pkt_fields = fields;

	// No contrack here

	proto_docsis.init = proto_docsis_init;
	proto_docsis.process = proto_docsis_process;
	proto_docsis.cleanup = proto_docsis_cleanup;

	if (proto_register(&proto_docsis) == POM_OK)
		return POM_OK;


	return POM_ERR;

}


static int proto_docsis_init(struct proto *proto, struct registry_instance *i) {

	struct proto_docsis_priv *priv = malloc(sizeof(struct proto_docsis_priv));
	if (!priv) {
		pom_oom(sizeof(struct proto_docsis_priv));
		return POM_ERR;
	}
	memset(priv, 0, sizeof(struct proto_docsis_priv));

	proto->priv = priv;

	priv->proto_ethernet = proto_add_dependency("ethernet");
	priv->proto_docsis_mgmt = proto_add_dependency("docsis_mgmt");

	if (!priv->proto_ethernet || !priv->proto_docsis_mgmt) {
		proto_docsis_cleanup(proto);
		return POM_ERR;
	}


	return POM_OK;

}

static int proto_docsis_process(struct proto *proto, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct proto_docsis_priv *priv = proto->priv;
	struct proto_process_stack *s = &stack[stack_index];
	struct proto_process_stack *s_next = &stack[stack_index + 1];
	struct docsis_hdr *dhdr = s->pload;

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

		// Don't process crypted packets any further
		struct docsis_ehdr *ehdr = (struct docsis_ehdr*) (dhdr + offsetof(struct docsis_hdr, hcs));
		if (ehdr->eh_type == EH_TYPE_BP_DOWN || ehdr->eh_type == EH_TYPE_BP_DOWN)
			return PROTO_OK;
			
	}

	s_next->pload = s->pload + hdr_len;
	s_next->plen = s->plen - hdr_len;

	switch (dhdr->fc_type) {
		case FC_TYPE_PKT_MAC:
		case FC_TYPE_ISOLATION_PKT_MAC:
			// We don't need the 4 bytes of ethernet checksum
			s_next->plen -= 4;
			s_next->proto = priv->proto_ethernet->proto;
			break;
		case FC_TYPE_MAC_SPC:
			if (dhdr->fc_parm == FCP_MGMT) {
				s_next->proto = priv->proto_docsis_mgmt->proto;
				break;
			}
			break;

	}

	return PROTO_OK;

}

static int proto_docsis_cleanup(struct proto *proto) {

	if (proto->priv) {
		struct proto_docsis_priv *priv = proto->priv;

		if (priv->proto_ethernet)
			proto_remove_dependency(priv->proto_ethernet);
		if (priv->proto_docsis_mgmt)
			proto_remove_dependency(priv->proto_docsis_mgmt);

		free(priv);
	}

	return POM_OK;
}

static int proto_docsis_mod_unregister() {

	int res = proto_unregister("docsis");

	res += ptype_cleanup(ptype_bool);
	ptype_bool = NULL;
	res += ptype_cleanup(ptype_uint8);
	ptype_bool = NULL;

	return res;
}
