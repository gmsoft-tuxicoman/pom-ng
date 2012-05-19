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

#include <pom-ng/ptype.h>
#include <pom-ng/proto.h>
#include <pom-ng/ptype_string.h>
#include <pom-ng/ptype_mac.h>

#include "proto_ethernet.h"

#include <string.h>
#include <arpa/inet.h>

struct mod_reg_info* proto_ethernet_reg_info() {

	static struct mod_reg_info reg_info = { 0 };
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = proto_ethernet_mod_register;
	reg_info.unregister_func = proto_ethernet_mod_unregister;
	reg_info.dependencies = "ptype_string, ptype_mac";

	return &reg_info;
}

static int proto_ethernet_mod_register(struct mod_reg *mod) {

	static struct proto_pkt_field fields[PROTO_ETHERNET_FIELD_NUM + 1] = { { 0 } };
	fields[0].name = "src";
	fields[0].value_type = ptype_get_type("mac");
	fields[0].description = "Source address";
	fields[1].name = "dst";
	fields[1].value_type = ptype_get_type("mac");
	fields[1].description = "Destination address";

	static struct proto_reg_info proto_ethernet = { 0 };
	proto_ethernet.name = "ethernet";
	proto_ethernet.api_ver = PROTO_API_VER;
	proto_ethernet.mod = mod;
	proto_ethernet.pkt_fields = fields;

	// No contrack here

	proto_ethernet.init = proto_ethernet_init;
	proto_ethernet.process = proto_ethernet_process;
	proto_ethernet.cleanup = proto_ethernet_cleanup;

	if (proto_register(&proto_ethernet) == POM_OK)
		return POM_OK;


	return POM_ERR;

}


static int proto_ethernet_init(struct proto *proto, struct registry_instance *i) {
	
	struct proto_ethernet_priv *priv = malloc(sizeof(struct proto_ethernet_priv));
	if (!priv) {
		pom_oom(sizeof(struct proto_ethernet_priv));
		return POM_ERR;
	}
	memset(priv, 0, sizeof(struct proto_ethernet_priv));

	proto->priv = priv;

	priv->proto_ipv4 = proto_add_dependency("ipv4");
	priv->proto_ipv6 = proto_add_dependency("ipv6");
	priv->proto_arp = proto_add_dependency("arp");
	priv->proto_vlan = proto_add_dependency("vlan");
	priv->proto_pppoe = proto_add_dependency("pppoe");

	if (!priv->proto_ipv4 || !priv->proto_ipv6 || !priv->proto_arp || !priv->proto_vlan || !priv->proto_pppoe) {
		proto_ethernet_cleanup(proto);
		return POM_ERR;
	}


	return POM_OK;

}

static int proto_ethernet_process(struct proto *proto, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct proto_ethernet_priv *priv = proto->priv;
	struct proto_process_stack *s = &stack[stack_index];

	if (sizeof(struct ether_header) > s->plen)
		return PROTO_INVALID;

	struct ether_header *ehdr = s->pload;

	PTYPE_MAC_SETADDR(s->pkt_info->fields_value[proto_ethernet_field_src], ehdr->ether_shost);
	PTYPE_MAC_SETADDR(s->pkt_info->fields_value[proto_ethernet_field_dst], ehdr->ether_dhost);

	struct proto_process_stack *s_next = &stack[stack_index + 1];

	s_next->pload = s->pload + sizeof(struct ether_header);
	s_next->plen = s->plen - sizeof(struct ether_header);

	switch (ntohs(ehdr->ether_type)) {
		case 0x0800:
			s_next->proto = priv->proto_ipv4->proto;
			break;
		case 0x0806:
			s_next->proto = priv->proto_arp->proto;
			break;
		case 0x8100:
			s_next->proto = priv->proto_vlan->proto;
			break;
		case 0x86dd:
			s_next->proto = priv->proto_ipv6->proto;
			break;
		case 0x8863:
		case 0x8864:
			s_next->proto = priv->proto_pppoe->proto;

		default:
			s_next->proto = NULL;
			break;

	}

	return PROTO_OK;

}

static int proto_ethernet_cleanup(struct proto *proto) {

	if (proto->priv) {

		struct proto_ethernet_priv *priv = proto->priv;
		if (priv->proto_ipv4)
			proto_remove_dependency(priv->proto_ipv4);
		if (priv->proto_ipv6)
			proto_remove_dependency(priv->proto_ipv6);
		if (priv->proto_arp)
			proto_remove_dependency(priv->proto_arp);
		if (priv->proto_vlan)
			proto_remove_dependency(priv->proto_vlan);
		if (priv->proto_pppoe)
			proto_remove_dependency(priv->proto_pppoe);

		free(priv);
	}

	return POM_OK;
}

static int proto_ethernet_mod_unregister() {

	return proto_unregister("ethernet");
}
