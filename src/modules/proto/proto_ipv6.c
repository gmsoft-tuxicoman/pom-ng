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
#include <pom-ng/conntrack.h>
#include <pom-ng/ptype_ipv6.h>
#include <pom-ng/ptype_uint8.h>
#include <pom-ng/ptype_uint32.h>

#include "proto_ipv6.h"

#ifndef BYTE_ORDER
#error Please define BYTE_ORDER
#endif

#include <netinet/ip6.h>

static struct proto *proto_icmp6 = NULL, *proto_tcp = NULL, *proto_udp = NULL;

static struct ptype *param_frag_timeout = NULL, *param_conntrack_timeout = NULL;

struct mod_reg_info* proto_ipv6_reg_info() {

	static struct mod_reg_info reg_info = { 0 };
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = proto_ipv6_mod_register;
	reg_info.unregister_func = proto_ipv6_mod_unregister;
	reg_info.dependencies = "proto_icmp6, proto_tcp, proto_udp, ptype_ipv6, ptype_uint8, ptype_uint32";

	return &reg_info;
}


static int proto_ipv6_mod_register(struct mod_reg *mod) {

	static struct proto_reg_info proto_ipv6 = { 0 };
	proto_ipv6.name = "ipv6";
	proto_ipv6.api_ver = PROTO_API_VER;
	proto_ipv6.mod = mod;

	static struct proto_pkt_field fields[PROTO_IPV6_FIELD_NUM + 1] = { { 0 } };
	fields[0].name = "src";
	fields[0].value_type = ptype_get_type("ipv6");
	fields[0].description = "Source address";
	fields[1].name = "dst";
	fields[1].value_type = ptype_get_type("ipv6");
	fields[1].description = "Destination address";
	fields[2].name = "hlim";
	fields[2].value_type = ptype_get_type("uint8");
	fields[2].description = "Hop limit";
	proto_ipv6.pkt_fields = fields;

	static struct conntrack_info ct_info = { 0 };
	ct_info.default_table_size = 20000;
	ct_info.fwd_pkt_field_id = proto_ipv6_field_src;
	ct_info.rev_pkt_field_id = proto_ipv6_field_dst;
	ct_info.cleanup_handler = proto_ipv6_conntrack_cleanup;
	proto_ipv6.ct_info = &ct_info;
	
	proto_ipv6.init = proto_ipv6_init;
	proto_ipv6.process = proto_ipv6_process;
	proto_ipv6.cleanup = proto_ipv6_cleanup;

	if (proto_register(&proto_ipv6) == POM_OK)
		return POM_OK;

	return POM_ERR;
}


static int proto_ipv6_init(struct proto *proto, struct registry_instance *i) {

	param_frag_timeout = ptype_alloc_unit("uint32", "seconds");
	if (!param_frag_timeout)
		return POM_ERR;

	param_conntrack_timeout = ptype_alloc_unit("uint32", "seconds");
	if (!param_conntrack_timeout)
		return POM_ERR;

	struct registry_param *p = registry_new_param("fragment_timeout", "60", param_frag_timeout, "Timeout for incomplete ipv6 fragments", 0);
	if (registry_instance_add_param(i, p) != POM_OK)
		goto err;

	p = registry_new_param("conntrack_timeout", "7200", param_conntrack_timeout, "Timeout for ipv6 connections", 0);
	if (registry_instance_add_param(i, p) != POM_OK)
		goto err;
	
	proto_icmp6 = proto_get("icmp6");
	proto_tcp = proto_get("tcp");
	proto_udp = proto_get("udp");

	if (!proto_icmp6 || !proto_tcp || !proto_udp) {
		proto_ipv6_cleanup(proto);
		return POM_ERR;
	}

	return POM_OK;

err:

	if (p)
		registry_cleanup_param(p);

	if (param_frag_timeout) {
		ptype_cleanup(param_frag_timeout);
		param_frag_timeout = NULL;
	}
	if (param_conntrack_timeout) {
		ptype_cleanup(param_conntrack_timeout);
		param_conntrack_timeout = NULL;
	}
	return POM_ERR;
}

static int proto_ipv6_process_fragment(struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct proto_process_stack *s = &stack[stack_index];
	struct proto_process_stack *s_next = &stack[stack_index + 1];

	struct proto_ipv6_fragment *tmp = s->ce->priv;

	struct ip6_frag *fhdr = s_next->pload;
	uint8_t nxthdr = fhdr->ip6f_nxt;

	void *frag_data = s_next->pload + sizeof(struct ip6_frag);
	size_t frag_len = s_next->plen - sizeof(struct ip6_frag);

	struct proto *next_proto = NULL;
	switch (fhdr->ip6f_nxt) {
		case IPPROTO_TCP: // 6
			next_proto = proto_tcp;
			break;

		case IPPROTO_UDP: // 17
			next_proto = proto_udp;
			break;

		case IPPROTO_ICMPV6: // 58
			next_proto = proto_icmp6;
			break;

	}

	// Don't bother processing unsupported protocols
	if (!next_proto)
		return PROTO_STOP;

	uint16_t frag_offset = ntohs(fhdr->ip6f_offlg & IP6F_OFF_MASK);
	int frag_more = fhdr->ip6f_offlg & IP6F_MORE_FRAG;

	// Let's find the right buffer
	for (; tmp && !(tmp->id == fhdr->ip6f_ident && tmp->nxthdr == nxthdr); tmp = tmp->next);

	if (!tmp) {
		// Buffer not found, create it
		tmp = malloc(sizeof(struct proto_ipv6_fragment));
		if (!tmp) {
			pom_oom(sizeof(struct proto_ipv6_fragment));
			return PROTO_ERR;
		}
		memset(tmp, 0, sizeof(struct proto_ipv6_fragment));

		tmp->t = conntrack_timer_alloc(s->ce, proto_ipv6_fragment_cleanup, tmp);
		if (!tmp->t) {
			free(tmp);
			return PROTO_ERR;
		}
		
		tmp->id = fhdr->ip6f_ident;
		tmp->nxthdr = nxthdr;
		tmp->multipart = packet_multipart_alloc(next_proto, 0);
		if (!tmp->multipart) {
			conntrack_timer_cleanup(tmp->t);
			free(tmp);
			return PROTO_ERR;
		}

		tmp->next = s->ce->priv;
		if (tmp->next)
			tmp->next->prev = tmp;
		s->ce->priv = tmp;
	}

	// Fragment was already handled
	if (tmp->flags & PROTO_IPV6_FLAG_PROCESSED) {
		return PROTO_STOP;
	}
	
	// Add the fragment
	if (packet_multipart_add_packet(tmp->multipart, p, frag_offset, frag_len, frag_data - p->buff) != POM_OK) {
		packet_multipart_cleanup(tmp->multipart);
		conntrack_timer_cleanup(tmp->t);
		free(tmp);
		return PROTO_ERR;
	}

	// Schedule the timeout for the fragment
	uint32_t *frag_timeout = PTYPE_UINT32_GETVAL(param_frag_timeout);
	conntrack_timer_queue(tmp->t, *frag_timeout);


	if (!frag_more)
		tmp->flags |= PROTO_IPV6_FLAG_GOT_LAST;

	if ((tmp->flags & PROTO_IPV6_FLAG_GOT_LAST) && !tmp->multipart->gaps)
		tmp->flags |= PROTO_IPV6_FLAG_PROCESSED;

	// We need to unlock the conntrack to avoid a deadlock when processing packets
	conntrack_unlock(s->ce);

	if ((tmp->flags & PROTO_IPV6_FLAG_PROCESSED)) {
		int res = packet_multipart_process(tmp->multipart, stack, stack_index + 1);
		tmp->multipart = NULL; // Multipart will be cleared automatically
		if (res == PROTO_ERR) {
			return PROTO_ERR;
		}
	}
	return PROTO_STOP; // Stop processing the packet

}

static int proto_ipv6_process(struct proto *proto, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct proto_process_stack *s = &stack[stack_index];
	struct proto_process_stack *s_next = &stack[stack_index + 1];

	if (s->plen < sizeof(struct ip6_hdr))
		return PROTO_INVALID;

	struct ip6_hdr* hdr = s->pload;

	if (sizeof(struct ip6_hdr) + ntohs(hdr->ip6_plen) > s->plen)
		return PROTO_INVALID;

	PTYPE_IPV6_SETADDR(s->pkt_info->fields_value[proto_ipv6_field_src], hdr->ip6_src);
	PTYPE_IPV6_SETADDR(s->pkt_info->fields_value[proto_ipv6_field_dst], hdr->ip6_dst);
	PTYPE_UINT8_SETVAL(s->pkt_info->fields_value[proto_ipv6_field_hlim], hdr->ip6_hlim);

	// Handle conntrack stuff
	if (conntrack_get(stack, stack_index) != POM_OK)
		return PROTO_ERR;


	s_next->pload = s->pload + sizeof(struct ip6_hdr);
	s_next->plen = ntohs(hdr->ip6_plen);

	if (s->ce->children) {
		if (conntrack_delayed_cleanup(s->ce, 0) != POM_OK) {
			conntrack_unlock(s->ce);
			return PROTO_ERR;
		}
	} else {
		uint32_t *conntrack_timeout = PTYPE_UINT32_GETVAL(param_conntrack_timeout);
		if (conntrack_delayed_cleanup(s->ce, *conntrack_timeout) != POM_OK) {
			conntrack_unlock(s->ce);
			return PROTO_ERR;
		}
	}

	uint8_t nhdr = hdr->ip6_nxt;
	int locked = 1;
	int done = 0;
	int res = PROTO_OK;
	while (!done) {

		switch (nhdr) {
			case IPPROTO_HOPOPTS: // 0
			case IPPROTO_ROUTING: // 43
			case IPPROTO_DSTOPTS: { // 60
				struct ip6_ext *ehdr;
				ehdr = s_next->pload;
				unsigned int ehlen = (ehdr->ip6e_len + 1) * 8;
				if (ehlen > s_next->plen)
					return PROTO_INVALID;
				s_next->pload += ehlen;
				s_next->plen -= ehlen;
				nhdr = ehdr->ip6e_nxt;
				break;
			}

			case IPPROTO_TCP: // 6
				done = 1;
				s_next->proto = proto_tcp;
				break;

			case IPPROTO_UDP: // 17
				done = 1;
				s_next->proto = proto_udp;
				break;

			case IPPROTO_ICMPV6: // 58
				done = 1;
				s_next->proto = proto_icmp6;
				break;

			case IPPROTO_FRAGMENT: // 44
				res = proto_ipv6_process_fragment(p, stack, stack_index);
				locked = 0;
				done = 1;
				break;


			case IPPROTO_NONE: // 59
			default:
				done = 1;
				break;

		}
	}

	if (locked)
		conntrack_unlock(s->ce);
	return res;
}

static int proto_ipv6_fragment_cleanup(struct conntrack_entry *ce, void *priv) {

	struct proto_ipv6_fragment *f = priv;

	// Remove the frag from the conntrack
	if (f->prev)
		f->prev->next = f->next;
	else
		ce->priv = f->next;

	if (f->next)
		f->next->prev = f->prev;


	if (!(f->flags & PROTO_IPV6_FLAG_PROCESSED))
		pomlog(POMLOG_DEBUG "Cleaning up unprocessed fragment");

	if (f->multipart)
		packet_multipart_cleanup(f->multipart);
	
	if (f->t)
		conntrack_timer_cleanup(f->t);
	
	free(f);

	return POM_OK;

}

static int proto_ipv6_conntrack_cleanup(void *ce_priv) {

	struct proto_ipv6_fragment *frag_list = ce_priv;

	while (frag_list) {
		struct proto_ipv6_fragment *f = frag_list;
		frag_list = f->next;

		if (!(f->flags & PROTO_IPV6_FLAG_PROCESSED))
			pomlog(POMLOG_DEBUG "Cleaning up unprocessed fragment");

		if (f->multipart)
			packet_multipart_cleanup(f->multipart);
		
		if (f->t)
			conntrack_timer_cleanup(f->t);
		
		free(f);

	}

	return POM_OK;
}

static int proto_ipv6_cleanup(struct proto *proto) {

	int res = POM_OK;

	res += ptype_cleanup(param_frag_timeout);
	res += ptype_cleanup(param_conntrack_timeout);

	return res;
}

static int proto_ipv6_mod_unregister() {

	return proto_unregister("ipv6");
}
