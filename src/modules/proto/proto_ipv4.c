/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2010-2014 Guy Martin <gmsoft@tuxicoman.be>
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
#include <pom-ng/ptype_ipv4.h>
#include <pom-ng/ptype_uint8.h>
#include <pom-ng/ptype_uint32.h>

#include "proto_ipv4.h"

#include <string.h>
#include <arpa/inet.h>

#define IP_DONT_FRAG 0x4000
#define IP_MORE_FRAG 0x2000
#define IP_OFFSET_MASK 0x1fff

static struct ptype *param_frag_timeout = NULL, *param_conntrack_timeout = NULL;

static struct registry_perf *perf_frags = NULL, *perf_frags_dropped = NULL, *perf_reassembled_pkts = NULL;

struct mod_reg_info* proto_ipv4_reg_info() {

	static struct mod_reg_info reg_info = { 0 };
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = proto_ipv4_mod_register;
	reg_info.unregister_func = proto_ipv4_mod_unregister;
	reg_info.dependencies = "ptype_ipv4, ptype_uint8, ptype_uint32";

	return &reg_info;
}


static int proto_ipv4_mod_register(struct mod_reg *mod) {

	static struct proto_reg_info proto_ipv4 = { 0 };
	proto_ipv4.name = "ipv4";
	proto_ipv4.api_ver = PROTO_API_VER;
	proto_ipv4.mod = mod;
	proto_ipv4.number_class = "ip";

	static struct proto_pkt_field fields[PROTO_IPV4_FIELD_NUM + 1] = { { 0 } };
	fields[0].name = "src";
	fields[0].value_type = ptype_get_type("ipv4");
	fields[0].description = "Source address";
	fields[1].name = "dst";
	fields[1].value_type = ptype_get_type("ipv4");
	fields[1].description = "Destination address";
	fields[2].name = "tos";
	fields[2].value_type = ptype_get_type("uint8");
	fields[2].description = "Type of service";
	fields[3].name = "ttl";
	fields[3].value_type = ptype_get_type("uint8");
	fields[3].description = "Time to live";
	proto_ipv4.pkt_fields = fields;

	static struct conntrack_info ct_info = { 0 };
	ct_info.default_table_size = 65535;
	ct_info.fwd_pkt_field_id = proto_ipv4_field_src;
	ct_info.rev_pkt_field_id = proto_ipv4_field_dst;
	ct_info.cleanup_handler = proto_ipv4_conntrack_cleanup;
	proto_ipv4.ct_info = &ct_info;
	
	proto_ipv4.init = proto_ipv4_init;
	proto_ipv4.process = proto_ipv4_process;
	proto_ipv4.cleanup = proto_ipv4_cleanup;

	if (proto_register(&proto_ipv4) == POM_OK)
		return POM_OK;

	return POM_ERR;
}


static int proto_ipv4_init(struct proto *proto, struct registry_instance *i) {

	if (proto_number_register("ethernet", 0x0800, proto) != POM_OK ||
		proto_number_register("ip", IPPROTO_IPIP, proto) != POM_OK ||
		proto_number_register("ppp", 0x21, proto) != POM_OK)
		return POM_ERR;

	perf_frags = registry_instance_add_perf(i, "fragments", registry_perf_type_counter, "Number of fragments received", "pkts");
	perf_frags_dropped = registry_instance_add_perf(i, "dropped_fragments", registry_perf_type_counter, "Number of fragments dropped", "pkts");
	perf_reassembled_pkts = registry_instance_add_perf(i, "reassembled_pkts", registry_perf_type_counter, "Number of reassembled packets", "pkts");

	if (!perf_frags || !perf_frags_dropped || !perf_reassembled_pkts)
		return POM_ERR;

	param_frag_timeout = ptype_alloc_unit("uint32", "seconds");
	if (!param_frag_timeout)
		return POM_ERR;

	param_conntrack_timeout = ptype_alloc_unit("uint32", "seconds");
	if (!param_conntrack_timeout)
		return POM_ERR;

	struct registry_param *p = registry_new_param("fragment_timeout", "60", param_frag_timeout, "Timeout for incomplete ipv4 fragments", 0);
	if (proto_add_param(proto, p) != POM_OK)
		goto err;

	p = registry_new_param("conntrack_timeout", "7200", param_conntrack_timeout, "Timeout for ipv4 connections", 0);
	if (proto_add_param(proto, p) != POM_OK)
		goto err;

	return POM_OK;

err:
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


static int proto_ipv4_process(void *proto_priv, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct proto_process_stack *s = &stack[stack_index];
	struct proto_process_stack *s_next = &stack[stack_index + 1];

	struct ip* hdr = s->pload;

	unsigned int hdr_len = hdr->ip_hl * 4;

	if (s->plen < sizeof(struct ip) || // length smaller than header
		hdr->ip_hl < 5 || // ip header < 5 bytes
		ntohs(hdr->ip_len) < hdr_len || // datagram size < ip header length
		ntohs(hdr->ip_len) > s->plen) { // datagram size > given size
		return PROTO_INVALID;
	}


	PTYPE_IPV4_SETADDR(s->pkt_info->fields_value[proto_ipv4_field_src], hdr->ip_src);
	PTYPE_IPV4_SETADDR(s->pkt_info->fields_value[proto_ipv4_field_dst], hdr->ip_dst);
	PTYPE_UINT8_SETVAL(s->pkt_info->fields_value[proto_ipv4_field_tos], hdr->ip_tos);
	PTYPE_UINT8_SETVAL(s->pkt_info->fields_value[proto_ipv4_field_ttl], hdr->ip_ttl);

	// Handle conntrack stuff
	if (conntrack_get(stack, stack_index) != POM_OK)
		return PROTO_ERR;


	s_next->pload = s->pload + hdr_len;
	s_next->plen = ntohs(hdr->ip_len) - hdr_len;

	s_next->proto = proto_get_by_number(s->proto, hdr->ip_p);


	int res = POM_ERR;
	if (s->ce->children) {
		res = conntrack_delayed_cleanup(s->ce, 0, p->ts);
	} else {
		uint32_t *conntrack_timeout = PTYPE_UINT32_GETVAL(param_conntrack_timeout);
		res = conntrack_delayed_cleanup(s->ce, *conntrack_timeout, p->ts);
	}
	if (res == POM_ERR) {
		conntrack_unlock(s->ce);
		return PROTO_ERR;
	}

	uint16_t frag_off = ntohs(hdr->ip_off);

	// Check if packet is fragmented and need more handling

	if (frag_off & IP_DONT_FRAG) {
		conntrack_unlock(s->ce);
		return PROTO_OK; // Nothing to do
	}

	if (!(frag_off & IP_MORE_FRAG) && !(frag_off & IP_OFFSET_MASK)) {
		conntrack_unlock(s->ce);
		return PROTO_OK; // Nothing to do, full packet
	}

	uint16_t offset = (frag_off & IP_OFFSET_MASK) << 3;
	size_t frag_size = ntohs(hdr->ip_len) - (hdr->ip_hl * 4);

	// Ignore invalid fragments
	if (frag_size > 0xFFFF) {
		conntrack_unlock(s->ce);
		return PROTO_INVALID;
	}

	if (frag_size > s->plen + hdr_len) {
		conntrack_unlock(s->ce);
		return PROTO_INVALID;
	}

	// Account for one more fragment
	registry_perf_inc(perf_frags, 1);

	struct proto_ipv4_fragment *tmp = s->ce->priv;

	// Let's find the right buffer
	for (; tmp && tmp->id != hdr->ip_id; tmp = tmp->next);

	if (!tmp) {
		// Buffer not found, create it
		tmp = malloc(sizeof(struct proto_ipv4_fragment));
		if (!tmp) {
			pom_oom(sizeof(struct proto_ipv4_fragment));
			conntrack_unlock(s->ce);
			return PROTO_ERR;
		}
		memset(tmp, 0, sizeof(struct proto_ipv4_fragment));

		tmp->t = conntrack_timer_alloc(s->ce, proto_ipv4_fragment_cleanup, tmp);
		if (!tmp->t) {
			conntrack_unlock(s->ce);
			free(tmp);
			return PROTO_ERR;
		}
		
		tmp->id = hdr->ip_id;

		if (!s_next->proto) {
			// Set processed flag so no attempt to process this will be done
			tmp->flags |= PROTO_IPV4_FLAG_PROCESSED;
			conntrack_unlock(s->ce);
			conntrack_timer_cleanup(tmp->t);
			free(tmp);
			return PROTO_STOP;
		}

		tmp->multipart = packet_multipart_alloc(s_next->proto, 0, 0);
		if (!tmp->multipart) {
			conntrack_unlock(s->ce);
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
	if (tmp->flags & PROTO_IPV4_FLAG_PROCESSED) {
		conntrack_unlock(s->ce);
		registry_perf_inc(perf_frags_dropped, 1);
		return PROTO_STOP;
	}
	
	// Add the fragment
	if (packet_multipart_add_packet(tmp->multipart, p, offset, frag_size, (s->pload - (void*)p->buff) + (hdr->ip_hl * 4)) != POM_OK) {
		conntrack_unlock(s->ce);
		packet_multipart_cleanup(tmp->multipart);
		conntrack_timer_cleanup(tmp->t);
		free(tmp);
		return PROTO_ERR;
	}
	tmp->count++;

	// Schedule the timeout for the fragment
	uint32_t *frag_timeout = PTYPE_UINT32_GETVAL(param_frag_timeout);
	conntrack_timer_queue(tmp->t, *frag_timeout, p->ts);


	if (!(frag_off & IP_MORE_FRAG))
		tmp->flags |= PROTO_IPV4_FLAG_GOT_LAST;

	if ((tmp->flags & PROTO_IPV4_FLAG_GOT_LAST) && !tmp->multipart->gaps)
		tmp->flags |= PROTO_IPV4_FLAG_PROCESSED;


	conntrack_unlock(s->ce);
	
	if ((tmp->flags & PROTO_IPV4_FLAG_PROCESSED)) {
		int res = packet_multipart_process(tmp->multipart, stack, stack_index + 1);
		tmp->multipart = NULL; // Multipart will be cleared automatically
		if (res == PROTO_ERR) {
			return PROTO_ERR;
		} else if (res == PROTO_INVALID) {
			registry_perf_inc(perf_frags_dropped, tmp->count);
		} else {
			registry_perf_inc(perf_reassembled_pkts, 1);
		}
	}

	return PROTO_STOP; // Stop processing the packet

}

static int proto_ipv4_fragment_cleanup(struct conntrack_entry *ce, void *priv, ptime now) {

	struct proto_ipv4_fragment *f = priv;

	// Remove the frag from the conntrack
	if (f->prev)
		f->prev->next = f->next;
	else
		ce->priv = f->next;

	if (f->next)
		f->next->prev = f->prev;

	conntrack_unlock(ce);


	if (!(f->flags & PROTO_IPV4_FLAG_PROCESSED)) {
		registry_perf_inc(perf_frags_dropped, f->count);
	}

	if (f->multipart)
		packet_multipart_cleanup(f->multipart);
	
	if (f->t)
		conntrack_timer_cleanup(f->t);
	
	free(f);

	return POM_OK;

}

static int proto_ipv4_conntrack_cleanup(void *ce_priv) {

	struct proto_ipv4_fragment *frag_list = ce_priv;

	while (frag_list) {
		struct proto_ipv4_fragment *f = frag_list;
		frag_list = f->next;

		if (!(f->flags & PROTO_IPV4_FLAG_PROCESSED)) {
			registry_perf_inc(perf_frags_dropped, f->count);
		}

		if (f->multipart)
			packet_multipart_cleanup(f->multipart);
		
		if (f->t)
			conntrack_timer_cleanup(f->t);
		
		free(f);

	}

	return POM_OK;
}

static int proto_ipv4_cleanup(void *proto_priv) {

	int res = POM_OK;

	res += ptype_cleanup(param_frag_timeout);
	res += ptype_cleanup(param_conntrack_timeout);

	return res;
}

static int proto_ipv4_mod_unregister() {

	return proto_unregister("ipv4");
}
