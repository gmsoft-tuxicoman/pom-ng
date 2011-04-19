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
#include <pom-ng/core.h>
#include <pom-ng/ptype_uint8.h>
#include <pom-ng/ptype_uint16.h>
#include <pom-ng/ptype_uint32.h>

#include "proto_tcp.h"

#include <string.h>
#include <arpa/inet.h>

#define __FAVOR_BSD
#include <netinet/tcp.h>

#if 0 
#define tcp_tshoot(x...) pomlog(POMLOG_TSHOOT x)
#else
#define tcp_tshoot(x...)
#endif


static struct proto_dependency *proto_http = NULL;

// ptypes for fields value template
static struct ptype *ptype_uint8 = NULL, *ptype_uint16 = NULL, *ptype_uint32 = NULL;

// params
static struct ptype *param_tcp_syn_sent_t, *param_tcp_syn_recv_t, *param_tcp_last_ack_t, *param_tcp_close_t, *param_tcp_time_wait_t, *param_tcp_established_t, *param_tcp_reuse_handling;

struct mod_reg_info* proto_tcp_reg_info() {
	static struct mod_reg_info reg_info;
	memset(&reg_info, 0, sizeof(struct mod_reg_info));
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = proto_tcp_mod_register;
	reg_info.unregister_func = proto_tcp_mod_unregister;

	return &reg_info;
}


static int proto_tcp_mod_register(struct mod_reg *mod) {

	ptype_uint8 = ptype_alloc("uint8");
	ptype_uint16 = ptype_alloc("uint16");
	ptype_uint32 = ptype_alloc("uint32");
	
	if (!ptype_uint8 || !ptype_uint16 || !ptype_uint32) {
		if (ptype_uint8) {
			ptype_cleanup(ptype_uint8);
			ptype_uint8 = NULL;
		}
		if (ptype_uint16) {
			ptype_cleanup(ptype_uint16);
			ptype_uint16 = NULL;
		}
		if (ptype_uint32) {
			ptype_cleanup(ptype_uint32);
			ptype_uint32 = NULL;
		}
		return POM_ERR;
	}

	static struct proto_pkt_field fields[PROTO_TCP_FIELD_NUM + 1];
	memset(fields, 0, sizeof(struct proto_pkt_field) * (PROTO_TCP_FIELD_NUM + 1));
	fields[0].name = "sport";
	fields[0].value_template = ptype_uint16;
	fields[0].description = "Source port";
	fields[1].name = "dport";
	fields[1].value_template = ptype_uint16;
	fields[1].description = "Destination port";
	fields[2].name = "flags";
	fields[2].value_template = ptype_uint8;
	fields[2].description = "Flags";
	fields[3].name = "seq";
	fields[3].value_template = ptype_uint32;
	fields[3].description = "Sequence";
	fields[4].name = "ack";
	fields[4].value_template = ptype_uint32;
	fields[4].description = "Sequence ACK";
	fields[5].name = "win";
	fields[5].value_template = ptype_uint16;
	fields[5].description = "Window";


	static struct proto_reg_info proto_tcp;
	memset(&proto_tcp, 0, sizeof(struct proto_reg_info));
	proto_tcp.name = "tcp";
	proto_tcp.api_ver = PROTO_API_VER;
	proto_tcp.mod = mod;
	proto_tcp.pkt_fields = fields;
	
	proto_tcp.ct_info.default_table_size = 20000;
	proto_tcp.ct_info.fwd_pkt_field_id = proto_tcp_field_sport;
	proto_tcp.ct_info.rev_pkt_field_id = proto_tcp_field_dport;
	proto_tcp.ct_info.cleanup_handler = proto_tcp_conntrack_cleanup;
	
	proto_tcp.init = proto_tcp_init;
	proto_tcp.process = proto_tcp_process;
	proto_tcp.cleanup = proto_tcp_cleanup;


	if (proto_register(&proto_tcp) == POM_OK)
		return POM_OK;

	return POM_ERR;

}


static int proto_tcp_init(struct registry_instance *i) {


	param_tcp_syn_sent_t = ptype_alloc_unit("uint16", "seconds");
	param_tcp_syn_recv_t = ptype_alloc_unit("uint16", "seconds");
	param_tcp_last_ack_t = ptype_alloc_unit("uint16", "seconds");
	param_tcp_close_t = ptype_alloc_unit("uint16", "seconds");
	param_tcp_time_wait_t = ptype_alloc_unit("uint16", "seconds");
	param_tcp_established_t = ptype_alloc_unit("uint16", "seconds");
	param_tcp_reuse_handling = ptype_alloc("bool");
	
	if (!param_tcp_syn_sent_t
		|| !param_tcp_syn_recv_t
		|| !param_tcp_last_ack_t
		|| !param_tcp_close_t
		|| !param_tcp_time_wait_t
		|| !param_tcp_established_t
		|| !param_tcp_reuse_handling) {
		
		goto err;
	}

	struct registry_param *p = NULL;
	p = registry_new_param("syn_sent_timer", "180", param_tcp_syn_sent_t, "SYN sent timer", 0);
	if (registry_instance_add_param(i, p) != POM_OK)
		goto err;

	p = registry_new_param("syn_recv_timer", "60", param_tcp_syn_recv_t, "SYN received timer", 0);
	if (registry_instance_add_param(i, p) != POM_OK)
		goto err;

	p = registry_new_param("last_ack_timer", "30", param_tcp_last_ack_t, "Last ACK timer", 0);
	if (registry_instance_add_param(i, p) != POM_OK)
		goto err;

	p = registry_new_param("close_timer", "10", param_tcp_close_t, "Close timer", 0);
	if (registry_instance_add_param(i, p) != POM_OK)
		goto err;

	p = registry_new_param("time_wait_timer", "180", param_tcp_time_wait_t, "Time wait timer", 0);
	if (registry_instance_add_param(i, p) != POM_OK)
		goto err;

	p = registry_new_param("established_timer", "7200", param_tcp_established_t, "Established timer", 0);
	if (registry_instance_add_param(i, p) != POM_OK)
		goto err;

	p = registry_new_param("enable_reuse_handling", "no", param_tcp_reuse_handling, "Enable connection reuse handling (SO_REUSEADDR)", 0);
	if (registry_instance_add_param(i, p) != POM_OK)
		goto err;

	proto_http = proto_add_dependency("http");
	if (!proto_http) {
		proto_tcp_cleanup();
		return POM_ERR;
	}

	return POM_OK;

err:
	
	if (param_tcp_syn_sent_t)
		ptype_cleanup(param_tcp_syn_sent_t);
	if (param_tcp_syn_recv_t)
		ptype_cleanup(param_tcp_syn_recv_t);
	if (param_tcp_last_ack_t)
		ptype_cleanup(param_tcp_last_ack_t);
	if (param_tcp_close_t)
		ptype_cleanup(param_tcp_close_t);
	if (param_tcp_time_wait_t)
		ptype_cleanup(param_tcp_time_wait_t);
	if (param_tcp_established_t)
		ptype_cleanup(param_tcp_established_t);
	if (param_tcp_reuse_handling)
		ptype_cleanup(param_tcp_reuse_handling);

	return POM_ERR;
}

static int proto_tcp_process(struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct proto_process_stack *s = &stack[stack_index];
	struct tcphdr* hdr = s->pload;

	if (s->plen < sizeof(struct tcphdr))
		return PROTO_INVALID;

	unsigned int hdr_len = (hdr->th_off << 2);

	if (hdr_len > s->plen || hdr_len < 20) {
		// Incomplete or invalid packet
		return PROTO_INVALID;
	}
	
	unsigned int plen = s->plen - hdr_len;

	if ((hdr->th_flags & TH_SYN) && plen > 0) {
		// Invalid packet, SYN or RST flag present and len > 0
		return PROTO_INVALID;
	}

	if ((hdr->th_flags & TH_SYN) && ((hdr->th_flags & TH_RST) || (hdr->th_flags & TH_FIN))) {
		// Invalid packet SYN and either RST or FIN flag present
		return PROTO_INVALID;
	}

	PTYPE_UINT16_SETVAL(s->pkt_info->fields_value[proto_tcp_field_sport], ntohs(hdr->th_sport));
	PTYPE_UINT16_SETVAL(s->pkt_info->fields_value[proto_tcp_field_dport], ntohs(hdr->th_dport));
	PTYPE_UINT8_SETVAL(s->pkt_info->fields_value[proto_tcp_field_flags], hdr->th_flags);
	PTYPE_UINT32_SETVAL(s->pkt_info->fields_value[proto_tcp_field_seq], ntohl(hdr->th_seq));
	PTYPE_UINT32_SETVAL(s->pkt_info->fields_value[proto_tcp_field_ack], ntohl(hdr->th_ack));
	PTYPE_UINT16_SETVAL(s->pkt_info->fields_value[proto_tcp_field_win], ntohl(hdr->th_win));

	if ((hdr->th_flags & TH_RST) && plen > 0) {
		plen = 0; // RFC 1122 4.2.2.12 : RST may contain the data that caused the packet to be sent, discard it
	}
	

	// Conntrack stuff
	struct proto_process_stack *s_prev = &stack[stack_index - 1];
	s->ce = conntrack_get(s->proto, s->pkt_info->fields_value[proto_tcp_field_sport], s->pkt_info->fields_value[proto_tcp_field_dport], s_prev->ce);
	if (!s->ce)
		return PROTO_ERR;

	pom_mutex_lock(&s->ce->lock);

	struct proto_tcp_conntrack_priv *priv = s->ce->priv;

	uint16_t *delay = NULL;

	if (!priv) {
		priv = malloc(sizeof(struct proto_tcp_conntrack_priv));
		if (!priv) {
			pom_mutex_unlock(&s->ce->lock);
			pom_oom(sizeof(struct proto_tcp_conntrack_priv));
			return POM_ERR;
		}
		memset(priv, 0, sizeof(struct proto_tcp_conntrack_priv));

		s->ce->priv = priv;

		// Set the correct state to the conntrack
		if (hdr->th_flags & TH_SYN && hdr->th_flags & TH_ACK) {
			priv->state = STATE_TCP_SYN_RECV;
			PTYPE_UINT16_GETVAL(param_tcp_syn_recv_t, delay);
		} else if (hdr->th_flags & TH_SYN) {
			priv->state = STATE_TCP_SYN_SENT;
			PTYPE_UINT16_GETVAL(param_tcp_syn_sent_t, delay);
		} else if (hdr->th_flags & TH_RST || hdr->th_flags & TH_FIN) {
			priv->state = STATE_TCP_LAST_ACK;
			PTYPE_UINT16_GETVAL(param_tcp_close_t, delay);
		} else {
			priv->state = STATE_TCP_ESTABLISHED;
			PTYPE_UINT16_GETVAL(param_tcp_established_t, delay);
		}
	} else {

		// Update conntrack timer
		if (hdr->th_flags & TH_SYN && hdr->th_flags & TH_ACK) {
			priv->state = STATE_TCP_SYN_RECV;
			PTYPE_UINT16_GETVAL(param_tcp_syn_recv_t, delay);
		} else if (hdr->th_flags & TH_SYN) {
			priv->state = STATE_TCP_SYN_SENT;
			PTYPE_UINT16_GETVAL(param_tcp_syn_sent_t, delay);
		} else if (hdr->th_flags & TH_RST || hdr->th_flags & TH_FIN) {
			if (hdr->th_flags & TH_ACK) {
				priv->state = STATE_TCP_TIME_WAIT;
				PTYPE_UINT16_GETVAL(param_tcp_time_wait_t, delay);
			} else {
				priv->state = STATE_TCP_LAST_ACK;
				PTYPE_UINT16_GETVAL(param_tcp_last_ack_t, delay);
			}
		} else if (priv->state == STATE_TCP_LAST_ACK && hdr->th_flags & TH_ACK) {
			priv->state = STATE_TCP_TIME_WAIT;
			PTYPE_UINT16_GETVAL(param_tcp_time_wait_t, delay);
		} else if (priv->state == STATE_TCP_TIME_WAIT) {
			pom_mutex_unlock(&s->ce->lock);
			return POM_OK;
		} else {
			priv->state = STATE_TCP_ESTABLISHED;
			PTYPE_UINT16_GETVAL(param_tcp_established_t, delay);
		}
	}

	if (conntrack_delayed_cleanup(s->ce, *delay) != POM_OK) {
		pom_mutex_unlock(&s->ce->lock);
		return PROTO_ERR;
	}

	if (!priv->stream) {
		priv->stream = packet_stream_alloc(hdr->th_seq, 65535, 0);
		if (!priv->stream) {
			pom_mutex_unlock(&s->ce->lock);
			return PROTO_ERR;
		}
		
		// TODO improve this
		if (ntohs(hdr->th_sport) == 80 || ntohs(hdr->th_dport) == 80)
			priv->proto = proto_http;
	}

	pom_mutex_unlock(&s->ce->lock);
	
	if (!priv->proto || !priv->proto->proto)
		return PROTO_OK;

	if (packet_stream_add_packet(priv->stream, p, s, hdr->th_seq) != POM_OK)
		return PROTO_ERR;
	
	struct packet_stream_pkt *stream_pkt = NULL;

	while ((stream_pkt = packet_stream_get_next(priv->stream, stack))) {
		
		// Do the processing
		int res = POM_OK;
		struct proto_process_stack *s_next = &stack[stack_index + 1];

		s_next->pload = s->pload + hdr_len;
		s_next->plen = plen;

		if (priv->proto->proto)
			res = core_process_multi_packet(stack, stack_index + 1, stream_pkt->pkt);

		if (packet_stream_release_packet(priv->stream, stream_pkt) != POM_OK)
			return PROTO_ERR;

	}

	return PROTO_STOP;
}

static int proto_tcp_conntrack_cleanup(struct conntrack_entry *ce) {


	if (ce->priv) {
		struct proto_tcp_conntrack_priv *priv = ce->priv;
		if (priv->stream) {
			if (packet_stream_cleanup(priv->stream) != POM_OK)
				return POM_ERR;
		}
		free(ce->priv);

	}


	return POM_OK;
}

static int proto_tcp_cleanup() {


	int res = POM_OK;

	res += ptype_cleanup(param_tcp_syn_sent_t);
	res += ptype_cleanup(param_tcp_syn_recv_t);
	res += ptype_cleanup(param_tcp_last_ack_t);
	res += ptype_cleanup(param_tcp_close_t);
	res += ptype_cleanup(param_tcp_time_wait_t);
	res += ptype_cleanup(param_tcp_established_t);
	res += ptype_cleanup(param_tcp_reuse_handling);

	res += proto_remove_dependency(proto_http);

	return res;
}

static int proto_tcp_mod_unregister() {
	
	int res = proto_unregister("tcp");

	ptype_cleanup(ptype_uint8);
	ptype_uint8 = NULL;
	ptype_cleanup(ptype_uint16);
	ptype_uint16 = NULL;
	ptype_cleanup(ptype_uint32);
	ptype_uint32 = NULL;

	return res;
}
