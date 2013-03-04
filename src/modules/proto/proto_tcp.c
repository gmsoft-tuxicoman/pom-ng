/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2010-2013 Guy Martin <gmsoft@tuxicoman.be>
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
#include <pom-ng/core.h>
#include <pom-ng/stream.h>
#include <pom-ng/ptype_uint8.h>
#include <pom-ng/ptype_uint16.h>
#include <pom-ng/ptype_uint32.h>

#include "proto_tcp.h"

#include <string.h>
#include <arpa/inet.h>

#define __FAVOR_BSD
#include <netinet/tcp.h>

#if 0
#define debug_tcp(x...) pomlog(POMLOG_DEBUG x)
#else
#define debug_tcp(x...)
#endif

struct mod_reg_info* proto_tcp_reg_info() {

	static struct mod_reg_info reg_info = { 0 };
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = proto_tcp_mod_register;
	reg_info.unregister_func = proto_tcp_mod_unregister;
	reg_info.dependencies = "proto_http, ptype_bool, ptype_uint8, ptype_uint16, ptype_uint32";

	return &reg_info;
}

static int proto_tcp_mod_register(struct mod_reg *mod) {

	static struct proto_reg_info proto_tcp = { 0 };
	proto_tcp.name = "tcp";
	proto_tcp.api_ver = PROTO_API_VER;
	proto_tcp.mod = mod;
	
	static struct proto_pkt_field fields[PROTO_TCP_FIELD_NUM + 1] = { { 0 } };
	fields[0].name = "sport";
	fields[0].value_type = ptype_get_type("uint16");
	fields[0].description = "Source port";
	fields[1].name = "dport";
	fields[1].value_type = ptype_get_type("uint16");
	fields[1].description = "Destination port";
	fields[2].name = "flags";
	fields[2].value_type = ptype_get_type("uint8");
	fields[2].description = "Flags";
	fields[3].name = "seq";
	fields[3].value_type = ptype_get_type("uint32");
	fields[3].description = "Sequence";
	fields[4].name = "ack";
	fields[4].value_type = ptype_get_type("uint32");
	fields[4].description = "Sequence ACK";
	fields[5].name = "win";
	fields[5].value_type = ptype_get_type("uint16");
	fields[5].description = "Window";
	proto_tcp.pkt_fields = fields;

	static struct conntrack_info ct_info = { 0 };
	ct_info.default_table_size = 32768;
	ct_info.fwd_pkt_field_id = proto_tcp_field_sport;
	ct_info.rev_pkt_field_id = proto_tcp_field_dport;
	ct_info.cleanup_handler = proto_tcp_conntrack_cleanup;
	proto_tcp.ct_info = &ct_info;
	
	proto_tcp.init = proto_tcp_init;
	proto_tcp.process = proto_tcp_process;
	proto_tcp.cleanup = proto_tcp_cleanup;


	if (proto_register(&proto_tcp) == POM_OK)
		return POM_OK;

	return POM_ERR;

}

static int proto_tcp_init(struct proto *proto, struct registry_instance *i) {


	struct proto_tcp_priv *priv = malloc(sizeof(struct proto_tcp_priv));
	if (!priv) {
		pom_oom(sizeof(struct proto_tcp_priv));
		return POM_ERR;
	}
	memset(priv, 0, sizeof(struct proto_tcp_priv));
	proto_set_priv(proto, priv);

	priv->param_tcp_syn_sent_t = ptype_alloc_unit("uint16", "seconds");
	priv->param_tcp_syn_recv_t = ptype_alloc_unit("uint16", "seconds");
	priv->param_tcp_established_t = ptype_alloc_unit("uint16", "seconds");
	priv->param_tcp_half_closed_t = ptype_alloc_unit("uint16", "seconds");
	priv->param_tcp_closed_t = ptype_alloc_unit("uint16", "seconds");
	priv->param_tcp_reuse_handling = ptype_alloc("bool");
	priv->param_tcp_conn_buffer = ptype_alloc_unit("uint32", "bytes");

	// FIXME actually use param_tcp_reuse_handling !
	
	struct registry_param *p = NULL;

	if (!priv->param_tcp_syn_sent_t
		|| !priv->param_tcp_syn_recv_t
		|| !priv->param_tcp_half_closed_t
		|| !priv->param_tcp_established_t
		|| !priv->param_tcp_closed_t
		|| !priv->param_tcp_reuse_handling
		|| !priv->param_tcp_conn_buffer) {
		
		goto err;
	}

	p = registry_new_param("syn_recv_timer", "60", priv->param_tcp_syn_recv_t, "SYN received timer", 0);
	if (registry_instance_add_param(i, p) != POM_OK)
		goto err;

	p = registry_new_param("syn_sent_timer", "180", priv->param_tcp_syn_sent_t, "SYN sent timer", 0);
	if (registry_instance_add_param(i, p) != POM_OK)
		goto err;

	p = registry_new_param("established_timer", "7200", priv->param_tcp_established_t, "Established timer", 0);
	if (registry_instance_add_param(i, p) != POM_OK)
		goto err;

	p = registry_new_param("half_closed_timer", "120", priv->param_tcp_half_closed_t, "Half-closed timer", 0);
	if (registry_instance_add_param(i, p) != POM_OK)
		goto err;

	p = registry_new_param("closed_timer", "30", priv->param_tcp_closed_t, "Closed timer", 0);
	if (registry_instance_add_param(i, p) != POM_OK)
		goto err;

/*	FIXME
	p = registry_new_param("enable_reuse_handling", "no", priv->param_tcp_reuse_handling, "Enable connection reuse handling (SO_REUSEADDR)", 0);
	if (registry_instance_add_param(i, p) != POM_OK)
		goto err;
*/
	p = registry_new_param("conn_buffer", "65535", priv->param_tcp_conn_buffer, "Maximum buffer per connection", 0);
	if (registry_instance_add_param(i, p) != POM_OK)
		goto err;

	p = NULL;

	priv->proto_http = proto_get("http");
	if (!priv->proto_http)
		goto err;


	return POM_OK;

err:
	if (p)
		registry_cleanup_param(p);
	
	proto_tcp_cleanup(proto);

	return POM_ERR;
}


static int proto_tcp_update_state(struct proto_tcp_priv *ppriv, struct proto_tcp_conntrack_priv *priv, struct conntrack_entry *ce, uint8_t flags, unsigned int direction, ptime ts) {

	// We examine the flags SYN, FIN and RST to see if there is something interesting

	if (flags & TH_SYN) {
		if (flags & TH_ACK) { // SYN+ACK
			if (priv->state <= TCP_STATE_SYN_SENT) {
				priv->state = TCP_STATE_SYN_RECV;
			}
		} else {
			if (priv->state == TCP_STATE_NEW) {
				priv->state = TCP_STATE_SYN_SENT;
			}
		}
	} else if (flags & TH_FIN) {
		int dir_flag = (direction == POM_DIR_FWD ? PROTO_TCP_FIN_RECV_FWD : PROTO_TCP_FIN_RECV_REV);
		priv->flags |= dir_flag;

		if ((priv->flags & PROTO_TCP_FIN_RECV_BOTH) == PROTO_TCP_FIN_RECV_BOTH) {
			priv->state = TCP_STATE_CLOSED; // We got FIN in both directions
		} else {
			priv->state = TCP_STATE_HALF_CLOSED;
		}
	} else if (flags & TH_RST) {
		// RST always closes a connection
		priv->state = TCP_STATE_CLOSED;
	} else {
		if (priv->state < TCP_STATE_ESTABLISHED)
			priv->state = TCP_STATE_ESTABLISHED;
	}
	

	uint16_t *delay = NULL;

	switch (priv->state) {
		case TCP_STATE_SYN_SENT:
			delay = PTYPE_UINT16_GETVAL(ppriv->param_tcp_syn_sent_t);
			break;
		case TCP_STATE_SYN_RECV:
			delay = PTYPE_UINT16_GETVAL(ppriv->param_tcp_syn_recv_t);
			break;
		case TCP_STATE_ESTABLISHED:
			delay = PTYPE_UINT16_GETVAL(ppriv->param_tcp_established_t);
			break;
		case TCP_STATE_HALF_CLOSED:
			delay = PTYPE_UINT16_GETVAL(ppriv->param_tcp_half_closed_t);
			break;
		case TCP_STATE_CLOSED:
			delay = PTYPE_UINT16_GETVAL(ppriv->param_tcp_closed_t);
			break;
		default:
			pomlog(POMLOG_ERR "Internal error : Invalid state : %u", priv->state);
			return PROTO_ERR;
	}

	if (conntrack_delayed_cleanup(ce, *delay, ts) != POM_OK) {
		return PROTO_ERR;
	}


	return PROTO_OK;
}

static int proto_tcp_process(void *proto_priv, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

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
		// Invalid packet, SYN flag present and len > 0
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
	if (conntrack_get(stack, stack_index) != POM_OK)
		return PROTO_ERR;

	struct proto_tcp_priv *ppriv = proto_priv;
	struct proto_tcp_conntrack_priv *priv = s->ce->priv;

	if (!priv) {
		priv = malloc(sizeof(struct proto_tcp_conntrack_priv));
		if (!priv) {
			conntrack_unlock(s->ce);
			pom_oom(sizeof(struct proto_tcp_conntrack_priv));
			return POM_ERR;
		}
		memset(priv, 0, sizeof(struct proto_tcp_conntrack_priv));

		s->ce->priv = priv;

		// TODO improve this
		if (ntohs(hdr->th_sport) == 80 || ntohs(hdr->th_dport) == 80)
			priv->proto = ppriv->proto_http;
	}


	if (!priv->proto) {
		// No further handling is done if we don't care about what's next in the protocol chain
		int res = proto_tcp_update_state(ppriv, priv, s->ce, hdr->th_flags, s->direction, p->ts);
		conntrack_unlock(s->ce);
		return res;
	}


	// Use to set the sequence later on
	// It must be done when the conntrack is not locked
	int action = 0;
	struct stream *stream = priv->stream;
	uint32_t fwd_seq = 0, rev_seq = 0;

	// Learn the sequence from the SYN and SYN+ACK packets
	uint32_t seq = ntohl(hdr->th_seq);
	int dir_flag = (s->direction == POM_DIR_FWD ? PROTO_TCP_SEQ_KNOWN_DIR_FWD : PROTO_TCP_SEQ_KNOWN_DIR_REV);
	if (hdr->th_flags & TH_SYN) {
		
		// Add one to the seq when SYN is set
		seq++;


		if ((priv->flags & dir_flag) && priv->start_seq[s->direction] != seq) {
			pomlog(POMLOG_DEBUG "Possible reused TCP connection %p (stream %p) in direction %u : old seq %u, new seq %u", priv, priv->stream, s->direction, priv->start_seq[s->direction], seq);
		} else {
			priv->start_seq[s->direction] = seq;
			priv->flags |= dir_flag;

			debug_tcp("Connection %p (stream %p) in direction %u : start seq %u from SYN", priv, priv->stream, s->direction, seq);
			action |= dir_flag;
		}

		if (hdr->th_flags & TH_ACK) {
			int rev_dir = POM_DIR_REVERSE(s->direction);

			int rev_dir_flag = (s->direction == POM_DIR_REV ? PROTO_TCP_SEQ_KNOWN_DIR_FWD : PROTO_TCP_SEQ_KNOWN_DIR_REV);
			uint32_t rev_seq = ntohl(hdr->th_ack);
			if ((priv->flags & rev_dir_flag) && priv->start_seq[rev_dir] != rev_seq) {
				pomlog(POMLOG_DEBUG "Most probably reused TCP connection %p (stream %p) in direction %u : old seq %u, new seq %u", priv, priv->stream, rev_dir, priv->start_seq[rev_dir], rev_seq);
			} else {

				priv->start_seq[rev_dir] = ntohl(hdr->th_ack);
				priv->flags |= rev_dir_flag;

				debug_tcp("Connection %p (stream %p) in direction %u : start seq %u from SYN+ACK", priv, priv->stream, rev_dir, rev_seq);
				
				action |= rev_dir_flag;
			}

			priv->flags |= (s->direction == POM_DIR_REV ? PROTO_TCP_CLIENT_DIR_IS_FWD : PROTO_TCP_CLIENT_DIR_IS_REV);

		} else {
			priv->flags |= (s->direction == POM_DIR_FWD ? PROTO_TCP_CLIENT_DIR_IS_FWD : PROTO_TCP_CLIENT_DIR_IS_REV);
		}

	} else if (!(priv->flags & PROTO_TCP_SEQ_ASSURED) && (hdr->th_flags & TH_ACK) && priv->start_seq[s->direction] == seq && plen == 0 && (priv->flags & dir_flag) &&
		((s->direction == POM_DIR_FWD && (priv->flags & PROTO_TCP_CLIENT_DIR_IS_FWD)) || (s->direction == POM_DIR_REV && (priv->flags & PROTO_TCP_CLIENT_DIR_IS_REV)))) {
		// We have an ACK for which we know the SYN !
		// From this we can be sure we have the right sequences in both dir
		// Overwrite the reverse in any case
		int rev_dir = POM_DIR_REVERSE(s->direction);
		int rev_dir_flag = (s->direction == POM_DIR_REV ? PROTO_TCP_SEQ_KNOWN_DIR_FWD : PROTO_TCP_SEQ_KNOWN_DIR_REV);

		uint32_t rev_seq = ntohl(hdr->th_ack);
		priv->start_seq[rev_dir] = rev_seq;
		priv->flags |= rev_dir_flag;
		priv->flags |= PROTO_TCP_SEQ_ASSURED;

		debug_tcp("Connection %p (stream %p) in direction %u : assured seq %u from ACK", priv, priv->stream, s->direction, seq);
		action |= rev_dir_flag;

	}

	if (!priv->stream && plen) {
		priv->stream = stream_alloc(*PTYPE_UINT32_GETVAL(ppriv->param_tcp_conn_buffer), s->ce, STREAM_FLAG_BIDIR, proto_tcp_process_payload);
		if (!priv->stream) {
			conntrack_unlock(s->ce);
			return PROTO_ERR;
		}
		if (stream_set_timeout(priv->stream, 600, 30) != POM_OK) {
			conntrack_unlock(s->ce);
			stream_cleanup(priv->stream);
			priv->stream = NULL;
			return PROTO_ERR;
		}

		stream = priv->stream;
		action = priv->flags & (PROTO_TCP_SEQ_KNOWN_DIR_FWD | PROTO_TCP_SEQ_KNOWN_DIR_REV);
	}

	int res = PROTO_OK;
	if (stream) {
		if (action & PROTO_TCP_SEQ_KNOWN_DIR_FWD)
			fwd_seq = priv->start_seq[POM_DIR_FWD];
		if (action & PROTO_TCP_SEQ_KNOWN_DIR_REV)
			rev_seq = priv->start_seq[POM_DIR_REV];
	} else {
		res = proto_tcp_update_state(ppriv, priv, s->ce, hdr->th_flags, s->direction, p->ts);
	}

	conntrack_unlock(s->ce);

	if (!stream)
		return res;

	if (action & PROTO_TCP_SEQ_KNOWN_DIR_FWD)
		stream_set_start_seq(stream, POM_DIR_FWD, fwd_seq);
	if (action & PROTO_TCP_SEQ_KNOWN_DIR_REV)
		stream_set_start_seq(stream, POM_DIR_REV, rev_seq);

	if (plen || (hdr->th_flags & TH_FIN)) {

		if (hdr->th_flags & TH_FIN) {
			debug_tcp("Connection %p (stream %p): queued FIN packet with TS %u.%06u, seq %u and ack %u", priv, priv->stream, pom_ptime_sec(p->ts), pom_ptime_usec(p->ts), ntohs(hdr->th_seq), ntohs(hdr->th_ack));
		}

		// Queue the payload
		struct proto_process_stack *s_next = &stack[stack_index + 1];
		s_next->pload = s->pload + hdr_len;
		s_next->plen = s->plen - hdr_len;
		int res = stream_process_packet(stream, p, stack, stack_index + 1, ntohl(hdr->th_seq), ntohl(hdr->th_ack));
		if (res == PROTO_OK)
			return PROTO_STOP;
		return res;
	}
	
	return PROTO_OK;
}

static int proto_tcp_process_payload(struct conntrack_entry *ce, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct proto_tcp_conntrack_priv *cp = ce->priv;

	if (!cp->proto)
		return PROTO_OK;

	struct proto_process_stack *s_tcp = &stack[stack_index - 1];
	uint8_t flags = *PTYPE_UINT8_GETVAL(s_tcp->pkt_info->fields_value[proto_tcp_field_flags]);
	if (flags & TH_FIN) // Increase the sequence number by 1 if we got a FIN
		stream_increase_seq(cp->stream, s_tcp->direction, 1);
	
	if (proto_tcp_update_state(proto_get_priv(s_tcp->proto), cp, ce, flags, s_tcp->direction, p->ts) != POM_OK)
		return PROTO_ERR;

	stack[stack_index].proto = cp->proto;
	return core_process_multi_packet(stack, stack_index, p);
}


static int proto_tcp_conntrack_cleanup(void *ce_priv) {

	struct proto_tcp_conntrack_priv *priv = ce_priv;
	if (!priv)
		return POM_OK;

	debug_tcp("Connection %p (stream %p) cleaned up", ce_priv, priv->stream);
	if (priv->stream) {
		if (stream_cleanup(priv->stream) != POM_OK)
			return POM_ERR;
	}
	free(priv);


	return POM_OK;
}

static int proto_tcp_cleanup(void *proto_priv) {

	struct proto_tcp_priv *priv = proto_priv;

	if (priv) {
		if (priv->param_tcp_syn_recv_t)
			ptype_cleanup(priv->param_tcp_syn_recv_t);
		if (priv->param_tcp_syn_sent_t)
			ptype_cleanup(priv->param_tcp_syn_sent_t);
		if (priv->param_tcp_established_t)
			ptype_cleanup(priv->param_tcp_established_t);
		if (priv->param_tcp_half_closed_t)
			ptype_cleanup(priv->param_tcp_half_closed_t);
		if (priv->param_tcp_closed_t)
			ptype_cleanup(priv->param_tcp_closed_t);
		if (priv->param_tcp_reuse_handling)
			ptype_cleanup(priv->param_tcp_reuse_handling);

		free(priv);
	}

	return POM_OK;
}

static int proto_tcp_mod_unregister() {
	
	return proto_unregister("tcp");
}
