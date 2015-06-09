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
#include <pom-ng/core.h>
#include <pom-ng/ptype.h>
#include <pom-ng/proto.h>
#include <pom-ng/conntrack.h>
#include <pom-ng/ptype_uint8.h>
#include <pom-ng/ptype_uint16.h>
#include <pom-ng/ptype_uint32.h>
#include <arpa/inet.h>


#include "proto_rtp.h"

static struct ptype *proto_rtp_p_buffer_timeout = NULL, *proto_rtp_p_stream_timeout = NULL;


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

	static struct conntrack_info ct_info = { 0 };

	ct_info.default_table_size = 1; // No hashing done here
	ct_info.cleanup_handler = proto_rtp_conntrack_cleanup;
	proto_rtp.ct_info = &ct_info;

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

	proto_rtp.init = proto_rtp_init;
	proto_rtp.cleanup = proto_rtp_cleanup;
	proto_rtp.process = proto_rtp_process;

	if (proto_register(&proto_rtp) == POM_OK)
		return POM_OK;


	return POM_ERR;

}

static int proto_rtp_init(struct proto *proto, struct registry_instance *i) {


	proto_rtp_p_buffer_timeout = ptype_alloc_unit("uint16", "seconds");
	proto_rtp_p_stream_timeout = ptype_alloc_unit("uint32", "seconds");
	if (!proto_rtp_p_buffer_timeout || !proto_rtp_p_stream_timeout)
		return POM_ERR;

	struct registry_param *p = registry_new_param("stream_timeout", "180", proto_rtp_p_stream_timeout, "Timeout for RTP connections", 0);
	if (proto_add_param(proto, p) != POM_OK)
		goto err;

	p = registry_new_param("buffer_timeout", "1", proto_rtp_p_buffer_timeout, "Timeout for the jitter buffer", 0);
	if (proto_add_param(proto, p) != POM_OK)
		goto err;


	return POM_OK;
err:
	if (p)
		registry_cleanup_param(p);

	return POM_ERR;
}

static int proto_rtp_cleanup(void *proto_priv) {

	if (proto_rtp_p_buffer_timeout) {
		ptype_cleanup(proto_rtp_p_buffer_timeout);
		proto_rtp_p_buffer_timeout = NULL;
	}
	if (proto_rtp_p_stream_timeout) {
		ptype_cleanup(proto_rtp_p_stream_timeout);
		proto_rtp_p_stream_timeout = NULL;
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

	uint16_t seq = ntohs(hdr->seq_num);

	PTYPE_UINT8_SETVAL(s->pkt_info->fields_value[proto_rtp_field_pt], hdr->payload_type);
	PTYPE_UINT32_SETVAL(s->pkt_info->fields_value[proto_rtp_field_ssrc], hdr->ssrc);
	PTYPE_UINT16_SETVAL(s->pkt_info->fields_value[proto_rtp_field_seq], seq);
	PTYPE_UINT32_SETVAL(s->pkt_info->fields_value[proto_rtp_field_timestamp], ntohl(hdr->timestamp));

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

	if (conntrack_get_unique_from_parent(stack, stack_index) != POM_OK)
		return PROTO_ERR;


	struct proto_rtp_conntrack_priv *priv = s->ce->priv;

	if (!priv) {
		priv = malloc(sizeof(struct proto_rtp_conntrack_priv));
		if (!priv) {
			pom_oom(sizeof(struct proto_rtp_conntrack_priv));
			goto err;
		}
		memset(priv, 0, sizeof(struct proto_rtp_conntrack_priv));

		s->ce->priv = priv;
	}

	if (!priv->streams) // Cancel any possible pending cleanup
		conntrack_delayed_cleanup(s->ce, 0, p->ts);

	struct proto_rtp_stream *stream;

	for (stream = priv->streams; stream && stream->ssrc != hdr->ssrc; stream = stream->next);

	if (!stream) {
		stream = proto_rtp_stream_alloc(s->ce, hdr->ssrc, seq);
		if (!stream)
			goto err;

		stream->next = priv->streams;
		if (stream->next)
			stream->next->prev = stream;
		priv->streams = stream;

	}

	if (proto_rtp_stream_process_packet(stream, p, stack, stack_index, seq) != POM_OK)
		goto err;

	conntrack_unlock(s->ce);

	return PROTO_STOP;
err:
	conntrack_unlock(s->ce);

	return PROTO_ERR;
}

static int proto_rtp_mod_unregister() {

	return proto_unregister("rtp");
}


static int proto_rtp_conntrack_cleanup(void *ce_priv) {

	struct proto_rtp_conntrack_priv *priv = ce_priv;

	while (priv->streams) {
		struct proto_rtp_stream *tmp = priv->streams;
		priv->streams = tmp->next;
		proto_rtp_stream_cleanup(tmp);
	}

	free(priv);

	return POM_OK;
}

static struct proto_rtp_stream *proto_rtp_stream_alloc(struct conntrack_entry *ce, uint32_t ssrc, uint16_t init_seq) {

	struct proto_rtp_stream *res = malloc(sizeof(struct proto_rtp_stream));
	if (!res) {
		pom_oom(sizeof(struct proto_rtp_stream));
		return NULL;
	}
	memset(res, 0, sizeof(struct proto_rtp_stream));

	res->t = conntrack_timer_alloc(ce, proto_rtp_stream_timeout, res);

	res->next_seq = init_seq;
	res->ssrc = ssrc;

	return res;
}

static int proto_rtp_stream_process_queue(struct proto_rtp_stream *stream, ptime now) {

	while (stream->head && stream->head->seq == stream->next_seq) {
		stream->next_seq++;

		struct proto_rtp_stream_pkt *tmp = stream->head;
		stream->head = tmp->next;
		if (stream->head)
			stream->head->prev = NULL;
		else
			stream->tail = NULL;

		int res = core_process_multi_packet(tmp->stack, tmp->stack_index + 1, tmp->pkt);
		core_stack_release(tmp->stack);
		packet_release(tmp->pkt);
		free(tmp);

		if (res != POM_OK)
			return POM_ERR;
	}

	if (stream->head)
		conntrack_timer_queue(stream->t, *PTYPE_UINT32_GETVAL(proto_rtp_p_buffer_timeout), now);
	else
		conntrack_timer_queue(stream->t, *PTYPE_UINT32_GETVAL(proto_rtp_p_stream_timeout), now);

	return POM_OK;
}

static int proto_rtp_stream_timeout(struct conntrack_entry *ce, void *priv, ptime now) {

	struct proto_rtp_stream *stream = priv;

	if (!stream->head) {
		// This stream has timed out, remove it
		struct proto_rtp_conntrack_priv *cpriv = ce->priv;
		if (stream->next)
			stream->next->prev = stream->prev;
		if (stream->prev)
			stream->prev->next = stream->next;
		else
			cpriv->streams = stream->next;
		proto_rtp_stream_cleanup(stream);

		if (!cpriv->streams) {
			// Timeout the conntrack shortly after
			conntrack_delayed_cleanup(ce, 1, now);
		}
		conntrack_unlock(ce);
		return POM_OK;
	}

	stream->next_seq = stream->head->seq;

	int res = proto_rtp_stream_process_queue(stream, now);
	conntrack_unlock(ce);
	return res;
}

static int proto_rtp_stream_process_packet(struct proto_rtp_stream *stream, struct packet *pkt, struct proto_process_stack *stack, unsigned int stack_index, uint16_t seq) {

	int16_t diff = seq - stream->next_seq;

	if (diff < 0) {
		// Old packet, discard
		return POM_OK;
	} else if (diff == 0) {
		// We can process this packet

		stream->next_seq++;

		if (core_process_multi_packet(stack, stack_index + 1, pkt) != POM_OK)
			return POM_ERR;

		int res = POM_OK;
		if (stream->head)
			res = proto_rtp_stream_process_queue(stream, pkt->ts);
		else
			conntrack_timer_queue(stream->t, *PTYPE_UINT32_GETVAL(proto_rtp_p_stream_timeout), pkt->ts);
		return res;
	}

	// Not the packet we want, queue
	struct proto_rtp_stream_pkt *tmp = stream->tail;

	while (tmp) {
		diff = seq - tmp->seq;
		if (diff == 0) {
			// Dupe packet, discard
			return POM_OK;
		} else if (diff > 0) {
			break; // Packet goes after the current one
		}
		tmp = tmp->prev;
	}

	struct proto_rtp_stream_pkt *p = malloc(sizeof(struct proto_rtp_stream_pkt));
	if (!p) {
		pom_oom(sizeof(struct proto_rtp_stream_pkt));
		return POM_ERR;
	}
	memset(p, 0, sizeof(struct proto_rtp_stream_pkt));

	p->pkt = packet_clone(pkt, 0);
	if (!p->pkt) {
		free(p);
		return POM_ERR;
	}

	p->stack = core_stack_backup(stack, pkt, p->pkt);
	p->stack_index = stack_index;
	p->seq = seq;

	if (!stream->head)
		conntrack_timer_queue(stream->t, *PTYPE_UINT32_GETVAL(proto_rtp_p_buffer_timeout), pkt->ts);

	if (!tmp) {
		// Packet goes at the head
		p->next = stream->head;
		if (p->next)
			p->next->prev = p;
		else
			stream->tail = p;
		stream->head = p;
	} else {
		// Packet goes after the current one
		p->next = tmp->next;
		p->prev = tmp;

		if (p->next)
			p->next->prev = p;
		else
			stream->tail = p;
		tmp->next = p;
	}

	return POM_OK;
}

static int proto_rtp_stream_cleanup(struct proto_rtp_stream *stream) {

	if (stream->t)
		conntrack_timer_cleanup(stream->t);

	int res = POM_OK;

	while (stream->head) {
		struct proto_rtp_stream_pkt *tmp = stream->head;
		stream->head = tmp->next;

		res += core_process_multi_packet(tmp->stack, tmp->stack_index + 1, tmp->pkt);
		core_stack_release(tmp->stack);
		packet_release(tmp->pkt);

		free(tmp);
	}

	free(stream);

	return (res ? POM_ERR : POM_OK);
}
