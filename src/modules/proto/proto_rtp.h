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

#ifndef __PROTO_RTP_H__
#define __PROTO_RTP_H__

#define PROTO_RTP_FIELD_NUM 4

enum proto_rtp_fields {
	proto_rtp_field_pt = 0,
	proto_rtp_field_ssrc,
	proto_rtp_field_seq,
	proto_rtp_field_timestamp,
};

struct proto_rtp_priv {

	struct ptype *p_buffer_timeout;
	struct ptype *p_stream_timeout;
};

struct proto_rtp_stream_pkt {

	struct packet *pkt;
	struct proto_process_stack *stack;
	unsigned int stack_index;

	struct proto_rtp_stream_pkt *prev, *next;

	uint16_t seq;
};

struct proto_rtp_stream {

	struct conntrack_timer *t;
	struct proto_rtp_stream_pkt *head, *tail;
	struct proto_rtp_stream *prev, *next;
	uint32_t ssrc;
	uint16_t next_seq;
};

struct proto_rtp_conntrack_priv {

	struct proto_rtp_stream *streams;
};

struct mod_reg_info* proto_rtp_reg_info();
static int proto_rtp_mod_register(struct mod_reg *mod);
static int proto_rtp_mod_unregister();
static int proto_rtp_init(struct proto *proto, struct registry_instance *i);
static int proto_rtp_cleanup(void *proto_priv);
static int proto_rtp_process(void *proto_priv, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index);
static int proto_rtp_conntrack_cleanup(void *ce_priv);
static struct proto_rtp_stream *proto_rtp_stream_alloc(struct conntrack_entry *ce, uint32_t ssrc, uint16_t init_seq);
static int proto_rtp_stream_timeout(struct conntrack_entry *ce, void *priv, ptime now);
static int proto_rtp_stream_process_packet(struct proto_rtp_stream *stream, struct packet *pkt, struct proto_process_stack *stack, unsigned int stack_index, uint16_t seq);
static int proto_rtp_stream_cleanup(struct proto_rtp_stream *stream);

#endif
