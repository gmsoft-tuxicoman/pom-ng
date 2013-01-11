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

#ifndef __PROTO_MPEG_TS_H__
#define __PROTO_MPEG_TS_H__

#include <pom-ng/proto.h>
#include <pom-ng/timer.h>
#include <pom-ng/input.h>

#define MPEG_TS_LEN 188

#define MPEG_TS_DOCSIS_PID 0x1FFE
#define MPEG_TS_NULL_PID 0x1FFF

#define PROTO_MPEG_TS_FIELD_NUM 1

enum proto_mpeg_ts_fields {
	proto_mpeg_ts_field_pid,
};

enum proto_mpeg_stream_type {
	proto_mpeg_stream_type_pes,
	proto_mpeg_stream_type_sect,
	proto_mpeg_stream_type_docsis,
};

struct proto_mpeg_ts_priv {
	struct proto *proto_docsis;
	struct proto *proto_mpeg_sect;

	struct ptype *param_mpeg_ts_stream_timeout;
};

struct proto_mpeg_ts_stream {

	struct input *input;
	unsigned int pkt_cur_len;
	unsigned int pkt_tot_len;
	struct packet_multipart *multipart;
	struct packet_stream *stream;
	struct proto_mpeg_ts_priv *ppriv;

	enum proto_mpeg_stream_type type;

	uint16_t last_seq;
	struct timer *t;

	struct conntrack_entry *ce;

	struct mpeg_ts_stream *prev, *next;

};

struct proto_mpeg_ts_conntrack_priv {
	unsigned int streams_array_size;
	struct proto_mpeg_ts_stream *streams;
};

int proto_mpeg_ts_init(struct proto *proto, struct registry_instance *i);
int proto_mpeg_ts_process(void *proto_priv, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index);
int proto_mpeg_ts_process_stream(void *priv, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index);
int proto_mpeg_ts_stream_cleanup(void *, struct timeval *now);
int proto_mpeg_ts_conntrack_cleanup(void *ce_priv);
int proto_mpeg_ts_cleanup(void *proto_priv);

#endif
