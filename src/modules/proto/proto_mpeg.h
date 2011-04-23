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

#ifndef __PROTO_MPEG_H__
#define __PROTO_MPEG_H__

#include <pom-ng/proto.h>
#include <pom-ng/timer.h>

#define MPEG_TS_LEN 188

#define MPEG_TS_DOCSIS_PID 0x1FFE
#define MPEG_TS_NULL_PID 0x1FFF

#define PROTO_MPEG_TS_FIELD_NUM 1

enum proto_mpeg_ts_fields {
	proto_mpeg_ts_field_pid,
};

struct proto_mpeg_ts_stream {

	unsigned int input_id;
	unsigned int pkt_cur_len;
	unsigned int pkt_tot_len;
	struct packet_multipart *multipart;
	struct packet_stream *stream;

	uint16_t last_seq;
	struct timer *t;

	struct conntrack_entry *ce;

	struct mpeg_ts_stream *prev, *next;

};

struct proto_mpeg_ts_conntrack_priv {
	unsigned int streams_array_size;
	struct proto_mpeg_ts_stream *streams;
};

struct mod_reg_info* proto_mpeg_reg_info();
static int proto_mpeg_mod_register(struct mod_reg *mod);
static int proto_mpeg_mod_unregister();

static int proto_mpeg_ts_init(struct registry_instance *i);
static int proto_mpeg_ts_process(struct packet *p, struct proto_process_stack *stack, unsigned int stack_index);
static int proto_mpeg_ts_process_docsis(void *priv, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index);
static int proto_mpeg_ts_stream_cleanup(void *);
static int proto_mpeg_ts_conntrack_cleanup(struct conntrack_entry *ce);
static int proto_mpeg_ts_cleanup();

#endif
