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

#ifndef __PROTO_TCP_H__
#define __PROTO_TCP_H__

#include <pom-ng/packet.h>

#define PROTO_TCP_FIELD_NUM 6

#define PROTO_TCP_SEQ_KNOWN_DIR_FWD	0x01
#define PROTO_TCP_SEQ_KNOWN_DIR_REV	0x02
#define PROTO_TCP_SEQ_ASSURED		0x04
#define PROTO_TCP_CLIENT_DIR_IS_FWD	0x08
#define PROTO_TCP_CLIENT_DIR_IS_REV	0x10
#define PROTO_TCP_FIN_RECV_FWD		0x20
#define PROTO_TCP_FIN_RECV_REV		0x40
#define PROTO_TCP_FIN_RECV_BOTH		(PROTO_TCP_FIN_RECV_FWD | PROTO_TCP_FIN_RECV_REV)

enum
{
	TCP_STATE_NEW = 0, // State not known yet
	TCP_STATE_SYN_SENT,
	TCP_STATE_SYN_RECV,  
	TCP_STATE_ESTABLISHED,
	TCP_STATE_HALF_CLOSED,
	TCP_STATE_CLOSED,
};

enum proto_tcp_fields {
	proto_tcp_field_sport = 0,
	proto_tcp_field_dport,
	proto_tcp_field_flags,
	proto_tcp_field_seq,
	proto_tcp_field_ack,
	proto_tcp_field_win,
};

struct proto_tcp_priv {

	struct ptype *param_tcp_syn_sent_t;
	struct ptype *param_tcp_syn_recv_t;
	struct ptype *param_tcp_established_t;
	struct ptype *param_tcp_half_closed_t;
	struct ptype *param_tcp_closed_t;
	struct ptype *param_tcp_reuse_handling;
	struct ptype *param_tcp_conn_buffer;
	struct ptype *param_tcp_stream_timeout;
	struct proto *proto_http;
};

struct proto_tcp_conntrack_priv {

	unsigned int state;
	struct stream *stream;
	struct proto *proto;
	uint32_t start_seq[POM_DIR_TOT];
	int flags;
};

struct mod_reg_info* proto_tcp_reg_info();
static int proto_tcp_init(struct proto *proto, struct registry_instance *i);
static int proto_tcp_mod_register(struct mod_reg *mod);
static int proto_tcp_process(void *proto_priv, struct packet *p, struct proto_process_stack *s, unsigned int stack_index);
static int proto_tcp_process_payload(struct conntrack_entry *ce, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index);
static int proto_tcp_conntrack_cleanup(void *ce_priv);
static int proto_tcp_cleanup(void *proto_priv);
static int proto_tcp_mod_unregister();

#endif
