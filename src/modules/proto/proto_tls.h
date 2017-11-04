/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2017 Guy Martin <gmsoft@tuxicoman.be>
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

#ifndef __PROTO_TLS_H__
#define __PROTO_TLS_H__

#include <pom-ng/proto.h>

#define PROTO_TLS_FIELD_NUM 3

enum proto_tls_fields {
	proto_tls_field_version_major = 0,
	proto_tls_field_version_minor,
	proto_tls_field_length,
	proto_tls_field_last
};

#define PROTO_TLS_HANDSHAKE_FIELD_NUM 4
#define PROTO_TLS_HANDSHAKE_HDR_SIZE 4

enum proto_tls_handshake_fields {
	proto_tls_handshake_field_type = proto_tls_field_last
};

struct tls_header {
	uint8_t content_type;
	uint8_t version_major;
	uint8_t version_minor;
	uint16_t length;
} __attribute__ ((__packed__));


struct proto_tls_conntrack_priv {
	struct packet_stream_parser *parser;
};

struct mod_reg_info* proto_tls_reg_info();
static int proto_tls_mod_unregister();
static int proto_tls_mod_register(struct mod_reg *mod);

static int proto_tls_init(struct proto *proto, struct registry_instance *i);
static int proto_tls_process(void *proto_priv, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index);
static int proto_tls_conntrack_cleanup(void *ce_priv);

static int proto_tls_changecipherspec_init(struct proto *proto, struct registry_instance *i);
static int proto_tls_changecipherspec_process(void *proto_priv, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index);

static int proto_tls_alert_init(struct proto *proto, struct registry_instance *i);
static int proto_tls_alert_process(void *proto_priv, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index);

static int proto_tls_handshake_init(struct proto *proto, struct registry_instance *i);
static int proto_tls_handshake_process(void *proto_priv, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index);

static int proto_tls_appdata_init(struct proto *proto, struct registry_instance *i);
static int proto_tls_appdata_process(void *proto_priv, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index);

#endif
