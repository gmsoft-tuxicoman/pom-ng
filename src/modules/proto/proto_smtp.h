/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2013 Guy Martin <gmsoft@tuxicoman.be>
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

#ifndef __PROTO_SMTP_H__
#define __PROTO_SMTP_H__


#include <pom-ng/proto_smtp.h>

#define SMTP_MAX_LINE 4096

// Either if it's invalid or encrypted
#define PROTO_SMTP_FLAG_INVALID			0x1
#define PROTO_SMTP_FLAG_CLIENT_DATA		0x2
#define PROTO_SMTP_FLAG_CLIENT_DATA_END		0x4
#define PROTO_SMTP_FLAG_STARTTLS		0x8

#define PROTO_SMTP_DATA_END		"\r\n.\r\n"

struct proto_smtp_priv {

	struct event_reg *evt_cmd;
	struct event_reg *evt_reply;
};

struct proto_smtp_conntrack_priv {

	struct packet_stream_parser *parser[POM_DIR_TOT];
	uint32_t flags;
	int server_direction;
//	unsigned int data_end_pos;
	struct event *data_evt, *reply_evt;
};

struct mod_reg_info* proto_smtp_reg_info();
static int proto_smtp_init(struct proto *proto, struct registry_instance *i);
static int proto_smtp_cleanup(void *proto_priv);
static int proto_smtp_mod_register(struct mod_reg *mod);
static int proto_smtp_process(void *proto_priv, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index);
static int proto_smtp_post_process(void *proto_priv, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index);
static int proto_smtp_conntrack_cleanup(void *ce_priv);
static int proto_smtp_mod_unregister();

#endif
