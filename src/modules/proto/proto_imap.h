/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2015 Guy Martin <gmsoft@tuxicoman.be>
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

#ifndef __PROTO_IMAP_H__
#define __PROTO_IMAP_H__


#include <pom-ng/proto_imap.h>

#define IMAP_MAX_LINE 4096

// Either if it's invalid or encrypted
#define PROTO_IMAP_FLAG_INVALID			0x1
#define PROTO_IMAP_RSP_LINE_REMAINING		0x2
#define PROTO_IMAP_FLAG_STARTTLS		0x4

struct proto_imap_priv {

	struct event_reg *evt_cmd;
	struct event_reg *evt_rsp;
};

struct proto_imap_conntrack_priv {

	struct packet_stream_parser *parser[POM_DIR_TOT];
	int server_direction;
	struct event *data_evt, *rsp_evt;
	uint64_t data_bytes[POM_DIR_TOT];
	struct ptype *rsp_cur_line;
	uint32_t flags;
	uint16_t rsp_line_id;
};

struct mod_reg_info* proto_imap_reg_info();
static int proto_imap_init(struct proto *proto, struct registry_instance *i);
static int proto_imap_cleanup(void *proto_priv);
static int proto_imap_mod_register(struct mod_reg *mod);
static int proto_imap_process(void *proto_priv, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index);
static int proto_imap_conntrack_cleanup(void *ce_priv);
static int proto_imap_mod_unregister();

#endif
