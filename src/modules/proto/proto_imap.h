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
#include <pom-ng/decoder.h>

#define IMAP_MAX_LINE 4096

struct proto_imap_priv {

	struct event_reg *evt_cmd;
	struct event_reg *evt_rsp;
	struct event_reg *evt_pload;
};

enum proto_imap_state {
	proto_imap_state_normal = 0,
	proto_imap_state_invalid,
	proto_imap_state_compress_req,
	proto_imap_state_compress,
	proto_imap_state_starttls_req,
	proto_imap_state_starttls

};

struct proto_imap_conntrack_priv {

	struct packet_stream_parser *parser[POM_DIR_TOT];
	int server_direction;
	enum proto_imap_state state;
	struct decoder *comp_dec[POM_DIR_TOT];
	struct event *data_evt, *cmd_evt, *rsp_evt, *pload_evt[POM_DIR_TOT];
	uint64_t data_bytes[POM_DIR_TOT];
	uint32_t flags;
};

struct mod_reg_info* proto_imap_reg_info();
static int proto_imap_init(struct proto *proto, struct registry_instance *i);
static int proto_imap_cleanup(void *proto_priv);
static int proto_imap_mod_register(struct mod_reg *mod);
static int proto_imap_process(void *proto_priv, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index);
static int proto_imap_conntrack_cleanup(void *ce_priv);
static int proto_imap_mod_unregister();

#endif
