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

#ifndef __PROTO_PPP_CHAP_H__
#define __PROTO_PPP_CHAP_H__

#define PROTO_PPP_PAP_FIELDS 2

#define PROTO_PPP_PAP_EVT_REQUEST_DATA_COUNT	4
#define PROTO_PPP_PAP_EVT_ACK_NACK_DATA_COUNT	3

#include <pom-ng/proto_ppp_pap.h>

enum proto_ppp_pap_fields {

	proto_ppp_pap_field_code = 0,
	proto_ppp_pap_field_identifier
};

struct ppp_pap_header {
	uint8_t code;
	uint8_t identifier;
	uint16_t length;
} __attribute__ ((__packed__));


struct proto_ppp_pap_priv {
	struct ptype *p_auth_timeout;
	struct event_reg *evt_request;
	struct event_reg *evt_ack_nack;
};

struct mod_reg_info* proto_ppp_pap_reg_info();
static int proto_ppp_pap_init(struct proto *proto, struct registry_instance *i);
static int proto_ppp_pap_cleanup(void *proto_priv);
static int proto_ppp_pap_mod_register(struct mod_reg *mod);
static int proto_ppp_pap_process(void *proto_priv, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index);
static int proto_ppp_pap_mod_unregister();

#endif
