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

#define PROTO_PPP_CHAP_FIELDS 2

#define PROTO_PPP_CHAP_EVT_CHALLENGE_RESPONSE_DATA_COUNT	4
#define PROTO_PPP_CHAP_EVT_SUCCESS_FAILURE_DATA_COUNT		3

enum proto_ppp_chap_fields {

	proto_ppp_chap_field_code = 0,
	proto_ppp_chap_field_identifier
};

struct ppp_chap_header {
	uint8_t code;
	uint8_t identifier;
	uint16_t length;
} __attribute__ ((__packed__));


struct proto_ppp_chap_priv {
	struct event_reg *evt_challenge_response;
	struct event_reg *evt_success_failure;
};

enum {
	evt_ppp_chap_challenge_response_code = 0,
	evt_ppp_chap_challenge_response_identifier,
	evt_ppp_chap_challenge_response_value,
	evt_ppp_chap_challenge_response_name
};

enum {
	evt_ppp_chap_success_failure_code = 0,
	evt_ppp_chap_success_failure_identifier,
	evt_ppp_chap_success_failure_message
};

struct mod_reg_info* proto_ppp_chap_reg_info();
static int proto_ppp_chap_init(struct proto *proto, struct registry_instance *i);
static int proto_ppp_chap_cleanup(void *proto_priv);
static int proto_ppp_chap_mod_register(struct mod_reg *mod);
static int proto_ppp_chap_process(void *proto_priv, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index);
static int proto_ppp_chap_mod_unregister();

#endif
