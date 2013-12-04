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

#ifndef __PROTO_EAP_H__
#define __PROTO_EAP_H__

struct eap_header
{
	uint8_t  code;
	uint8_t  identifier;
	uint16_t length;
} __attribute__ ((__packed__));

#define PROTO_EAP_FIELD_NUM 2

#define PROTO_EAP_EVT_IDENTITY_DATA_COUNT		3
#define PROTO_EAP_EVT_MD5_CHALLENGE_DATA_COUNT		4
#define PROTO_EAP_EVT_SUCCESS_FAILURE_DATA_COUNT	2

enum proto_eap_fields {
	proto_eap_field_code = 0,
	proto_eap_field_identifier
};

struct proto_eap_priv {

	struct ptype *p_timeout;
	struct event_reg *evt_identity;
	struct event_reg *evt_md5_challenge;
	struct event_reg *evt_success_failure;

};

struct mod_reg_info* proto_eap_reg_info();
static int proto_eap_mod_register(struct mod_reg *mod);
static int proto_eap_init(struct proto *proto, struct registry_instance *i);
static int proto_eap_cleanup(void *proto_priv);
static int proto_eap_process(void *proto_priv, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index);
static int proto_eap_mod_unregister();

#endif
