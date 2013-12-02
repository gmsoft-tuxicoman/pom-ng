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

#ifndef __ANALYZER_PPP_PAP_H__
#define __ANALYZER_PPP_PAP_H__

#include <pom-ng/event.h>

#define ANALYZER_PPP_PAP_AUTH_DATA_COUNT 8


struct analyzer_ppp_pap_priv {


	struct event_reg *evt_request;
	struct event_reg *evt_ack_nack;

	struct event_reg *evt_auth;

};

struct analyzer_ppp_pap_ce_priv {


	struct event *evt_request;
	struct event *evt_ack_nack;

	struct event *evt;

	struct ptype *client, *server;
	struct ptype *vlan;
	char *top_proto;

};


enum {
	analyzer_ppp_pap_auth_client = 0,
	analyzer_ppp_pap_auth_server,
	analyzer_ppp_pap_auth_top_proto,
	analyzer_ppp_pap_auth_vlan,
	analyzer_ppp_pap_auth_identifier,
	analyzer_ppp_pap_auth_success,
	analyzer_ppp_pap_auth_peer_id,
	analyzer_ppp_pap_auth_password
};


int analyzer_ppp_pap_mod_register(struct mod_reg *mod);
int analyzer_ppp_pap_mod_unregister();
int analyzer_ppp_pap_init(struct analyzer *analyzer);
int analyzer_ppp_pap_cleanup(struct analyzer *analyzer);
int analyzer_ppp_pap_event_listeners_notify(void *obj, struct event_reg *evt_reg, int has_listeners);
int analyzer_ppp_pap_event_process_begin(struct event *evt, void *obj, struct proto_process_stack *stack, unsigned int stack_index);
int analyzer_ppp_pap_finalize(struct analyzer_ppp_pap_priv *apriv, struct analyzer_ppp_pap_ce_priv *cpriv);
int analyzer_ppp_pap_ce_priv_cleanup(void *obj, void *priv);

#endif
