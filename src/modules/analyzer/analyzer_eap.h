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

#ifndef __ANALYZER_EAP_H__
#define __ANALYZER_EAP_H__

#include <pom-ng/event.h>

#define ANALYZER_EAP_MD5_AUTH_DATA_COUNT 9

struct analyzer_eap_priv {


	struct event_reg *evt_md5_challenge;
	struct event_reg *evt_success_failure;

	struct event_reg *evt_md5_auth;

};

struct analyzer_eap_ce_priv {


	struct event *evt_request;
	struct event *evt_response;
	struct event *evt_result;

	struct event *evt;

	struct ptype *client, *server;
	struct ptype *vlan;
	char *top_proto;

};


enum {
	analyzer_eap_common_client = 0,
	analyzer_eap_common_server,
	analyzer_eap_common_top_proto,
	analyzer_eap_common_vlan,
	analyzer_eap_common_identifier,
	analyzer_eap_common_username,
	analyzer_eap_common_success
};

enum {
	analyzer_eap_md5_challenge = analyzer_eap_common_success + 1,
	analyzer_eap_md5_response
};

int analyzer_eap_mod_register(struct mod_reg *mod);
int analyzer_eap_mod_unregister();
int analyzer_eap_init(struct analyzer *analyzer);
int analyzer_eap_cleanup(struct analyzer *analyzer);
int analyzer_eap_event_listeners_notify(void *obj, struct event_reg *evt_reg, int has_listeners);
int analyzer_eap_event_process_begin(struct event *evt, void *obj, struct proto_process_stack *stack, unsigned int stack_index);
int analyzer_eap_finalize(struct analyzer_eap_priv *apriv, struct analyzer_eap_ce_priv *cpriv);
int analyzer_eap_ce_priv_cleanup(void *obj, void *priv);

#endif
