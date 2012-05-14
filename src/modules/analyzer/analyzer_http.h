/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2011 Guy Martin <gmsoft@tuxicoman.be>
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

#ifndef __ANALYZER_HTTP_H__
#define __ANALYZER_HTTP_H__

#include <pom-ng/conntrack.h>
#include <pom-ng/event.h>
#include <pom-ng/analyzer.h>
#include <pom-ng/analyzer_http.h>

struct analyzer_http_priv {
	
	struct ptype *ptype_string;
	struct ptype *ptype_uint64;
	struct event_reg *evt_request;

	struct event_reg *evt_query;
	struct event_reg *evt_response;

	struct proto_dependency *proto_http;
	struct proto_packet_listener *http_packet_listener;
};

struct analyzer_http_event_list {

	struct event *evt;
	struct analyzer_http_event_list *prev, *next;
};

struct analyzer_http_ce_priv {

	struct analyzer_http_event_list *evt_head, *evt_tail;

	int client_direction;

};

struct analyzer_http_request_event_priv {

	// Original events from which we base ours
	struct event *query_event;
	struct event *response_event;

	// Payload information
	struct analyzer_pload_buffer *pload[POM_DIR_TOT];
	char *content_type[POM_DIR_TOT];
	size_t content_len[POM_DIR_TOT];
	unsigned int content_flags[POM_DIR_TOT];

};


struct mod_reg_info* analyzer_http_reg_info();
int analyzer_http_mod_register(struct mod_reg *mod);
int analyzer_http_mod_unregister();

int analyzer_http_init(struct analyzer *analyzer);
int analyzer_http_cleanup(struct analyzer *analyzer);

int analyzer_http_event_listeners_notify(void *obj, struct event_reg *evt_reg, int has_listeners);
int analyzer_http_ce_priv_cleanup(void *obj, void *priv);

int analyzer_http_event_process_begin(struct event *evt, void *obj, struct proto_process_stack *stack, unsigned int stack_index);
int analyzer_http_event_process_end(struct event *evt, void *obj);
int analyzer_http_event_finalize_process(struct analyzer_http_ce_priv *priv);
int analyzer_http_request_event_cleanup(struct event *evt);


int analyzer_http_proto_packet_process(void *object, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index);

#endif

