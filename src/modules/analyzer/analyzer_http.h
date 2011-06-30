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
#include <pom-ng/packet.h>
#include <pom-ng/proto.h>
#include <pom-ng/analyzer.h>
#include <pom-ng/analyzer_http.h>

struct analyzer_http_priv {
	struct proto_dependency *proto_http;
};

#define ANALYZER_HTTP_GOT_QUERY_EVT	0x1
#define ANALYZER_HTTP_GOT_RESPONSE_EVT	0x2


struct analyzer_http_ce_priv {
	unsigned int flags;
	struct analyzer_event evt;
};


struct mod_reg_info* analyzer_http_reg_info();
static int analyzer_http_mod_register(struct mod_reg *mod);
static int analyzer_http_mod_unregister();

static int analyzer_http_init(struct analyzer_reg *analyzer);
static int analyzer_http_cleanup(struct analyzer_reg *analyzer);

static int analyzer_http_event_listeners_notify(struct analyzer_reg *analyzer, struct analyzer_event_reg *event, int has_listeners);
static int analyzer_http_event_reset(struct analyzer_event *evt);
static int analyzer_http_ce_priv_cleanup(void *obj, void *priv);
static int analyzer_http_proto_event_process(struct analyzer_reg *analyzer, struct proto_event *evt, struct proto_process_stack *stack, unsigned int stack_index);
static int analyzer_http_proto_event_expire(struct analyzer_reg *analyzer, struct proto_event *evt, struct conntrack_entry *ce);


#endif

