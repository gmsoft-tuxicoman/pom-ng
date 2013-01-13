/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2010-2012 Guy Martin <gmsoft@tuxicoman.be>
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


#ifndef __PROTO_H__
#define __PROTO_H__

#include <pom-ng/proto.h>
#include "packet.h"
#include "conntrack.h"
#include "registry.h"

#define PROTO_REGISTRY "proto"

struct proto {

	struct proto_reg_info *info;
	
	/// Conntrack tables
	struct conntrack_tables *ct;

	// Packet info pool
	struct packet_info_pool pkt_info_pool;

	struct registry_instance *reg_instance;

	void *priv;

	struct proto_packet_listener *packet_listeners;
	struct proto_packet_listener *payload_listeners;

	pthread_rwlock_t expectation_lock;
	struct proto_expectation *expectations;

	struct registry_perf *perf_pkts;
	struct registry_perf *perf_bytes;
	struct registry_perf *perf_conn_cur;
	struct registry_perf *perf_conn_tot;
	struct registry_perf *perf_expt_pending;
	struct registry_perf *perf_expt_matched;

	struct proto *next, *prev;

};

struct proto_event_analyzer_list {

	struct proto_event_analyzer_reg *analyzer_reg;
	struct proto_event_analyzer_list *next, *prev;

};

struct proto_expectation_stack {
	
	struct proto *proto;
	struct ptype *fields[POM_DIR_TOT];
	struct proto_expectation_stack *prev, *next;
};

struct proto_expectation {
	struct proto_expectation_stack *head, *tail;
	struct proto *proto;
	void *priv;
	struct timer *expiry;
	struct conntrack_session *session;
	struct proto_expectation *prev, *next;
};


int proto_init();
int proto_process_listeners(struct packet *p, struct proto_process_stack *s, unsigned int stack_index);
int proto_empty_conntracks();
int proto_cleanup();

int proto_expectation_expiry(void *priv, struct timeval *tv);

#endif
