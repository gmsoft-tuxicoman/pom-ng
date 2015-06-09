/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2010-2014 Guy Martin <gmsoft@tuxicoman.be>
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

#define PROTO_EXPECTATION_FLAG_QUEUED	0x1
#define PROTO_EXPECTATION_FLAG_MATCHED	0x2

struct proto {

	struct proto_reg_info *info;

	unsigned int id;
	
	/// Conntrack tables
	struct conntrack_tables *ct;

	struct registry_instance *reg_instance;

	void *priv;

	pthread_rwlock_t listeners_lock;
	struct proto_packet_listener *packet_listeners;
	struct proto_packet_listener *payload_listeners;

	pthread_rwlock_t expectation_lock;
	struct proto_expectation *expectations;

	struct proto_number_class *number_class;

	struct registry_perf *perf_pkts;
	struct registry_perf *perf_bytes;
	struct registry_perf *perf_conn_cur;
	struct registry_perf *perf_conn_tot;
	struct registry_perf *perf_conn_hash_col;
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
	void *priv, *callback_priv;
	void (*callback_priv_cleanup) (void *priv);
	struct timer *expiry;
	struct conntrack_session *session;
	struct proto_expectation *prev, *next;
	int flags;
	void (*match_callback) (struct proto_expectation *e, void *callback_priv, struct conntrack_entry *ce);
};

struct proto_number {

	struct proto *proto;
	unsigned int val;
	struct proto_number *prev, *next;
};

struct proto_number_class {
	char *name;
	size_t size;
	
	struct proto_number_class *next;
	struct proto_number *nums;
};

int proto_init();
int proto_process_pload_listeners(struct packet *p, struct proto_process_stack *s, unsigned int stack_index);
int proto_finish();
int proto_cleanup();

int proto_expectation_timeout(void *priv, ptime now);

unsigned int proto_get_count();
struct proto_number_class *proto_number_class_get(char *name);
int proto_number_unregister(struct proto *p);

#endif
