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



#include "common.h"
#include "proto.h"
#include "main.h"
#include "mod.h"
#include "filter.h"


#if 0
#define debug_expectation(x ...) pomlog(POMLOG_DEBUG x)
#else
#define debug_expectation(x ...)
#endif

static struct proto *proto_head = NULL;

static struct registry_class *proto_registry_class = NULL;

static struct proto_number_class *proto_number_class_head = NULL;

unsigned int proto_count = 0;

int proto_init() {
	
	proto_registry_class = registry_add_class(PROTO_REGISTRY);
	if (!proto_registry_class)
		return POM_ERR;

	return POM_OK;
}

int proto_register(struct proto_reg_info *reg_info) {

	if (reg_info->api_ver != PROTO_API_VER) {
		pomlog(POMLOG_ERR "Cannot register proto as API version differ : expected %u got %u", PROTO_API_VER, reg_info->api_ver);
		return POM_ERR;
	}


	// Check if the protocol already exists
	struct proto *proto;
	for (proto = proto_head; proto && strcmp(proto->info->name, reg_info->name); proto = proto->next);
	if (proto)
		return POM_ERR;

	// Allocate the protocol
	proto = malloc(sizeof(struct proto));
	if (!proto) {
		pom_oom(sizeof(struct proto));
		return POM_ERR;
	}

	memset(proto, 0, sizeof(struct proto));
	proto->info = reg_info;
	proto->id = proto_count;
	proto_count++;

	if (reg_info->number_class) {
		proto->number_class = proto_number_class_get(reg_info->number_class);
		if (!proto->number_class)
			goto err_proto;
	}

	int res = pthread_rwlock_init(&proto->expectation_lock, NULL);
	if (res) {
		pomlog(POMLOG_ERR "Error while initializing the proto_expectation rwlock : %s", pom_strerror(res));	
		goto err_proto;
	}

	res = pthread_rwlock_init(&proto->listeners_lock, NULL);
	if (res) {
		pomlog(POMLOG_ERR "Error while initializing the proto_listeners rwlock : %s", pom_strerror(res));
		goto err_lock1;
	}

	proto->reg_instance = registry_add_instance(proto_registry_class, reg_info->name);
	if (!proto->reg_instance) {
		pomlog(POMLOG_ERR "Error while adding the registry instanc for protocol %s", reg_info->name);
		goto err_lock;
	}


	// Allocate the conntrack table
	if (reg_info->ct_info) {
		proto->ct = conntrack_table_alloc(reg_info->ct_info->default_table_size, (reg_info->ct_info->rev_pkt_field_id == -1 ? 0 : 1));
		if (!proto->ct) {
			pomlog(POMLOG_ERR "Error while allocating conntrack tables");
			goto err_registry;
		}

		proto->perf_conn_cur = registry_instance_add_perf(proto->reg_instance, "conn_cur", registry_perf_type_gauge, "Current number of monitored connection", "connections");
		proto->perf_conn_tot = registry_instance_add_perf(proto->reg_instance, "conn_tot", registry_perf_type_counter, "Total number of connections", "connections");
		proto->perf_conn_hash_col = registry_instance_add_perf(proto->reg_instance, "conn_hash_col", registry_perf_type_counter, "Total number of conntrack hash collisions", "collisions");

		if (!proto->perf_conn_cur || !proto->perf_conn_tot || !proto->perf_conn_hash_col)
			goto err_conntrack;

	}

	proto->perf_pkts = registry_instance_add_perf(proto->reg_instance, "pkts", registry_perf_type_counter, "Number of packets processed", "pkts");
	proto->perf_bytes = registry_instance_add_perf(proto->reg_instance, "bytes", registry_perf_type_counter, "Number of bytes processed", "bytes");
	proto->perf_expt_pending = registry_instance_add_perf(proto->reg_instance, "expectations_pending", registry_perf_type_gauge, "Number of expectations pending", "expectations");
	proto->perf_expt_matched = registry_instance_add_perf(proto->reg_instance, "expectations_matched", registry_perf_type_counter, "Number of expectations matched", "expectations");

	if (!proto->perf_pkts || !proto->perf_bytes || !proto->perf_expt_pending || !proto->perf_expt_matched)
		goto err_conntrack;

	if (reg_info->init) {
		if (reg_info->init(proto, proto->reg_instance) == POM_ERR) {
			pomlog(POMLOG_ERR "Error while registering proto %s", reg_info->name);
			goto err_conntrack;
		}
	}

	mod_refcount_inc(reg_info->mod);

	proto->next = proto_head;
	if (proto->next)
		proto->next->prev = proto;
	proto_head = proto;

	pomlog(POMLOG_DEBUG "Proto %s registered", reg_info->name);

	return POM_OK;

err_conntrack:
	// Remove proto number if any
	proto_number_unregister(proto);
	conntrack_table_cleanup(proto->ct);
err_registry:
	registry_remove_instance(proto->reg_instance);
err_lock:
	pthread_rwlock_destroy(&proto->listeners_lock);
err_lock1:
	pthread_rwlock_destroy(&proto->expectation_lock);
err_proto:
	free(proto);

	return POM_ERR;

}

int proto_process(struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct proto_process_stack *s = &stack[stack_index];

	struct proto *proto = s->proto;

	if (!proto || !proto->info->process)
		return PROTO_ERR;
	int res = proto->info->process(proto->priv, p, stack, stack_index);

	registry_perf_inc(proto->perf_pkts, 1);
	registry_perf_inc(proto->perf_bytes, s->plen);

	if (res != PROTO_OK)
		return res;

	int matched = 0;

	// Process the expectations !
	pom_rwlock_rlock(&proto->expectation_lock);
	struct proto_expectation *e = NULL;
	for (e = proto->expectations; e; e = e->next) {

		if (e->flags & PROTO_EXPECTATION_FLAG_MATCHED) {
			// Another thread already matched the expectation, continue
			continue;
		}
		
		// Bit one means it matches the forward direction
		// Bit two means it matches the reverse direction

		int expt_dir = 3;

		struct proto_expectation_stack *es = e->tail;
		int stack_index_tmp = stack_index;
		while (es) {

			struct proto_process_stack *s_tmp = &stack[stack_index_tmp];

			if (s_tmp->proto != es->proto) {
				expt_dir = 0;
				break;
			}

			struct ptype *fwd_value = s_tmp->pkt_info->fields_value[s_tmp->proto->info->ct_info->fwd_pkt_field_id];
			struct ptype *rev_value = s_tmp->pkt_info->fields_value[s_tmp->proto->info->ct_info->rev_pkt_field_id];

			if (expt_dir & 1) {
				if ((es->fields[POM_DIR_FWD] && !ptype_compare_val(PTYPE_OP_EQ, es->fields[POM_DIR_FWD], fwd_value)) ||
					(es->fields[POM_DIR_REV] && !ptype_compare_val(PTYPE_OP_EQ, es->fields[POM_DIR_REV], rev_value))) {
					expt_dir &= ~1; // It doesn't match in the forward direction
				}
			}

			if (expt_dir & 2) {
				if ((es->fields[POM_DIR_FWD] && !ptype_compare_val(PTYPE_OP_EQ, es->fields[POM_DIR_FWD], rev_value)) ||
					(es->fields[POM_DIR_REV] && !ptype_compare_val(PTYPE_OP_EQ, es->fields[POM_DIR_REV], fwd_value))) {
					expt_dir &= ~2;
				}
			}

			if (!expt_dir)
				break;

			es = es->prev;
			stack_index_tmp--;
		}

		if (expt_dir) {
			// It matched
			if (!(__sync_fetch_and_or(&e->flags, PROTO_EXPECTATION_FLAG_MATCHED) & PROTO_EXPECTATION_FLAG_MATCHED)) {
				// Something matched
				matched++;
			}
		}
	}
	pom_rwlock_unlock(&proto->expectation_lock);

	if (!matched)
		return POM_OK;

	// At least one expectation matched !
	debug_expectation("%u expectation matched !", matched);

	// Relock with write access
	pom_rwlock_wlock(&proto->expectation_lock);
	e = proto->expectations;
	while (e) {

		struct proto_expectation *cur = e;
		e = e->next;

		if (!(cur->flags & PROTO_EXPECTATION_FLAG_MATCHED))
			continue;

		// Remove the expectation from the conntrack
		if (cur->next)
			cur->next->prev = cur->prev;
		if (cur->prev)
			cur->prev->next = cur->next;
		else
			proto->expectations = cur->next;

		// Remove matched and queued flags
		__sync_fetch_and_and(&cur->flags, ~(PROTO_EXPECTATION_FLAG_MATCHED | PROTO_EXPECTATION_FLAG_QUEUED));

		struct proto_process_stack *s_next = &stack[stack_index + 1];
		s_next->proto = cur->proto;

		if (conntrack_get_unique_from_parent(stack, stack_index + 1) != POM_OK) {
			proto_expectation_cleanup(cur);
			continue;
		}

		if (!s_next->ce->priv) {
			s_next->ce->priv = cur->priv;
			// Prevent cleanup of private data while cleaning the expectation
			cur->priv = NULL;
		}


		if (cur->session) {
			if (conntrack_session_bind(s_next->ce, cur->session)) {
				proto_expectation_cleanup(cur);
				continue;
			}
		}

		registry_perf_dec(cur->proto->perf_expt_pending, 1);
		registry_perf_inc(cur->proto->perf_expt_matched, 1);

		if (cur->match_callback) {
			// Call the callback with the conntrack locked
			cur->match_callback(cur, cur->callback_priv, s_next->ce);
			// Nullify callback_priv so it doesn't get cleaned up
			cur->callback_priv = NULL;
		}

		if (cur->expiry) {
			// The expectation was added using 'add_and_cleanup' function
			proto_expectation_cleanup(cur);
		}

		conntrack_unlock(s_next->ce);

	}
	pom_rwlock_unlock(&proto->expectation_lock);


	return res;
}


int proto_process_pload_listeners(struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	// Process payload listeners of the previous proto
	struct proto_process_stack *s = &stack[stack_index];
	struct proto_process_stack *s_next = &stack[stack_index + 1];
	struct proto *proto = s->proto;

	if (proto && s_next->plen) {
		
		struct proto_packet_listener *l;
		pom_rwlock_rlock(&proto->listeners_lock);
		for (l = proto->payload_listeners; l; l = l->next) {
			if (l->filter && !filter_packet_match(l->filter, stack))
				continue;
			if (l->process(l->object, p, stack, stack_index + 1) != POM_OK) {
				pomlog(POMLOG_WARN "Warning payload listener failed");
				// FIXME remove listener from the list ?
			}
		}
		pom_rwlock_unlock(&proto->listeners_lock);
	}

	return POM_OK;
}

int proto_post_process(struct packet *p, struct proto_process_stack *s, unsigned int stack_index) {

	if (!s)
		return PROTO_ERR;
	
	struct proto *proto = s[stack_index].proto;

	if (!proto)
		return PROTO_ERR;

	// Process the listeners after the whole stack has been processed
	struct proto_packet_listener *l;
	pom_rwlock_rlock(&proto->listeners_lock);
	for (l = proto->packet_listeners; l; l = l->next) {
		if (l->filter && !filter_packet_match(l->filter, s))
			continue;
		if (l->process(l->object, p, s, stack_index) != POM_OK) {
			pomlog(POMLOG_WARN "Warning packet listener failed");
			// FIXME remove listener from the list ?
		}
	}
	pom_rwlock_unlock(&proto->listeners_lock);

	if (proto->info->post_process)
		return proto->info->post_process(proto->priv, p, s, stack_index);

	return POM_OK;
}

int proto_unregister(char *name) {

	struct proto *proto;
	for (proto = proto_head; proto && strcmp(proto->info->name, name); proto = proto->next);
	if (!proto)
		return POM_OK;

	proto_number_unregister(proto);
	
	if (proto->info->cleanup && proto->info->cleanup(proto->priv)) {
		pomlog(POMLOG_ERR "Error while cleaning up the protocol %s", name);
		return POM_ERR;
	}

	if (proto->reg_instance)
		registry_remove_instance(proto->reg_instance);

		conntrack_table_cleanup(proto->ct);

	if (proto->next)
		proto->next->prev = proto->prev;
	if (proto->prev)
		proto->prev->next = proto->next;
	else
		proto_head = proto->next;

	mod_refcount_dec(proto->info->mod);

	free(proto);

	return POM_OK;
}

struct proto *proto_get(char *name) {
	
	struct proto *tmp;
	for (tmp = proto_head; tmp && strcmp(tmp->info->name, name); tmp = tmp->next);

	return tmp;
}

int proto_finish() {

	struct proto *proto;

	// Cleanup the expectations first
	for (proto = proto_head; proto; proto = proto->next) {
		while (proto->expectations) {
			struct proto_expectation *e = proto->expectations;
			proto->expectations = e->next;
			proto_expectation_cleanup(e);
		}
	}

	// Cleanup the conntracks
	for (proto = proto_head; proto; proto = proto->next) {
		conntrack_table_empty(proto->ct);
	}

	return POM_OK;
}

int proto_cleanup() {

	struct proto *proto;
	for (proto = proto_head; proto; proto = proto->next) {

		if (proto->info->cleanup && proto->info->cleanup(proto->priv) == POM_ERR)
			pomlog(POMLOG_WARN "Error while cleaning up protocol %s", proto->info->name);
		conntrack_table_cleanup(proto->ct);

		mod_refcount_dec(proto->info->mod);
	}

	while (proto_head) {
		proto = proto_head;
		proto_head = proto->next;

		int res = pthread_rwlock_destroy(&proto->listeners_lock);
		if (res)
			pomlog(POMLOG_ERR "Error while destroying the listners lock : %s", pom_strerror(res));
		res = pthread_rwlock_destroy(&proto->expectation_lock);
		if (res)
			pomlog(POMLOG_ERR "Error while destroying the listners lock : %s", pom_strerror(res));


		free(proto);
	}

	if (proto_registry_class)
		registry_remove_class(proto_registry_class);
	proto_registry_class = NULL;

	while (proto_number_class_head) {
		struct proto_number_class *cls = proto_number_class_head;
		proto_number_class_head = cls->next;
		while (cls->nums) {
			struct proto_number *num = cls->nums;
			cls->nums = num->next;
			free(num);
		}
		free(cls->name);
		free(cls);
	}

	return POM_OK;
}

struct proto_packet_listener *proto_packet_listener_register(struct proto *proto, unsigned int flags, void *object, int (*process) (void *object, struct packet *p, struct proto_process_stack *s, unsigned int stack_index), struct filter_node *f) {

	struct proto_packet_listener *l = malloc(sizeof(struct proto_packet_listener));
	if (!l) {
		pom_oom(sizeof(struct proto_packet_listener));
		return NULL;
	}
	memset(l, 0, sizeof(struct proto_packet_listener));

	l->flags = flags;
	l->process = process;
	l->proto = proto;
	l->object = object;
	l->filter = f;

	pom_rwlock_wlock(&proto->listeners_lock);

	if (l->flags & PROTO_PACKET_LISTENER_PLOAD_ONLY)
		l->next = proto->payload_listeners;
	else
		l->next = proto->packet_listeners;

	if (l->next)
		l->next->prev = l;

	if (l->flags & PROTO_PACKET_LISTENER_PLOAD_ONLY)
		proto->payload_listeners = l;
	else
		proto->packet_listeners = l;

	pom_rwlock_unlock(&l->proto->listeners_lock);

	return l;
}

int proto_packet_listener_unregister(struct proto_packet_listener *l) {

	if (!l)
		return POM_ERR;

	pom_rwlock_wlock(&l->proto->listeners_lock);

	if (l->next)
		l->next->prev = l->prev;

	if (l->prev) {
		l->prev->next = l->next;
	} else {
		if (l->flags & PROTO_PACKET_LISTENER_PLOAD_ONLY)
			l->proto->payload_listeners = l->next;
		else
			l->proto->packet_listeners = l->next;
	}

	pom_rwlock_unlock(&l->proto->listeners_lock);

	free(l);

	return POM_OK;
}

void proto_packet_listener_set_filter(struct proto_packet_listener *l, struct filter_node *f) {
	pom_rwlock_wlock(&l->proto->listeners_lock);
	l->filter = f;
	pom_rwlock_unlock(&l->proto->listeners_lock);
}


struct proto_expectation *proto_expectation_alloc(struct proto *proto, void *priv) {

	struct proto_expectation *res = malloc(sizeof(struct proto_expectation));
	if (!res) {
		pom_oom(sizeof(struct proto_expectation));
		return NULL;
	}
	memset(res, 0, sizeof(struct proto_expectation));
	
	res->priv = priv;
	res->proto = proto;

	debug_expectation("Expectation %p allocated", res);

	return res;
}

static struct proto_expectation_stack *proto_expectation_stack_alloc(struct proto *p, struct ptype *fwd_value, struct ptype *rev_value) {

	if (!p || !fwd_value) {
		pomlog(POMLOG_ERR "Cannot allocate expectation with a forward nor reverse conntrack entry field value");
		return NULL;
	}

	struct proto_expectation_stack *es = malloc(sizeof(struct proto_expectation_stack));
	if (!es) {
		pom_oom(sizeof(struct proto_expectation_stack));
		return NULL;
	}
	memset(es, 0, sizeof(struct proto_expectation_stack));
	es->proto = p;

	es->fields[POM_DIR_FWD] = ptype_alloc_from(fwd_value);
	if (!es->fields[POM_DIR_FWD]) {
		free(es);
		return NULL;
	}

	if (rev_value) {
		es->fields[POM_DIR_REV] = ptype_alloc_from(rev_value);
		if (!es->fields[POM_DIR_REV]) {
			ptype_cleanup(es->fields[POM_DIR_FWD]);
			free(es);
			return NULL;
		}
	}

	return es;
}

int proto_expectation_append(struct proto_expectation *e, struct proto *p, struct ptype *fwd_value, struct ptype *rev_value) {

	if (!e)
		return POM_ERR;

	struct proto_expectation_stack *es = proto_expectation_stack_alloc(p, fwd_value, rev_value);
	if (!es)
		return POM_ERR;

	es->prev = e->tail;

	if (es->prev)
		es->prev->next = es;
	else
		e->head = es;

	e->tail = es;

	return POM_OK;
}

int proto_expectation_prepend(struct proto_expectation *e, struct proto *p, struct ptype *fwd_value, struct ptype *rev_value) {

	if (!e)
		return POM_ERR;

	struct proto_expectation_stack *es = proto_expectation_stack_alloc(p, fwd_value, rev_value);
	if (!es)
		return POM_ERR;

	es->next = e->head;

	if (es->next)
		es->next->prev = es;
	else
		e->tail = es;

	e->head = es;

	return POM_OK;
}

struct proto_expectation *proto_expectation_alloc_from_conntrack(struct conntrack_entry *ce, struct proto *proto, void *priv) {

	struct proto_expectation *e = proto_expectation_alloc(proto, priv);

	if (!e)
		return NULL;

	if (!ce->fwd_value && !ce->rev_value) // This is a unique conntrack, match the upper layer instead
		ce = ce->parent->ce;

	while (1) {
		if (proto_expectation_prepend(e, ce->proto, ce->fwd_value, ce->rev_value) != POM_OK) {
			proto_expectation_cleanup(e);
			return NULL;
		}
	
		if (!ce->parent)
			break;

		ce = ce->parent->ce;
			
	}

	return e;
}

void proto_expectation_cleanup(struct proto_expectation *e) {

	if (!e)
		return;

	if (e->flags & PROTO_EXPECTATION_FLAG_QUEUED)
		proto_expectation_remove(e);

	debug_expectation("Cleaning up expectation %p", e);

	while (e->head) {
		struct proto_expectation_stack *es = e->head;
		e->head = es->next;
		if (es->fields[POM_DIR_FWD])
			ptype_cleanup(es->fields[POM_DIR_FWD]);
		if (es->fields[POM_DIR_REV])
			ptype_cleanup(es->fields[POM_DIR_REV]);
		
		free(es);

	}

	if (e->priv && e->proto->info->ct_info->cleanup_handler) {
		if (e->proto->info->ct_info->cleanup_handler(e->priv) != POM_OK)
			pomlog(POMLOG_WARN "Unable to free the conntrack priv of the proto_expectation");
	}

	if (e->session)
		conntrack_session_refcount_dec(e->session);

	if (e->expiry)
		timer_cleanup(e->expiry);

	if (e->callback_priv && e->callback_priv_cleanup)
		e->callback_priv_cleanup(e->callback_priv);

	free(e);
}

int proto_expectation_set_field(struct proto_expectation *e, int stack_index, struct ptype *value, int direction) {

	struct proto_expectation_stack *es = NULL;

	int i;
	if (stack_index > 0) {
		es = e->head;
		for (i = 1; es && i < stack_index; i++)
			es = es->next;
	} else {
		stack_index = -stack_index;
		es = e->tail;
		for (i = 1; es && i < stack_index; i++)
			es = es->prev;
	}

	if (!es) {
		pomlog(POMLOG_ERR "Invalid stack index in the expectation");
		return POM_ERR;
	}

	if (es->fields[direction]) {
		ptype_cleanup(es->fields[direction]);
		es->fields[direction] = NULL;
	}

	if (value) {
		es->fields[direction] = ptype_alloc_from(value);
		if (!es->fields[direction])
			return POM_ERR;
	}

	return POM_OK;
}

void proto_expectation_set_session(struct proto_expectation *e, struct conntrack_session *session) {

	conntrack_session_refcount_inc(session);
	e->session = session;
}

void proto_expectation_set_match_callback(struct proto_expectation *e, void (*match_callback) (struct proto_expectation *e, void *callback_priv, struct conntrack_entry *ce), void *callback_priv, void (*callback_priv_cleanup) (void *priv)) {

	e->match_callback = match_callback;
	e->callback_priv = callback_priv;
	e->callback_priv_cleanup = callback_priv_cleanup;
}

int proto_expectation_add_and_cleanup(struct proto_expectation *e, unsigned int expiry, ptime now) {

	if (e->flags & PROTO_EXPECTATION_FLAG_QUEUED)
		return POM_ERR;

	if (proto_expectation_add(e) != POM_OK)
		return POM_ERR;

	e->expiry = timer_alloc(e, proto_expectation_timeout);
	if (!e->expiry)
		return POM_ERR;

	if (timer_queue_now(e->expiry, expiry, now) != POM_OK)
		return POM_ERR;

	return POM_OK;
}

int proto_expectation_add(struct proto_expectation *e) {

	if (!e || !e->tail || !e->tail->proto) {
		pomlog(POMLOG_ERR "Cannot add expectation as it's incomplete");
		return POM_ERR;
	}

	if (e->flags & PROTO_EXPECTATION_FLAG_QUEUED)
		return POM_ERR;

	struct proto *proto = e->tail->proto;
	pom_rwlock_wlock(&proto->expectation_lock);

	__sync_fetch_and_or(&e->flags, PROTO_EXPECTATION_FLAG_QUEUED);

	e->next = proto->expectations;
	if (e->next)
		e->next->prev = e;

	proto->expectations = e;

	pom_rwlock_unlock(&proto->expectation_lock);

	registry_perf_inc(e->proto->perf_expt_pending, 1);

	return POM_OK;
}

int proto_expectation_remove(struct proto_expectation *e) {

	struct proto *proto = e->tail->proto;
	pom_rwlock_wlock(&proto->expectation_lock);

	if (!(e->flags & PROTO_EXPECTATION_FLAG_QUEUED)) {
		pom_rwlock_unlock(&proto->expectation_lock);
		return POM_ERR;
	}

	if (!e->next && !e->prev && proto->expectations != e) {
		// The expectation is not queued
		pom_rwlock_unlock(&proto->expectation_lock);
		return POM_OK;
	}

	if (e->next)
		e->next->prev = e->prev;
	if (e->prev)
		e->prev->next = e->next;
	else
		proto->expectations = e->next;

	__sync_fetch_and_and(&e->flags, ~PROTO_EXPECTATION_FLAG_QUEUED);

	pom_rwlock_unlock(&proto->expectation_lock);

	registry_perf_dec(e->proto->perf_expt_pending, 1);

	return POM_OK;
}

int proto_expectation_timeout(void *priv, ptime now) {

	struct proto_expectation *e = priv;

	proto_expectation_remove(e);
	proto_expectation_cleanup(e);

	return POM_OK;
}

void proto_set_priv(struct proto *p, void *priv) {
	p->priv = priv;
}

void *proto_get_priv(struct proto *p) {
	return p->priv;
}

struct proto_reg_info *proto_get_info(struct proto *p) {
	return p->info;
}

unsigned int proto_get_count() {
	return proto_count;
}

struct proto_number_class *proto_number_class_get(char *name) {
	
	struct proto_number_class *cls = proto_number_class_head;

	for (cls = proto_number_class_head; cls && strcmp(cls->name, name); cls = cls->next);

	if (cls)
		return cls;

	cls = malloc(sizeof(struct proto_number_class));
	if (!cls) {
		pom_oom(sizeof(struct proto_number_class));
		return NULL;
	}
	memset(cls, 0, sizeof(struct proto_number_class));
	cls->name = strdup(name);
	if (!cls->name) {
		pom_oom(strlen(name) + 1);
		free(cls);
		return NULL;
	}

	cls->next = proto_number_class_head;
	proto_number_class_head = cls;

	return cls;

}

int proto_number_register(char *class, unsigned int proto_num, struct proto *p) {

	struct proto_number_class *cls = proto_number_class_get(class);
	if (!cls)
		return POM_ERR;

	struct proto_number *num = malloc(sizeof(struct proto_number));
	if (!num) {
		pom_oom(sizeof(struct proto_number));
		return POM_ERR;
	}
	memset(num, 0, sizeof(struct proto_number));

	num->val = proto_num;
	num->proto = p;

	num->next = cls->nums;
	if (num->next)
		num->next->prev = num;
	cls->nums = num;

	return POM_OK;
}

struct proto *proto_get_by_number(struct proto *p, unsigned int num) {

	if (!p->number_class) {
		pomlog(POMLOG_ERR "No number class for this protocol !");
		return NULL;
	}

	struct proto_number *n;
	for (n = p->number_class->nums; n && n->val != num; n = n->next);

	if (n)
		return n->proto;

	return NULL;
}

int proto_number_unregister(struct proto *p) {

	struct proto_number_class *cls;
	for (cls = proto_number_class_head; cls; cls = cls->next) {
		struct proto_number *num;
		for (num = cls->nums; num && num->proto != p; num = num->next);

		if (num) {
			if (num->next)
				num->next->prev = num->prev;
			if (num->prev)
				num->prev->next = num->next;
			else
				cls->nums = num->next;
			free(num);
		}

	}

	return POM_OK;

}

int proto_add_param(struct proto *proto, struct registry_param *p) {
	
	p->flags &= REGISTRY_PARAM_FLAG_PAUSE_PROCESSING;
	return registry_instance_add_param(proto->reg_instance, p);
}
