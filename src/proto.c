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



#include "common.h"
#include "proto.h"
#include "main.h"
#include "mod.h"
#include "filter.h"

static struct proto *proto_head = NULL;

static pthread_mutex_t proto_list_lock = PTHREAD_MUTEX_INITIALIZER;

static struct registry_class *proto_registry_class = NULL;

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


	pom_mutex_lock(&proto_list_lock);

	// Check if the protocol already exists
	struct proto *proto;
	for (proto = proto_head; proto && strcmp(proto->info->name, reg_info->name); proto = proto->next);
	if (proto) {
		pom_mutex_unlock(&proto_list_lock);
		return POM_ERR;
	}

	// Allocate the protocol
	proto = malloc(sizeof(struct proto));
	if (!proto) {
		pom_mutex_unlock(&proto_list_lock);
		pom_oom(sizeof(struct proto));
		return POM_ERR;
	}

	memset(proto, 0, sizeof(struct proto));
	proto->info = reg_info;

	if (pthread_rwlock_init(&proto->expectation_lock, NULL)) {
		pomlog(POMLOG_ERR "Error while initializing the proto_expectation rwlock : %s", pom_strerror(errno));	
		goto err_proto;
	}

	if (packet_info_pool_init(&proto->pkt_info_pool)) {
		pomlog(POMLOG_ERR "Error while initializing the pkt_info_pool");
		goto err_lock;
	}

	proto->reg_instance = registry_add_instance(proto_registry_class, reg_info->name);
	if (!proto->reg_instance) {
		pomlog(POMLOG_ERR "Error while adding the registry instanc for protocol %s", reg_info->name);
		goto err_packet_info;
	}


	// Allocate the conntrack table
	if (reg_info->ct_info) {
		proto->ct = conntrack_tables_alloc(reg_info->ct_info->default_table_size, (reg_info->ct_info->rev_pkt_field_id == -1 ? 0 : 1));
		if (!proto->ct) {
			pomlog(POMLOG_ERR "Error while allocating conntrack tables");
			goto err_registry;
		}

		proto->perf_conn_cur = registry_instance_add_perf(proto->reg_instance, "conn_cur", registry_perf_type_gauge, "Current number of monitored connection", "connections");
		proto->perf_conn_tot = registry_instance_add_perf(proto->reg_instance, "conn_tot", registry_perf_type_counter, "Total number of connections", "connections");
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

	pom_mutex_unlock(&proto_list_lock);

	pomlog(POMLOG_DEBUG "Proto %s registered", reg_info->name);

	return POM_OK;

err_conntrack:
	conntrack_tables_cleanup(proto->ct);
err_registry:
	registry_remove_instance(proto->reg_instance);
err_packet_info:
	packet_info_pool_cleanup(&proto->pkt_info_pool);
err_lock:
	pthread_rwlock_destroy(&proto->expectation_lock);
err_proto:
	free(proto);

	pom_mutex_unlock(&proto_list_lock);

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

	if (res == PROTO_OK) {
		
		// Process the expectations !
		pom_rwlock_rlock(&proto->expectation_lock);
		struct proto_expectation *e = proto->expectations;
		while (e) {
			
			int expt_dir = POM_DIR_UNK;

			struct proto_expectation_stack *es = e->tail;
			struct ptype *fwd_value = s->pkt_info->fields_value[s->proto->info->ct_info->fwd_pkt_field_id];
			struct ptype *rev_value = s->pkt_info->fields_value[s->proto->info->ct_info->rev_pkt_field_id];

			if ((!es->fields[POM_DIR_FWD] || ptype_compare_val(PTYPE_OP_EQ, es->fields[POM_DIR_FWD], fwd_value)) &&
				(!es->fields[POM_DIR_REV] || ptype_compare_val(PTYPE_OP_EQ, es->fields[POM_DIR_REV], rev_value))) {
				// Expectation matched the forward direction
				expt_dir = POM_DIR_FWD;
			} else if ((!es->fields[POM_DIR_FWD] || ptype_compare_val(PTYPE_OP_EQ, es->fields[POM_DIR_FWD], rev_value)) &&
				(!es->fields[POM_DIR_REV] || ptype_compare_val(PTYPE_OP_EQ, es->fields[POM_DIR_REV], fwd_value))) {
				// Expectation matched the reverse direction
				expt_dir = POM_DIR_REV;
			}

			if (expt_dir == POM_DIR_UNK) {
				// Expectation not matched
				e = e->next;
				continue;
			}
			
			es = es->prev;
			int stack_index_tmp = stack_index - 1;
			while (es) {

				struct proto_process_stack *s_tmp = &stack[stack_index_tmp];

				if (s_tmp->proto != es->proto) {
					 e = e->next;
					 continue;
				}

				fwd_value = s_tmp->pkt_info->fields_value[s_tmp->proto->info->ct_info->fwd_pkt_field_id];
				rev_value = s_tmp->pkt_info->fields_value[s_tmp->proto->info->ct_info->rev_pkt_field_id];

				if (expt_dir == POM_DIR_FWD) {
					if ((es->fields[POM_DIR_FWD] && !ptype_compare_val(PTYPE_OP_EQ, es->fields[POM_DIR_FWD], fwd_value)) ||
						(es->fields[POM_DIR_REV] && !ptype_compare_val(PTYPE_OP_EQ, es->fields[POM_DIR_REV], rev_value))) {
						e = e->next;
						continue;
					}
				} else {
					if ((es->fields[POM_DIR_FWD] && !ptype_compare_val(PTYPE_OP_EQ, es->fields[POM_DIR_FWD], rev_value)) ||
						(es->fields[POM_DIR_REV] && !ptype_compare_val(PTYPE_OP_EQ, es->fields[POM_DIR_REV], fwd_value))) {
						e = e->next;
						continue;
					}

				}

				es = es->prev;
				stack_index_tmp--;
			}

			// Expectation matched !
			// Relock with write access
			pom_rwlock_unlock(&proto->expectation_lock);
			pom_rwlock_wlock(&proto->expectation_lock);

			// Remove it from the list
			
			if (e->next)
				e->next->prev = e->prev;

			if (e->prev)
				e->prev->next = e->next;
			else
				proto->expectations = e->next;

			struct proto_process_stack *s_next = &stack[stack_index + 1];
			s_next->proto = e->proto;

			
			s_next->ce = conntrack_get_unique_from_parent(s_next->proto, s->ce);
			if (!s_next->ce) {
				proto_expectation_cleanup(e);
				return PROTO_ERR;
			}

			s_next->ce->priv = e->priv;

			if (conntrack_session_bind(s_next->ce, e->session)) {
				proto_expectation_cleanup(e);
				return PROTO_ERR;
			}
			e->session = NULL;

			proto_expectation_cleanup(e);

			registry_perf_dec(proto->perf_expt_pending, 1);
			registry_perf_inc(proto->perf_expt_matched, 1);

			break;

		}
		pom_rwlock_unlock(&proto->expectation_lock);
	}

	return res;
}


int proto_process_listeners(struct packet *p, struct proto_process_stack *s, unsigned int stack_index) {

	if (!s[stack_index].plen)
		return POM_OK;

	// Process packet listeners
	struct proto *proto = s[stack_index].proto;
	
	if (!proto)
		return POM_OK;

	struct proto_packet_listener *l;
	for (l = proto->packet_listeners; l; l = l->next) {
		if (l->filter && !filter_proto_match(s, l->filter))
			continue;
		if (l->process(l->object, p, s, stack_index) != POM_OK) {
			pomlog(POMLOG_WARN "Warning packet listener failed");
			// FIXME remove listener from the list ?
		}
	}

	// Process payload listeners
	if (s[stack_index + 1].plen) {
		for (l = proto->payload_listeners; l; l = l->next) {
			if (l->filter && !filter_proto_match(s, l->filter))
				continue;
			if (l->process(l->object, p, s, stack_index + 1) != POM_OK) {
				pomlog(POMLOG_WARN "Warning payload listener failed");
				// FIXME remove listener from the list ?
			}
		}
	}

	return POM_OK;
}

int proto_post_process(struct packet *p, struct proto_process_stack *s, unsigned int stack_index) {

	if (!s)
		return PROTO_ERR;
	
	struct proto *proto = s[stack_index].proto;

	if (!proto)
		return PROTO_ERR;
	
	if (proto->info->post_process)
		return proto->info->post_process(proto->priv, p, s, stack_index);

	return POM_OK;
}

int proto_unregister(char *name) {

	pom_mutex_lock(&proto_list_lock);
	struct proto *proto;
	for (proto = proto_head; proto && strcmp(proto->info->name, name); proto = proto->next);
	if (!proto) {
		pom_mutex_unlock(&proto_list_lock);
		return POM_OK;
	}
	
	if (proto->info->cleanup && proto->info->cleanup(proto->priv)) {
		pom_mutex_unlock(&proto_list_lock);
		pomlog(POMLOG_ERR "Error while cleaning up the protocol %s", name);
		return POM_ERR;
	}

	if (proto->reg_instance)
		registry_remove_instance(proto->reg_instance);

		conntrack_tables_cleanup(proto->ct);

	packet_info_pool_cleanup(&proto->pkt_info_pool);
	
	if (proto->next)
		proto->next->prev = proto->prev;
	if (proto->prev)
		proto->prev->next = proto->next;
	else
		proto_head = proto->next;

	mod_refcount_dec(proto->info->mod);

	free(proto);

	pom_mutex_unlock(&proto_list_lock);

	return POM_OK;
}

struct proto *proto_get(char *name) {
	
	struct proto *tmp;
	for (tmp = proto_head; tmp && strcmp(tmp->info->name, name); tmp = tmp->next);

	if (!tmp)
		pomlog(POMLOG_WARN "Proto %s not found !", name);

	return tmp;
}

int proto_empty_conntracks() {

	pom_mutex_lock(&proto_list_lock);
	struct proto *proto;
	for (proto = proto_head; proto; proto = proto->next) {
		conntrack_tables_empty(proto->ct);
	}
	pom_mutex_unlock(&proto_list_lock);

	return POM_OK;
}

int proto_cleanup() {

	pom_mutex_lock(&proto_list_lock);

	
	struct proto *proto;
	for (proto = proto_head; proto; proto = proto->next) {

		if (proto->info->cleanup && proto->info->cleanup(proto->priv) == POM_ERR)
			pomlog(POMLOG_WARN "Error while cleaning up protocol %s", proto->info->name);
		conntrack_tables_cleanup(proto->ct);

		mod_refcount_dec(proto->info->mod);
		packet_info_pool_cleanup(&proto->pkt_info_pool);
	}

	while (proto_head) {
		proto = proto_head;
		proto_head = proto->next;
		free(proto);
	}

	pom_mutex_unlock(&proto_list_lock);

	if (proto_registry_class)
		registry_remove_class(proto_registry_class);
	proto_registry_class = NULL;

	return POM_OK;
}

struct proto_packet_listener *proto_packet_listener_register(struct proto *proto, unsigned int flags, void *object, int (*process) (void *object, struct packet *p, struct proto_process_stack *s, unsigned int stack_index)) {

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

	return l;
}

int proto_packet_listener_unregister(struct proto_packet_listener *l) {

	if (!l)
		return POM_ERR;

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

	free(l);

	return POM_OK;
}

void proto_packet_listener_set_filter(struct proto_packet_listener *l, struct filter_proto *f) {
	l->filter = f;
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

	return res;
}

static struct proto_expectation_stack *proto_expectation_stack_alloc(struct proto *p, struct ptype *fwd_value, struct ptype *rev_value) {

	if (!p || !fwd_value)
		return NULL;

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

	while (e->head) {
		struct proto_expectation_stack *es = e->head;
		e->head = es->next;
		if (es->fields[POM_DIR_FWD])
			ptype_cleanup(es->fields[POM_DIR_FWD]);
		if (es->fields[POM_DIR_REV])
			ptype_cleanup(es->fields[POM_DIR_REV]);
		
		free(es);

	}

	if (e->session)
		conntrack_session_refcount_dec(e->session);

	timer_cleanup(e->expiry);

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

int proto_expectation_add(struct proto_expectation *e, unsigned int expiry, struct conntrack_session *session) {

	if (!e || !e->tail || !e->tail->proto) {
		pomlog(POMLOG_ERR "Cannot add expectation as it's incomplete");
		return POM_ERR;
	}

	e->expiry = timer_alloc(e, proto_expectation_expiry);
	if (!e->expiry)
		return POM_ERR;

	if (timer_queue(e->expiry, expiry) != POM_OK)
		return POM_ERR;

	e->session = session;
	
	struct proto *proto = e->tail->proto;
	pom_rwlock_wlock(&proto->expectation_lock);

	e->next = proto->expectations;
	if (e->next)
		e->next->prev = e;

	proto->expectations = e;

	pom_rwlock_unlock(&proto->expectation_lock);

	registry_perf_inc(proto->perf_expt_pending, 1);

	return POM_OK;
}

int proto_expectation_expiry(void *priv, ptime now) {

	struct proto_expectation *e = priv;
	struct proto *proto = e->tail->proto;

	timer_cleanup(e->expiry);
	pom_rwlock_wlock(&proto->expectation_lock);

	if (e->next)
		e->next->prev = e->prev;

	if (e->prev)
		e->prev->next = e->next;
	else
		proto->expectations = e->next;

	pom_rwlock_unlock(&proto->expectation_lock);

	if (e->priv && proto->info->ct_info->cleanup_handler) {
		if (proto->info->ct_info->cleanup_handler(e->priv) != POM_OK)
			pomlog(POMLOG_WARN "Unable to free the conntrack priv of the proto_expectation");
	}

	proto_expectation_cleanup(e);

	registry_perf_dec(proto->perf_expt_pending, 1);

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
