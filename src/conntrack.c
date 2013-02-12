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

#include "proto.h"
#include "conntrack.h"
#include "jhash.h"
#include "common.h"
#include "ptype.h"

#include <pthread.h>
#include <pom-ng/timer.h>

#define INITVAL 0x5de97c2d // random value

//#define DEBUG_CONNTRACK

#if 0
#define debug_conntrack(x ...) pomlog(POMLOG_DEBUG x)
#else
#define debug_conntrack(x ...)
#endif

struct conntrack_tables* conntrack_table_alloc(size_t table_size, int has_rev) {

	struct conntrack_tables *ct = malloc(sizeof(struct conntrack_tables));
	if (!ct) {
		pom_oom(sizeof(struct conntrack_tables));
		return NULL;
	}
	memset(ct, 0, sizeof(struct conntrack_tables));


	size_t size = sizeof(struct conntrack_list) * table_size;
	ct->table = malloc(size);
	if (!ct->table) {
		pom_oom(size);
		goto err;
	}
	memset(ct->table, 0, size);

	size = sizeof(pthread_mutex_t) *table_size;
	ct->locks = malloc(size);
	if (!ct->locks) {
		pom_oom(size);
		goto err;

	}

	unsigned int i;

	for (i = 0; i < table_size; i++) {
		int res = pthread_mutex_init(&ct->locks[i], NULL);
		if (res) {
			pomlog(POMLOG_ERR "Could not initialize conntrack hash lock : %s", pom_strerror(res));
			goto err;
		}
	}
	ct->table_size = table_size;

	return ct;

err:
	conntrack_table_cleanup(ct);
	return NULL;
}


int conntrack_table_empty(struct conntrack_tables *ct) {

	if (!ct || !ct->table)
		return POM_ERR;

	unsigned int i;
	for (i = 0; i < ct->table_size; i++) {
		while (ct->table[i]) {
			struct conntrack_list *tmp = ct->table[i];
			conntrack_cleanup(ct, tmp->ce->hash, tmp->ce);
		}


	}

	return POM_OK;
}

int conntrack_table_cleanup(struct conntrack_tables *ct) {

	if (!ct)
		return POM_OK;


	if (ct->table) {
		conntrack_table_empty(ct);
		free(ct->table);
	}

	if (ct->locks) {
		unsigned int i;
		for (i = 0; i < ct->table_size; i++) {
			int res = pthread_mutex_destroy(&ct->locks[i]);
			if (res) {
				pomlog(POMLOG_WARN "Error while destroying a hash lock : %s", pom_strerror(errno));
			}
		}
		free(ct->locks);
	}


	free(ct);

	return POM_OK;
}


uint32_t conntrack_hash(struct ptype *a, struct ptype *b) {

	// Create a reversible hash for a and b
	if (!a)
		return POM_ERR;


	if (!b) {
		// Only fwd direction

		return ptype_get_hash(a);
	 }
	 
	size_t size_a = ptype_get_value_size(a);
	size_t size_b = ptype_get_value_size(b);

	// Try to use the best hash function
	if (size_a == sizeof(uint16_t) && size_b == sizeof(uint16_t)) { // Add up the two 16bit values
		uint32_t value = *((uint16_t*)a->value) + *((uint16_t*)b->value);
		return jhash_1word(value, INITVAL);
	} else if (size_a == sizeof(uint32_t) && size_b == sizeof(uint32_t)) { // XOR the two 32bit values before hashing
		return jhash_1word(*((uint32_t*)a->value) ^ *((uint32_t*)b->value), INITVAL);
	}

	uint32_t hash_a = jhash((char*)a->value, size_a, INITVAL);
	uint32_t hash_b = jhash((char*)b->value, size_b, INITVAL);
	return hash_a ^ hash_b;
}


struct conntrack_entry *conntrack_find(struct conntrack_list *lst, struct ptype *fwd_value, struct ptype *rev_value, struct conntrack_entry *parent) {

	if (!fwd_value)
		return NULL;


	for (; lst; lst = lst->next) {
		struct conntrack_entry *ce = lst->ce;

		// Check the parent conntrack
		if (ce->parent && ce->parent->ce != parent)
			continue;

		// Check the forward value
		if (!ptype_compare_val(PTYPE_OP_EQ, ce->fwd_value, fwd_value))
			continue;
		
		// Check the reverse value if present
		if (ce->rev_value)  {
			if (!rev_value) {
				// Conntrack_entry has a reverse value but none was provided
				continue;
			}

			if (!ptype_compare_val(PTYPE_OP_EQ, ce->rev_value, rev_value))
				continue;

		} else if (rev_value) {
			// Conntrack entry does not have a reverse value but one was provided
			continue;
		}

		return ce;

	}

	// No conntrack entry found
	return NULL;
}

struct conntrack_entry* conntrack_get_unique_from_parent(struct proto *proto, struct conntrack_entry *parent) {

	if (!proto || !parent)
		return NULL;


	struct conntrack_entry *res = NULL;
	struct conntrack_node_list *child = NULL;
	struct conntrack_list *lst = NULL;

#ifdef DEBUG_CONNTRACK
	if (!parent->refcount) {
		pomlog(POMLOG_ERR "Parent conntrack has a refcount of 0 !");
		return NULL;
	}
#endif

	struct conntrack_tables *ct = proto->ct;

	if (!parent->children) {

		// Alloc the conntrack
		res = malloc(sizeof(struct conntrack_entry));
		if (!res) {
			pom_oom(sizeof(struct conntrack_entry));
			goto err;
		}

		memset(res, 0, sizeof(struct conntrack_entry));
		res->proto = proto;

		if (pom_mutex_init_type(&res->lock, PTHREAD_MUTEX_ERRORCHECK) != POM_OK)
			goto err;

		// Alloc the child list
		child = malloc(sizeof(struct conntrack_node_list));
		if (!child) 
			goto err;
		
		memset(child, 0, sizeof(struct conntrack_node_list));
		child->ce = res;
		child->ct = proto->ct;

		// Alloc the parent node
		res->parent = malloc(sizeof(struct conntrack_node_list));
		if (!res->parent) {
			free(child);
			goto err;
		}
		memset(res->parent, 0, sizeof(struct conntrack_node_list));
		res->parent->ce = parent;
		res->parent->ct = parent->proto->ct;
		res->parent->hash = parent->hash;

		// Alloc the list node
		lst = malloc(sizeof(struct conntrack_list));
		if (!lst) {
			pom_oom(sizeof(struct conntrack_list));
			goto err;
		}
		memset(lst, 0, sizeof(struct conntrack_list));
		lst->ce = res;

		// Add the child to the parent
		child->next = parent->children;
		if (child->next)
			child->next->prev = child;
		parent->children = child;

		// Add the conntrack to the table
		pom_mutex_lock(&ct->locks[0]);
		lst->next = ct->table[0];
		if (lst->next)
			lst->next->prev = lst;
		ct->table[0] = lst;
		pom_mutex_unlock(&ct->locks[0]);
		debug_conntrack("Allocated conntrack %p with parent %p (uniq child)", res, parent);

		registry_perf_inc(proto->perf_conn_cur, 1);
		registry_perf_inc(proto->perf_conn_tot, 1);

	} else if (parent->children->next) {
		pomlog(POMLOG_ERR "Error, parent has more than one child while it was supposed to have only one");
	} else {
		res = parent->children->ce;
	}

	res->refcount++;

	return res;

err:
	pom_mutex_unlock(&ct->locks[0]);
	if (res) {
		pthread_mutex_destroy(&res->lock);
		free(res);
	}

	if (child)
		free(child);

	return NULL;

}

int conntrack_get(struct proto_process_stack *stack, unsigned int stack_index) {

	struct proto_process_stack *s = &stack[stack_index];
	struct proto_process_stack *s_prev = &stack[stack_index - 1];
	struct proto_process_stack *s_next = &stack[stack_index + 1];

	if (s->ce)
		return POM_OK;
		
	if (!s->proto || !s->proto->info->ct_info)
		return POM_ERR;

	struct ptype *fwd_value = s->pkt_info->fields_value[s->proto->info->ct_info->fwd_pkt_field_id];
	if (!fwd_value)
		return POM_ERR;

	struct ptype *rev_value = NULL;
	if (s->proto->info->ct_info->rev_pkt_field_id != CONNTRACK_PKT_FIELD_NONE) {
		rev_value = s->pkt_info->fields_value[s->proto->info->ct_info->rev_pkt_field_id];
		if (!rev_value)
			return POM_ERR;
	}

	struct conntrack_tables *ct = s->proto->ct;

	uint32_t hash = conntrack_hash(fwd_value, rev_value) % ct->table_size;

	// Lock the specific hash while browsing for a conntrack
	pom_mutex_lock(&ct->locks[hash]);

	// Try to find the conntrack in the forward table

	// Check if we can find this entry in the forward way
	if (ct->table[hash]) {
		s->ce = conntrack_find(ct->table[hash], fwd_value, rev_value, s_prev->ce);
		if (s->ce) {
			s->direction = POM_DIR_FWD;
			s_next->direction = POM_DIR_FWD;
			pom_mutex_lock(&s->ce->lock);
			s->ce->refcount++;
			pom_mutex_unlock(&ct->locks[hash]);
			return POM_OK;;
		}
	}


	// It wasn't found in the forward way, maybe in the reverse direction ?
	if (rev_value) {
		s->ce = conntrack_find(ct->table[hash], rev_value, fwd_value, s_prev->ce);
		if (s->ce) {
			s->direction = POM_DIR_REV;
			s_next->direction = POM_DIR_REV;
			pom_mutex_lock(&s->ce->lock);
			s->ce->refcount++;
			pom_mutex_unlock(&ct->locks[hash]);
			return POM_OK;
		}

	}

	// It's not found in the reverse direction either, let's create it then

	if (s_prev->direction == POM_DIR_REV) {
		// This indicates that the parent conntrack matched in a reverse direction
		// Let's keep directions consistent and swap fwd and rev values
		struct ptype *tmp = rev_value;
		rev_value = fwd_value;
		fwd_value = tmp;
	}


	// Alloc the conntrack entry
	struct conntrack_entry *ce = malloc(sizeof(struct conntrack_entry));
	if (!ce) {
		pom_mutex_unlock(&ct->locks[hash]);
		pom_oom(sizeof(struct conntrack_entry));
		return POM_ERR;
	}
	memset(ce, 0, sizeof(struct conntrack_entry));

	if (pom_mutex_init_type(&ce->lock, PTHREAD_MUTEX_ERRORCHECK) != POM_OK) {
		pom_mutex_unlock(&ct->locks[hash]);
		free(ce);
		return POM_ERR;
	}

	struct conntrack_node_list *child = NULL;

	// We shouldn't have to check if the parent still exists as it
	// is supposed to have a refcount since conntrack_get is called after
	// the parent's conntrack_get was called and before conntrack_refcount_dec
	// was called by core_process_stack.
	if (s_prev->ce) {

		child = malloc(sizeof(struct conntrack_node_list));
		if (!child) {
			pthread_mutex_destroy(&ce->lock);
			pom_mutex_unlock(&ct->locks[hash]);
			free(ce);
			pom_oom(sizeof(struct conntrack_node_list));
			return POM_ERR;
		}
		memset(child, 0, sizeof(struct conntrack_node_list));

		child->ce = ce;
		child->ct = s->proto->ct;
		child->hash = hash;

		ce->parent = malloc(sizeof(struct conntrack_node_list));
		if (!ce->parent) {
			pthread_mutex_destroy(&ce->lock);
			pom_mutex_unlock(&ct->locks[hash]);
			free(child);
			free(ce);
			pom_oom(sizeof(struct conntrack_node_list));
			return POM_ERR;
		}
		ce->parent->ce = s_prev->ce;
		ce->parent->ct = s_prev->ce->proto->ct;
		ce->parent->hash = s_prev->ce->hash;

	}

	ce->proto = s->proto;

	ce->hash = hash;

	struct conntrack_list *lst = NULL;

	ce->fwd_value = ptype_alloc_from(fwd_value);
	if (!ce->fwd_value)
		goto err;

	if (rev_value) {
		ce->rev_value = ptype_alloc_from(rev_value);
		if (!ce->rev_value)
			goto err;
	}
	// Alloc the list node
	lst = malloc(sizeof(struct conntrack_list));
	if (!lst) {
		ptype_cleanup(ce->fwd_value);
		pom_oom(sizeof(struct conntrack_list));
		goto err;
	}
	memset(lst, 0, sizeof(struct conntrack_list));
	lst->ce = ce;

	// Insert in the conntrack table
	lst->next = ct->table[hash];
	if (lst->next)
		lst->next->prev = lst;
	ct->table[hash] = lst;

	// Add the child to the parent if any
	if (child) {
		pom_mutex_lock(&s_prev->ce->lock);
		if (!s_prev->ce->refcount)
			pomlog(POMLOG_WARN "Internal error, the parent is supposed to have a refcount > 0");
		child->next = s_prev->ce->children;
		if (child->next)
			child->next->prev = child;
		s_prev->ce->children = child;
		pom_mutex_unlock(&s_prev->ce->lock);
	}

	// Unlock the table
	if (s_prev->ce) {
		debug_conntrack("Allocated conntrack %p with parent %p", ce, s_prev->ce);
	} else {
		debug_conntrack("Allocated conntrack %p with no parent", ce);
	}
	pom_mutex_lock(&ce->lock);
	ce->refcount++;
	pom_mutex_unlock(&ct->locks[hash]);

	s->ce = ce;
	s->direction = s_prev->direction;

	// Propagate the direction to the payload as well
	s_next->direction = s->direction;
	
	registry_perf_inc(ce->proto->perf_conn_cur, 1);
	registry_perf_inc(ce->proto->perf_conn_tot, 1);

	return POM_OK;

err:
	pom_mutex_unlock(&ct->locks[hash]);

	pthread_mutex_destroy(&ce->lock);
	if (child)
		free(child);

	if (lst)
		free(lst);

	if (ce->parent)
		free(ce->parent);
	
	if (ce->fwd_value)
		ptype_cleanup(ce->fwd_value);

	if (ce->rev_value)
		ptype_cleanup(ce->rev_value);

	free(ce);

	return POM_ERR;
}

void conntrack_lock(struct conntrack_entry *ce) {
	pom_mutex_lock(&ce->lock);
}

void conntrack_unlock(struct conntrack_entry *ce) {
	pom_mutex_unlock(&ce->lock);
}

void conntrack_refcount_dec(struct conntrack_entry *ce) {
	pom_mutex_lock(&ce->lock);
	if (!ce->refcount) {
		pomlog(POMLOG_ERR "Reference count already 0 !");
		abort();
	}
	ce->refcount--;
	pom_mutex_unlock(&ce->lock);
}

int conntrack_add_priv(struct conntrack_entry *ce, void *obj, void *priv, int (*cleanup) (void *obj, void *priv)) {

	struct conntrack_priv_list *priv_lst = malloc(sizeof(struct conntrack_priv_list));
	if (!priv_lst) {
		pom_oom(sizeof(struct conntrack_priv_list));
		return POM_ERR;
	}
	memset(priv_lst, 0, sizeof(struct conntrack_priv_list));
	priv_lst->obj = obj;
	priv_lst->priv = priv;
	priv_lst->cleanup = cleanup;

	priv_lst->next = ce->priv_list;
	if (priv_lst->next)
		priv_lst->next->prev = priv_lst;
	ce->priv_list = priv_lst;

	return POM_OK;
}

void *conntrack_get_priv(struct conntrack_entry *ce, void *obj) {

	struct conntrack_priv_list *priv_lst = ce->priv_list;
	for (; priv_lst && priv_lst->obj != obj; priv_lst = priv_lst->next);

	if (!priv_lst)
		return NULL;

	return priv_lst->priv;
}

int conntrack_delayed_cleanup(struct conntrack_entry *ce, unsigned int delay) {

	if (!delay) {
		if (ce->cleanup_timer) {
			timer_dequeue(ce->cleanup_timer->timer);
			timer_cleanup(ce->cleanup_timer->timer);
			free(ce->cleanup_timer);
			ce->cleanup_timer = NULL;
		}
		return POM_OK;
	}

	if (!ce->cleanup_timer) {
		ce->cleanup_timer = malloc(sizeof(struct conntrack_timer));
		if (!ce->cleanup_timer) {
			pom_oom(sizeof(struct conntrack_timer));
			return POM_ERR;
		}
		ce->cleanup_timer->timer = timer_alloc(ce->cleanup_timer, conntrack_timed_cleanup);
		if (!ce->cleanup_timer->timer) {
			free(ce->cleanup_timer);
			ce->cleanup_timer = NULL;
			return POM_ERR;
		}

		ce->cleanup_timer->ce = ce;
		ce->cleanup_timer->proto = ce->proto;
		ce->cleanup_timer->hash = ce->hash;
		

	}

	timer_queue(ce->cleanup_timer->timer, delay);

	return POM_OK;
}


int conntrack_timed_cleanup(void *timer, ptime now) {

	struct conntrack_timer *t = timer;
	return conntrack_cleanup(t->proto->ct, t->hash, t->ce);

}

int conntrack_cleanup(struct conntrack_tables *ct, uint32_t hash, struct conntrack_entry *ce) {

	// Remove the conntrack from the conntrack table
	pom_mutex_lock(&ct->locks[hash]);

	// Try to find the conntrack in the list
	struct conntrack_list *lst = NULL;

	for (lst = ct->table[hash]; lst && lst->ce != ce; lst = lst->next);

	if (!lst) {
		pom_mutex_unlock(&ct->locks[hash]);
		pomlog(POMLOG_ERR "Trying to cleanup a non existing conntrack : %p", ce);
		return POM_OK;
	}

	conntrack_lock(ce);
	if (ce->refcount) {
		pomlog(POMLOG_ERR "Conntrack %p is still being referenced : %u !", ce, ce->refcount);
		conntrack_delayed_cleanup(ce, 1);
		conntrack_unlock(ce);
		pom_mutex_unlock(&ct->locks[hash]);
		return POM_OK;
	}


	if (lst->prev)
		lst->prev->next = lst->next;
	else
		ct->table[hash] = lst->next;

	if (lst->next)
		lst->next->prev = lst->prev;

	free(lst);

	pom_mutex_unlock(&ct->locks[hash]);

	// At this point, the conntrack should not be used at all !

	if (ce->parent) {
		debug_conntrack("Cleaning up conntrack %p, with parent %p", ce, ce->parent->ce);
	} else {
		debug_conntrack("Cleaning up conntrack %p, with no parent", ce);
	}

	// Cleanup private stuff from the conntrack
	if (ce->priv && ce->proto->info->ct_info->cleanup_handler) {
		if (ce->proto->info->ct_info->cleanup_handler(ce->priv) != POM_OK)
			pomlog(POMLOG_WARN "Unable to free the private memory of a conntrack");
	}

	// Cleanup the priv_list
	struct conntrack_priv_list *priv_lst = ce->priv_list;
	while (priv_lst) {
		if (priv_lst->cleanup) {
			if (priv_lst->cleanup(priv_lst->obj, priv_lst->priv) != POM_OK)
				pomlog(POMLOG_WARN "Error while cleaning up private objects in conntrack_entry");
		}
		ce->priv_list = priv_lst->next;
		free(priv_lst);
		priv_lst = ce->priv_list;

	}


	if (ce->cleanup_timer) {
		conntrack_timer_cleanup(ce->cleanup_timer);
		ce->cleanup_timer = NULL;
	}

	if (ce->session)
		conntrack_session_refcount_dec(ce->session);

	conntrack_unlock(ce);
	
	if (ce->parent) {
		// Remove the child from the parent
		
		// Make sure the parent still exists
		uint32_t hash = ce->parent->hash;
		pom_mutex_lock(&ce->parent->ct->locks[hash]);
		
		for (lst = ce->parent->ct->table[hash]; lst && lst->ce != ce->parent->ce; lst = lst->next);

		if (lst) {

			conntrack_lock(ce->parent->ce);
			struct conntrack_node_list *tmp = ce->parent->ce->children;

			for (; tmp && tmp->ce != ce; tmp = tmp->next);

			if (tmp) {
				if (tmp->prev)
					tmp->prev->next = tmp->next;
				else
					ce->parent->ce->children = tmp->next;

				if (tmp->next)
					tmp->next->prev = tmp->prev;

				free(tmp);
			} else {
				pomlog(POMLOG_WARN "Conntrack %s not found in parent's %s children list", ce, ce->parent->ce);
			}

			if (!ce->parent->ce->children) // Parent has no child anymore, clean it up after some time
				conntrack_delayed_cleanup(ce->parent->ce, CONNTRACK_CHILDLESS_TIMEOUT);

			conntrack_unlock(ce->parent->ce);
		} else {
			debug_conntrack("Parent conntrack %p not found while cleaning child %p !", ce->parent->ce, ce);
		}

		pom_mutex_unlock(&ce->parent->ct->locks[hash]);

		free(ce->parent);
	}

	// No need to lock ourselves at this point this there shouldn't be any reference
	// in the conntrack tables


	// Cleanup the children
	while (ce->children) {
		struct conntrack_node_list *child = ce->children;
		ce->children = child->next;

		if (conntrack_cleanup(child->ct, child->hash, child->ce) != POM_OK) 
			return POM_ERR;

		free(child);
	}

	
	if (ce->fwd_value)
		ptype_cleanup(ce->fwd_value);
	if (ce->rev_value)
		ptype_cleanup(ce->rev_value);

	pthread_mutex_destroy(&ce->lock);

	registry_perf_dec(ce->proto->perf_conn_cur, 1);

	free(ce);

	return POM_OK;
}

struct conntrack_timer *conntrack_timer_alloc(struct conntrack_entry *ce, int (*handler) (struct conntrack_entry *ce, void *priv), void *priv) {


	if (!ce || !handler)
		return NULL;

	struct conntrack_timer *t = malloc(sizeof(struct conntrack_timer));
	if (!t) {
		pom_oom(sizeof(struct conntrack_timer));
		return NULL;
	}
	memset(t, 0, sizeof(struct conntrack_timer));

	t->timer = timer_alloc(t, conntrack_timer_process);

	if (!t->timer) {
		free(t);
		return NULL;
	}

	t->proto = ce->proto;
	t->hash = ce->hash;
	t->handler = handler;
	t->priv = priv;
	t->ce = ce;

	return t;
}

int conntrack_timer_queue(struct conntrack_timer *t, unsigned int expiry) {
	return timer_queue(t->timer, expiry);
}

int conntrack_timer_dequeue(struct conntrack_timer *t) {
	return timer_dequeue(t->timer);
}

int conntrack_timer_cleanup(struct conntrack_timer *t) {

#ifdef DEBUG_CONNTRACK
	int res = pthread_mutex_lock(&t->ce->lock);

	if (!res) {
		pomlog(POMLOG_ERR "Internal error, conntrack not locked when timer cleaned up");
		pom_mutex_unlock(&t->ce->lock);
	} else if (res != EDEADLK) {
		pomlog(POMLOG_ERR "Error while locking timer lock : %s", pom_strerror(errno));
		abort();
	}
#endif

	timer_cleanup(t->timer);
	free(t);
	return POM_OK;

}

int conntrack_timer_process(void *priv, ptime now) {

	struct conntrack_timer *t = priv;

	struct conntrack_tables *ct = t->proto->ct;

	// Lock the main table
	pom_mutex_lock(&ct->locks[t->hash]);

	// Check if the conntrack still exists

	struct conntrack_list *lst = NULL;
	for (lst = ct->table[t->hash]; lst && lst->ce != t->ce; lst = lst->next);

	if (!lst) {
		pomlog(POMLOG_DEBUG "Timer fired but conntrack doesn't exists anymore");
		pom_mutex_unlock(&ct->locks[t->hash]);
		return POM_OK;
	}


	// Save the reference to the conntrack as the timer might get cleaned up
	struct conntrack_entry *ce = t->ce;

	conntrack_lock(ce);
	pom_mutex_unlock(&ct->locks[t->hash]);
	
	int res = t->handler(ce, t->priv);
	
	conntrack_unlock(ce);

	return res;
}

struct conntrack_session *conntrack_session_get(struct conntrack_entry *ce) {

	if (!ce->session) {
		ce->session = malloc(sizeof(struct conntrack_session));
		if (!ce->session) {
			pom_oom(sizeof(struct conntrack_session));
			return NULL;
		}
		memset(ce->session, 0, sizeof(struct conntrack_session));

		if (pthread_mutex_init(&ce->session->lock, NULL)) {
			pomlog(POMLOG_ERR "Error while initializing session mutex : %s", pom_strerror(errno));
			free(ce->session);
			ce->session = NULL;
			return NULL;
		}
		ce->session->refcount++;
	}
	
	pom_mutex_lock(&ce->session->lock);

	return ce->session;
}

int conntrack_session_bind(struct conntrack_entry *ce, struct conntrack_session *session) {

	if (ce->session) {
		pomlog(POMLOG_WARN "Warning, session already exists when trying to bind another session. TODO: implement merging");
		conntrack_session_refcount_dec(ce->session);
	}

	pom_mutex_lock(&session->lock);
	session->refcount++;
	ce->session = session;
	pom_mutex_unlock(&session->lock);

	return POM_OK;
}

void conntrack_session_unlock(struct conntrack_session *session) {
	pom_mutex_unlock(&session->lock);
}


int conntrack_session_refcount_dec(struct conntrack_session *session) {

	pom_mutex_lock(&session->lock);
	session->refcount--;

	if (session->refcount) {
		pom_mutex_unlock(&session->lock);
		return POM_OK;
	}

	pom_mutex_unlock(&session->lock);

	pthread_mutex_destroy(&session->lock);

	while (session->privs) {
		struct conntrack_priv_list *lst = session->privs;
		session->privs = lst->next;
		if (lst->cleanup) {
			if (lst->cleanup(lst->obj, lst->priv) != POM_OK)
				pomlog(POMLOG_WARN "Cleanup handler failed for session priv");
		}
		free(lst);
	}

	free(session);
	return POM_OK;
}


int conntrack_session_add_priv(struct conntrack_session *s, void *obj, void *priv, int (*cleanup_handler) (void *obj, void *priv)) {
	
	struct conntrack_priv_list *lst = malloc(sizeof(struct conntrack_priv_list));
	if (!lst) {
		pom_oom(sizeof(struct conntrack_priv_list));
		return POM_ERR;
	}
	memset(lst, 0, sizeof(struct conntrack_priv_list));
	lst->obj = obj;
	lst->priv = priv;
	lst->cleanup = cleanup_handler;

	lst->next = s->privs;
	if (lst->next)
		lst->next->prev = lst;

	s->privs = lst;

	return POM_OK;
}

void *conntrack_session_get_priv(struct conntrack_session *s, void *obj) {

	struct conntrack_priv_list *lst = s->privs;
	while (lst) {
		if (lst->obj == obj)
			return lst->priv;
	}

	return NULL;
}
