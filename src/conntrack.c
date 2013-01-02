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

struct conntrack_tables* conntrack_tables_alloc(size_t tables_size, int has_rev) {

	struct conntrack_tables *ct = malloc(sizeof(struct conntrack_tables));
	if (!ct) {
		pom_oom(sizeof(struct conntrack_tables));
		return NULL;
	}
	memset(ct, 0, sizeof(struct conntrack_tables));

	if (pthread_mutex_init(&ct->lock, NULL)) {
		pomlog(POMLOG_ERR "Could not initialize conntrack tables mutex : %s", pom_strerror(errno));
		free(ct);
		return NULL;
	}

	size_t size = sizeof(struct conntrack_list) * tables_size;
	ct->fwd_table = malloc(size);
	if (!ct->fwd_table) {
		pom_oom(size);
		free(ct);
		return NULL;
	}
	memset(ct->fwd_table, 0, size);


	if (has_rev) {
		ct->rev_table = malloc(size);
		if (!ct->rev_table) {
			free(ct->fwd_table);
			free(ct);
			pom_oom(size);
			return NULL;
		}
		memset(ct->rev_table, 0, size);
	}

	ct->tables_size = tables_size;

	return ct;
}


int conntrack_tables_empty(struct conntrack_tables *ct) {

	if (!ct)
		return POM_OK;
	if (ct->fwd_table) {
		unsigned int i;
		for (i = 0; i < ct->tables_size; i++) {
			while (ct->fwd_table[i]) {
				struct conntrack_list *tmp = ct->fwd_table[i];
				conntrack_cleanup(ct, tmp->ce->fwd_hash, tmp->ce);
			}

		}
	}

	if (ct->rev_table) {
		unsigned int i;
		for (i = 0; i < ct->tables_size; i++) {
			while (ct->rev_table[i]) {
				struct conntrack_list *tmp = ct->rev_table[i];
				conntrack_cleanup(ct, tmp->ce->fwd_hash, tmp->ce);
			}
		}
	}

	return POM_OK;
}

int conntrack_tables_cleanup(struct conntrack_tables *ct) {

	if (!ct)
		return POM_OK;

	conntrack_tables_empty(ct);

	if (ct->fwd_table) 
		free(ct->fwd_table);

	if (ct->rev_table)
		free(ct->rev_table);

	pthread_mutex_destroy(&ct->lock);

	free(ct);

	return POM_OK;
}

int conntrack_hash(uint32_t *hash, struct ptype *fwd, struct ptype *rev) {

	if (!fwd)
		return POM_ERR;


	if (!rev) {
		// Only fwd direction

		*hash = ptype_get_hash(fwd);
	 } else {
		size_t size_fwd = ptype_get_value_size(fwd);
		size_t size_rev = ptype_get_value_size(rev);

		// Try to use the best hash function
		if (size_fwd == sizeof(uint16_t) && size_rev == sizeof(uint16_t)) { // exactly one word
			*hash = jhash_1word(*((uint16_t*)fwd->value) << 16 | *((uint16_t*)rev->value), INITVAL);
		} else if (size_fwd == sizeof(uint32_t) && size_rev == sizeof(uint32_t)) { // exactly 2 words
			*hash = jhash_2words(*((uint32_t*)fwd->value), *((uint32_t*)rev->value), INITVAL);
		} else {

			uint32_t hash_fwd = jhash((char*)fwd->value, size_fwd, INITVAL);
			*hash = jhash((char*)rev->value, size_rev, hash_fwd);
		}

	 }

	return POM_OK;
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
	struct conntrack_list *lst_fwd = NULL;

#ifdef DEBUG_CONNTRACK
	if (!parent->refcount) {
		pomlog(POMLOG_ERR "Parent conntrack has a refcount of 0 !");
		return NULL;
	}
#endif

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
		child->fwd_hash = 0;

		// Alloc the parent node
		res->parent = malloc(sizeof(struct conntrack_node_list));
		if (!res->parent) {
			free(child);
			goto err;
		}
		memset(res->parent, 0, sizeof(struct conntrack_node_list));
		res->parent->ce = parent;
		res->parent->ct = parent->proto->ct;
		res->parent->fwd_hash = parent->fwd_hash;

		// Alloc the forward list
		lst_fwd = malloc(sizeof(struct conntrack_list));
		if (!lst_fwd) {
			pom_oom(sizeof(struct conntrack_list));
			goto err;
		}
		memset(lst_fwd, 0, sizeof(struct conntrack_list));
		lst_fwd->ce = res;

		// Add the child to the parent
		child->next = parent->children;
		if (child->next)
			child->next->prev = child;
		parent->children = child;

		// Add the conntrack to the table
		struct conntrack_tables *ct = proto->ct;
		pom_mutex_lock(&ct->lock);
		lst_fwd->next = ct->fwd_table[0];
		if (lst_fwd->next)
			lst_fwd->next->prev = lst_fwd;
		ct->fwd_table[0] = lst_fwd;
		pom_mutex_unlock(&ct->lock);
		debug_conntrack("Allocated conntrack %p with parent %p (uniq child)", res, parent);

	} else if (parent->children->next) {
		pomlog(POMLOG_ERR "Error, parent has more than one child while it was supposed to have only one");
	} else {
		res = parent->children->ce;
	}

	res->refcount++;

	return res;

err:
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

	struct ptype *rev_value = NULL;
	if (s->proto->info->ct_info->rev_pkt_field_id != CONNTRACK_PKT_FIELD_NONE)
		rev_value = s->pkt_info->fields_value[s->proto->info->ct_info->rev_pkt_field_id];

	if (!fwd_value || !rev_value)
		return POM_ERR;

	uint32_t full_hash_fwd = 0, hash_fwd = 0, full_hash_rev = 0, hash_rev = 0;

	if (conntrack_hash(&full_hash_fwd, fwd_value, rev_value) == POM_ERR) {
		pomlog(POMLOG_ERR "Error while computing forward hash for conntrack");
		return POM_ERR;
	}

	struct conntrack_tables *ct = s->proto->ct;

	// Lock the tables while browsing for a conntrack
	pom_mutex_lock(&ct->lock);

	if (!ct->fwd_table) {
		pom_mutex_unlock(&ct->lock);
		pomlog(POMLOG_ERR "Cannot get conntrack as the forward table is not allocated");
		return POM_ERR;
	}

	// Try to find the conntrack in the forward table
	hash_fwd = full_hash_fwd % ct->tables_size;

	// Check if we can find this entry in the forward way
	if (ct->fwd_table[hash_fwd]) {
		s->ce = conntrack_find(ct->fwd_table[hash_fwd], fwd_value, rev_value, s_prev->ce);
		if (s->ce) {
			s->direction = POM_DIR_FWD;
			s_next->direction = POM_DIR_FWD;
			pom_mutex_lock(&s->ce->lock);
			s->ce->refcount++;
			pom_mutex_unlock(&ct->lock);
			return POM_OK;;
		}
	}

	// It wasn't found in the forward way, maybe in the reverse direction ?
	if (rev_value && ct->rev_table[hash_fwd]) {
		// Lookup the forward hash in the reverse table
		s->ce = conntrack_find(ct->rev_table[hash_fwd], rev_value, fwd_value, s_prev->ce);
		if (s->ce) {
			s->direction = POM_DIR_REV;
			s_next->direction = POM_DIR_REV;
			pom_mutex_lock(&s->ce->lock);
			s->ce->refcount++;
			pom_mutex_unlock(&ct->lock);
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
		hash_rev = hash_fwd;
		full_hash_rev = full_hash_fwd;
		if (conntrack_hash(&full_hash_fwd, fwd_value, rev_value) == POM_ERR) {
			pom_mutex_unlock(&ct->lock);
			pomlog(POMLOG_ERR "Error while computing forward hash for conntrack");
			return POM_ERR;
		}
		hash_fwd = full_hash_fwd % ct->tables_size;
	}


	// Alloc the conntrack entry
	struct conntrack_entry *ce = malloc(sizeof(struct conntrack_entry));
	if (!ce) {
		pom_mutex_unlock(&ct->lock);
		pom_oom(sizeof(struct conntrack_entry));
		return POM_ERR;
	}
	memset(ce, 0, sizeof(struct conntrack_entry));

	if (pom_mutex_init_type(&ce->lock, PTHREAD_MUTEX_ERRORCHECK) != POM_OK) {
		pom_mutex_unlock(&ct->lock);
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
			pom_mutex_unlock(&ct->lock);
			free(ce);
			pom_oom(sizeof(struct conntrack_node_list));
			return POM_ERR;
		}
		memset(child, 0, sizeof(struct conntrack_node_list));

		child->ce = ce;
		child->ct = s->proto->ct;
		child->fwd_hash = full_hash_fwd;

		ce->parent = malloc(sizeof(struct conntrack_node_list));
		if (!ce->parent) {
			pthread_mutex_destroy(&ce->lock);
			pom_mutex_unlock(&ct->lock);
			free(child);
			free(ce);
			pom_oom(sizeof(struct conntrack_node_list));
			return POM_ERR;
		}
		ce->parent->ce = s_prev->ce;
		ce->parent->ct = s_prev->ce->proto->ct;
		ce->parent->fwd_hash = s_prev->ce->fwd_hash;

	}

	ce->proto = s->proto;

	ce->fwd_hash = full_hash_fwd;

	struct conntrack_list *lst_fwd = NULL, *lst_rev = NULL;

	ce->fwd_value = ptype_alloc_from(fwd_value);
	if (!ce->fwd_value)
		goto err;

	// Alloc the forward list
	lst_fwd = malloc(sizeof(struct conntrack_list));
	if (!lst_fwd) {
		ptype_cleanup(ce->fwd_value);
		pom_oom(sizeof(struct conntrack_list));
		goto err;
	}
	memset(lst_fwd, 0, sizeof(struct conntrack_list));
	lst_fwd->ce = ce;

	// Alloc the reverse list
	if (rev_value) {
		if (s_prev->direction != POM_DIR_REV) { // Hash rev was already computed if we had to reverse the direction
			if (conntrack_hash(&full_hash_rev, rev_value, fwd_value) == POM_ERR) {
				pomlog(POMLOG_ERR "Error while computing reverse hash for conntrack");
				pom_mutex_unlock(&ct->lock);
				return POM_ERR;
			}
			hash_rev = full_hash_rev % ct->tables_size;
		}

		ce->rev_hash = full_hash_rev;
		lst_rev = malloc(sizeof(struct conntrack_list)); 
		if (!lst_rev) {
			ptype_cleanup(ce->fwd_value);
			free(lst_fwd);
			pom_oom(sizeof(struct conntrack_list));
			goto err;
		}
		memset(lst_rev, 0, sizeof(struct conntrack_list));
		lst_rev->ce = ce;

		ce->rev_value = ptype_alloc_from(rev_value);
		if (!ce->rev_value) {
			ptype_cleanup(ce->fwd_value);
			free(lst_fwd);
			free(lst_rev);
			goto err;
		}

		// Insert the reverse direction in the conntrack table
		lst_rev->next = ct->rev_table[hash_rev];
		if (lst_rev->next)
			lst_rev->next->prev = lst_rev;
		ct->rev_table[hash_rev] = lst_rev;

		lst_fwd->rev = lst_rev;
		lst_rev->rev = lst_fwd;


	}

	// Insert the forward direction in the conntrack table
	lst_fwd->next = ct->fwd_table[hash_fwd];
	if (lst_fwd->next)
		lst_fwd->next->prev = lst_fwd;
	ct->fwd_table[hash_fwd] = lst_fwd;

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

	// Unlock the tables
	if (s_prev->ce) {
		debug_conntrack("Allocated conntrack %p with parent %p", ce, s_prev->ce);
	} else {
		debug_conntrack("Allocated conntrack %p with no parent", ce);
	}
	pom_mutex_lock(&ce->lock);
	ce->refcount++;
	pom_mutex_unlock(&ct->lock);

	s->ce = ce;
	s->direction = s_prev->direction;

	// Propagate the direction to the payload as well
	s_next->direction = s->direction;
	
	return POM_OK;

err:
	pom_mutex_unlock(&ct->lock);

	pthread_mutex_destroy(&ce->lock);
	if (child)
		free(child);

	if (lst_fwd)
		free(lst_fwd);

	if (lst_rev)
		free(lst_rev);

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
		ce->cleanup_timer->fwd_hash = ce->fwd_hash;
		

	}

	timer_queue(ce->cleanup_timer->timer, delay);

	return POM_OK;
}


int conntrack_timed_cleanup(void *timer, struct timeval *now) {

	struct conntrack_timer *t = timer;
	return conntrack_cleanup(t->proto->ct, t->fwd_hash, t->ce);

}

int conntrack_cleanup(struct conntrack_tables *ct, uint32_t fwd_hash, struct conntrack_entry *ce) {

	// Remove the conntrack from the conntrack tables
	pom_mutex_lock(&ct->lock);

	// Try to find the conntrack in the forward table
	struct conntrack_list *lst = NULL;
	uint32_t hash = fwd_hash % ct->tables_size;

	for (lst = ct->fwd_table[hash]; lst && lst->ce != ce; lst = lst->next);

	if (!lst) {
		pom_mutex_unlock(&ct->lock);
		pomlog(POMLOG_ERR "Trying to cleanup a non existing conntrack : %p", ce);
		return POM_OK;
	}

	conntrack_lock(ce);
	if (ce->refcount) {
		pomlog(POMLOG_ERR "Conntrack %p is still being referenced : %u !", ce, ce->refcount);
		conntrack_unlock(ce);
		pom_mutex_unlock(&ct->lock);
		return POM_OK;
	}


	if (lst->prev)
		lst->prev->next = lst->next;
	else
		ct->fwd_table[hash] = lst->next;

	if (lst->next)
		lst->next->prev = lst->prev;

	struct conntrack_list *lst_rev = lst->rev;
	
	free(lst);

	if (lst_rev) {
		// Remove it from the reverse table
		hash = ce->rev_hash % ct->tables_size;
		
		if (lst_rev->prev)
			lst_rev->prev->next = lst_rev->next;
		else {
			if (lst_rev != ct->rev_table[hash]) {
				conntrack_unlock(ce);
				pomlog(POMLOG_ERR "Conntrack list was supposed to be the head of reverse but wasn't !");
				return POM_ERR;
			}
			ct->rev_table[hash] = lst_rev->next;
		}

		if (lst_rev->next)
			lst_rev->next->prev = lst_rev->prev;
	
		free(lst_rev);
	}

	pom_mutex_unlock(&ct->lock);

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
		pom_mutex_lock(&ce->parent->ct->lock);
		
		uint32_t hash = ce->parent->fwd_hash % ce->parent->ct->tables_size;
		for (lst = ce->parent->ct->fwd_table[hash]; lst && lst->ce != ce->parent->ce; lst = lst->next);

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

		pom_mutex_unlock(&ce->parent->ct->lock);

		free(ce->parent);
	}

	// No need to lock ourselves at this point this there shouldn't be any reference
	// in the conntrack tables


	// Cleanup the children
	while (ce->children) {
		struct conntrack_node_list *child = ce->children;
		ce->children = child->next;

		if (conntrack_cleanup(child->ct, child->fwd_hash, child->ce) != POM_OK) 
			return POM_ERR;

		free(child);
	}

	
	if (ce->fwd_value)
		ptype_cleanup(ce->fwd_value);
	if (ce->rev_value)
		ptype_cleanup(ce->rev_value);

	pthread_mutex_destroy(&ce->lock);

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
	t->fwd_hash = ce->fwd_hash;
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

int conntrack_timer_process(void *priv, struct timeval *now) {

	struct conntrack_timer *t = priv;

	struct conntrack_tables *ct = t->proto->ct;

	// Lock the main table
	pom_mutex_lock(&ct->lock);

	// Check if the conntrack still exists
	uint32_t hash = t->fwd_hash % ct->tables_size;

	struct conntrack_list *lst = NULL;
	for (lst = ct->fwd_table[hash]; lst && lst->ce != t->ce; lst = lst->next);

	if (!lst) {
		pomlog(POMLOG_DEBUG "Timer fired but conntrack doesn't exists anymore");
		pom_mutex_unlock(&ct->lock);
		return POM_OK;
	}


	// Save the reference to the conntrack as the timer might get cleaned up
	struct conntrack_entry *ce = t->ce;

	conntrack_lock(ce);
	pom_mutex_unlock(&ct->lock);
	
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
