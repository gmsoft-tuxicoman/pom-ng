/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2010-2011 Guy Martin <gmsoft@tuxicoman.be>
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

#include <pthread.h>
#include <pom-ng/timer.h>

#define INITVAL 0x5de97c2d // random value

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
		int i;
		for (i = 0; i < ct->tables_size; i++) {
			while (ct->fwd_table[i]) {
				conntrack_cleanup(ct->fwd_table[i]->ce);
			}

		}
	}

	if (ct->rev_table) {
		int i;
		for (i = 0; i < ct->tables_size; i++) {
			while (ct->rev_table[i]) {
				conntrack_cleanup(ct->rev_table[i]->ce);
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

	size_t size_fwd = ptype_get_value_size(fwd);
	if (size_fwd < 0)
		return POM_ERR;

	if (!rev) {
		// Only fwd direction

		// Try to use the best hash function
		if (size_fwd == sizeof(uint32_t)) { // exactly one word
			*hash = jhash_1word(*((uint32_t*)fwd->value), INITVAL);
		} else if (size_fwd == 2 * sizeof(uint32_t))  { // exactly two words
			*hash = jhash_2words(*((uint32_t*)fwd->value), *((uint32_t*)(fwd->value + sizeof(uint32_t))), INITVAL);
		} else if (size_fwd == 3 * sizeof(uint32_t)) { // exactly 3 words
			*hash = jhash_3words(*((uint32_t*)fwd->value), *((uint32_t*)(fwd->value + sizeof(uint32_t))), *((uint32_t*)(fwd->value + (2 * sizeof(uint32_t)))), INITVAL);
		} else {
			*hash = jhash((char*)fwd->value, size_fwd, INITVAL);
		}
	 } else {
		size_t size_rev = ptype_get_value_size(rev);
		if (size_rev < 0)
			return POM_ERR;

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
		if (ce->parent != parent)
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
	struct conntrack_child_list *child = NULL;
	struct conntrack_list *lst_fwd = NULL;

	pom_mutex_lock(&parent->lock);

	if (!parent->children) {

		// Alloc the conntrack
		res = malloc(sizeof(struct conntrack_entry));
		if (!res) {
			pom_oom(sizeof(struct conntrack_entry));
			goto err;
		}

		memset(res, 0, sizeof(struct conntrack_entry));
		res->proto = proto;

		pthread_mutexattr_t attr;
		if (pthread_mutexattr_init(&attr)) {
			pomlog(POMLOG_ERR "Error while initializing conntrack mutex attribute");
			goto err;
		}

		if (pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE)) {
			pomlog(POMLOG_ERR "Error while setting conntrack mutex attribute to recursive");
			pthread_mutexattr_destroy(&attr);
			goto err;
		}

		if(pthread_mutex_init(&res->lock, &attr)) {
			pomlog(POMLOG_ERR "Error while initializing a conntrack lock : %s", pom_strerror(errno));
			pthread_mutexattr_destroy(&attr);
			goto err;
		}

		if (pthread_mutexattr_destroy(&attr)) {
			pomlog(POMLOG_WARN "Error while destroying conntrack mutex attribute");
			goto err;
		}

		// Alloc the child list
		child = malloc(sizeof(struct conntrack_child_list));
		if (!child) 
			goto err;
		
		memset(child, 0, sizeof(struct conntrack_child_list));
		child->ce = res;
		res->parent = parent;

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


	pom_mutex_unlock(&parent->lock);

	return res;

err:
	pom_mutex_unlock(&parent->lock);
	if (res) {
		pthread_mutex_destroy(&res->lock);
		free(res);
	}

	if (child)
		free(child);

	return NULL;

}

struct conntrack_entry *conntrack_get(struct proto *proto, struct ptype *fwd_value, struct ptype *rev_value, struct conntrack_entry *parent, int *direction) {

	if (!fwd_value || !proto)
		return NULL;

	uint32_t full_hash_fwd = 0, hash_fwd = 0, full_hash_rev = 0, hash_rev = 0;

	if (conntrack_hash(&full_hash_fwd, fwd_value, rev_value) == POM_ERR) {
		pomlog(POMLOG_ERR "Error while computing forward hash for conntrack");
		return NULL;
	}

	struct conntrack_tables *ct = proto->ct;

	// Lock the tables while browsing for a conntrack
	pom_mutex_lock(&ct->lock);

	if (!ct->fwd_table) {
		pom_mutex_unlock(&ct->lock);
		pomlog(POMLOG_ERR "Cannot get conntrack as the forward table is not allocated");
		return NULL;
	}

	// Try to find the conntrack in the forward table
	hash_fwd = full_hash_fwd % ct->tables_size;

	// Check if we can find this entry in the forward way
	struct conntrack_entry *res = NULL;
	if (ct->fwd_table[hash_fwd]) {
		res = conntrack_find(ct->fwd_table[hash_fwd], fwd_value, rev_value, parent);
		if (res) {
			if (direction)
				*direction = POM_DIR_FWD;
			pom_mutex_unlock(&ct->lock);
			return res;
		}
	}

	// It wasn't found in the forward way, maybe in the reverse direction ?
	if (rev_value && ct->rev_table[hash_fwd]) {
		// Lookup the forward hash in the reverse table
		res = conntrack_find(ct->rev_table[hash_fwd], rev_value, fwd_value, parent);
		if (res) {
			if (direction)
				*direction = POM_DIR_REV;
			pom_mutex_unlock(&ct->lock);
			return res;
		}

	}

	// It's not found in the reverse direction either, let's create it then

	if (direction && *direction) {
		// This indicates that the parent conntrack matched in a reverse direction
		// Let's keep directions consistent and swap fwd and rev values
		struct ptype *tmp = rev_value;
		rev_value = fwd_value;
		fwd_value = tmp;
		hash_rev = hash_fwd;
		full_hash_rev = full_hash_fwd;
		if (conntrack_hash(&full_hash_fwd, fwd_value, rev_value) == POM_ERR) {
			pomlog(POMLOG_ERR "Error while computing forward hash for conntrack");
			return NULL;
		}
		hash_fwd = full_hash_fwd % ct->tables_size;
	}


	// Alloc the conntrack entry
	res = malloc(sizeof(struct conntrack_entry));
	if (!res) {
		pom_mutex_unlock(&ct->lock);
		pom_oom(sizeof(struct conntrack_entry));
		return NULL;
	}
	memset(res, 0, sizeof(struct conntrack_entry));

	pthread_mutexattr_t attr;
	if (pthread_mutexattr_init(&attr)) {
		pom_mutex_unlock(&ct->lock);
		free(res);
		pomlog(POMLOG_ERR "Error while initializing conntrack mutex attribute");
		return NULL;
	}

	if (pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE)) {
		pom_mutex_unlock(&ct->lock);
		free(res);
		pomlog(POMLOG_ERR "Error while setting conntrack mutex attribute to recursive");
		return NULL;
	}

	if(pthread_mutex_init(&res->lock, &attr)) {
		pom_mutex_unlock(&ct->lock);
		free(res);
		pomlog(POMLOG_ERR "Error while initializing a conntrack lock : %s", pom_strerror(errno));
		return NULL;
	}

	if (pthread_mutexattr_destroy(&attr)) {
		pomlog(POMLOG_WARN "Error while destroying conntrack mutex attribute");
	}

	struct conntrack_child_list *child = NULL;
	if (parent) {

		child = malloc(sizeof(struct conntrack_child_list));
		if (!child) {
			pthread_mutex_destroy(&res->lock);
			pom_mutex_unlock(&ct->lock);
			pom_oom(sizeof(struct conntrack_child_list));
			free(res);
			return NULL;
		}
		memset(child, 0, sizeof(struct conntrack_child_list));

		child->ce = res;
		res->parent = parent;

	}

	res->proto = proto;

	res->fwd_hash = full_hash_fwd;

	res->fwd_value = ptype_alloc_from(fwd_value);
	if (!res->fwd_value)
		goto err;

	// Alloc the forward list
	struct conntrack_list *lst_fwd = NULL;
	lst_fwd = malloc(sizeof(struct conntrack_list));
	if (!lst_fwd) {
		ptype_cleanup(res->fwd_value);
		pom_oom(sizeof(struct conntrack_list));
		goto err;
	}
	memset(lst_fwd, 0, sizeof(struct conntrack_list));
	lst_fwd->ce = res;

	// Alloc the reverse list
	struct conntrack_list *lst_rev = NULL;
	if (rev_value) {
		if (!direction || !*direction) { // Hash rev was already computed if we had to reverse the direction
			if (conntrack_hash(&full_hash_rev, rev_value, fwd_value) == POM_ERR) {
				pomlog(POMLOG_ERR "Error while computing reverse hash for conntrack");
				pom_mutex_unlock(&ct->lock);
				return NULL;
			}
			hash_rev = full_hash_rev % ct->tables_size;
		}

		res->rev_hash = full_hash_rev;
		lst_rev = malloc(sizeof(struct conntrack_list)); 
		if (!lst_rev) {
			ptype_cleanup(res->fwd_value);
			free(lst_fwd);
			pom_oom(sizeof(struct conntrack_list));
			goto err;
		}
		memset(lst_rev, 0, sizeof(struct conntrack_list));
		lst_rev->ce = res;

		res->rev_value = ptype_alloc_from(rev_value);
		if (!res->rev_value) {
			ptype_cleanup(res->fwd_value);
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
		pom_mutex_lock(&parent->lock);
		child->next = parent->children;
		if (child->next)
			child->next->prev = child;
		parent->children = child;
		pom_mutex_unlock(&parent->lock);
	}

	// Unlock the tables
	debug_conntrack("Allocated conntrack %p with parent %p", res, parent);
	pom_mutex_unlock(&ct->lock);
	
	return res;

err:
	pom_mutex_unlock(&ct->lock);

	pthread_mutex_destroy(&res->lock);
	if (child)
		free(child);

	if (lst_fwd)
		free(lst_fwd);

	if (lst_rev)
		free(lst_rev);
	
	if (res->fwd_value)
		ptype_cleanup(res->fwd_value);

	free(res);

	return NULL;
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
			timer_dequeue(ce->cleanup_timer);
			timer_cleanup(ce->cleanup_timer);
			ce->cleanup_timer = NULL;
		}
		return POM_OK;
	}

	if (!ce->cleanup_timer) {
		ce->cleanup_timer = timer_alloc(ce, conntrack_cleanup);
		if (!ce->cleanup_timer)
			return POM_ERR;
	}

	timer_queue(ce->cleanup_timer, delay);

	return POM_OK;
}


int conntrack_cleanup(void *conntrack) {

	struct conntrack_entry *ce = conntrack;

	pom_mutex_lock(&ce->lock);

	debug_conntrack("Cleaning up conntrack %p, with parent %p", ce, ce->parent);

	if (!ce->proto) {
		// Conntrack is already being cleaned up by another thread
		return POM_OK;
	}
	
	if (ce->cleanup_timer) {
		timer_cleanup(ce->cleanup_timer);
		ce->cleanup_timer = NULL;
	}

	struct proto *proto = ce->proto;
	ce->proto = NULL;

	if (ce->priv && proto->info->ct_info->cleanup_handler) {
		if (proto->info->ct_info->cleanup_handler(ce) != POM_OK)
			pomlog(POMLOG_WARN "Unable to free the private memory of a conntrack");
	}
	
	if (ce->parent) {
		// Remove the child from the parent
		pom_mutex_lock(&ce->parent->lock);
		struct conntrack_child_list *tmp = ce->parent->children;

		for (; tmp; tmp = tmp->next) {
			if (tmp->ce == ce)
				break;
		}

		if (tmp) {
			if (tmp->prev)
				tmp->prev->next = tmp->next;
			else
				ce->parent->children = tmp->next;

			if (tmp->next)
				tmp->next->prev = tmp->prev;

			free(tmp);
		} else {
			pomlog(POMLOG_WARN "Conntrack not found in parent's children list");
		}

		pom_mutex_unlock(&ce->parent->lock);
	}

	// Cleanup the children
	while (ce->children) {
		pom_mutex_unlock(&ce->lock);
		if (conntrack_cleanup(ce->children->ce) != POM_OK) {
			return POM_ERR;
		}
		pom_mutex_lock(&ce->lock);
	}


	struct conntrack_tables *ct = proto->ct;

	// Lock the tables while browsing for a conntrack
	pom_mutex_lock(&ct->lock);
	pom_mutex_unlock(&ce->lock);

	// Try to find the conntrack in the forward table
	uint32_t hash = ce->fwd_hash % ct->tables_size;

	struct conntrack_list *lst = NULL;

	for (lst = ct->fwd_table[hash]; lst; lst = lst->next)
		if (lst->ce == ce)
			break;
	
	if (!lst) {
		pom_mutex_unlock(&ct->lock);
		pomlog(POMLOG_ERR "Conntrack not found in the list for corresponding hash");
		return POM_ERR;
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
				pomlog(POMLOG_ERR "Conntrack list was supposed to be the head of reverse but wasn't !");
				return POM_ERR;
			}
			ct->rev_table[hash] = lst_rev->next;
		}

		if (lst_rev->next)
			lst_rev->next->prev = lst_rev->prev;
	
		free(lst_rev);
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

	pom_mutex_unlock(&ct->lock);

	
	if (ce->fwd_value)
		ptype_cleanup(ce->fwd_value);
	if (ce->rev_value)
		ptype_cleanup(ce->rev_value);

	pthread_mutex_destroy(&ce->lock);

	free(ce);

	return POM_OK;
}


