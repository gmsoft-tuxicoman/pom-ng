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


#ifndef __POM_NG_CONNTRACK_H__
#define __POM_NG_CONNTRACK_H__

#include <pom-ng/base.h>

#define CONNTRACK_PKT_FIELD_NONE -1

struct proto_process_stack;

struct conntrack_entry {

	struct ptype *fwd_value, *rev_value; ///< Forward and reverse value for hashing
	struct conntrack_node_list *parent; ///< Parent conntrack
	struct conntrack_node_list *children; ///< Children of this conntrack
	void *priv; ///< Private data of the protocol
	struct conntrack_priv_list *priv_list; ///< Private data coming from other objects
	struct conntrack_timer *cleanup_timer; ///< Cleanup the conntrack when this timer is reached
	struct proto *proto; ///< Proto of this conntrack
	struct conntrack_session *session; ///< Session to which this conntrack belongs
	pthread_mutex_t lock; ///< Lock of the conntrack entry
	uint32_t hash; ///< Full hash prior to modulo
	unsigned int refcount; ///< Reference count (mostly in how many proto_stack it's referenced)
};

struct conntrack_node_list {
	struct conntrack_entry *ce; ///< Corresponding conntrack
	struct conntrack_tables *ct; ///< Tables in which this conntrack is stored
	struct conntrack_node_list *prev, *next;
	uint32_t hash; ///< Hash of the conntrack
};

struct conntrack_list {
	struct conntrack_entry *ce; ///< Corresponding conntrack
	struct conntrack_list *prev, *next; ///< Next and previous connection in the list
};

struct conntrack_info {
	int (*cleanup_handler) (void *ce_priv);
	unsigned int default_table_size;
	int fwd_pkt_field_id, rev_pkt_field_id;
};

int conntrack_get(struct proto_process_stack *stack, unsigned int stack_index);
int conntrack_get_unique_from_parent(struct proto_process_stack *stack, unsigned int stack_index);
int conntrack_get_unique(struct proto_process_stack *stack, unsigned int stack_index);

void conntrack_lock(struct conntrack_entry *ce);
void conntrack_unlock(struct conntrack_entry *ce);
void conntrack_refcount_dec(struct conntrack_entry *ce);


int conntrack_add_priv(struct conntrack_entry *ce, void *obj, void *priv, int (*cleanup) (void *obj, void *priv));
void *conntrack_get_priv(struct conntrack_entry *ce, void *obj);

int conntrack_delayed_cleanup(struct conntrack_entry *ce, unsigned int delay, ptime now);

struct conntrack_timer *conntrack_timer_alloc(struct conntrack_entry *ce, int (*handler) (struct conntrack_entry *ce, void *priv, ptime now), void *priv);
int conntrack_timer_queue(struct conntrack_timer *t, unsigned int expiry, ptime now);
int conntrack_timer_dequeue(struct conntrack_timer *t);
int conntrack_timer_cleanup(struct conntrack_timer *t);

struct conntrack_session *conntrack_session_get(struct conntrack_entry *ce);
void conntrack_session_unlock(struct conntrack_session *session);
int conntrack_session_add_priv(struct conntrack_session *s, void *obj, void *priv, int (*cleanup_handler) (void *obj, void *priv));
void *conntrack_session_get_priv(struct conntrack_session *s, void *obj);

#endif
