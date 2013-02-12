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


#ifndef __CONNTRACK_H__
#define __CONNTRACK_H__

#include <pom-ng/proto.h>
#include <pom-ng/conntrack.h>

#define CONNTRACK_CHILDLESS_TIMEOUT	10

struct conntrack_tables {
	struct conntrack_list **table;
	pthread_mutex_t *locks;
	size_t table_size;
};

struct conntrack_session {

	unsigned int refcount;
	struct conntrack_priv_list *privs;
	pthread_mutex_t lock;
};

struct conntrack_priv_list {
	void *obj;
	void *priv;
	int (*cleanup) (void *obj, void *priv);

	struct conntrack_priv_list *prev, *next;
};

struct conntrack_timer {

	struct timer *timer;
	struct conntrack_entry *ce;
	struct proto *proto;
	uint32_t hash;
	int (*handler) (struct conntrack_entry *ce, void *priv);
	void *priv;

	struct conntrack_timer *prev, *next;
};

struct conntrack_tables* conntrack_table_alloc(size_t table_size, int has_rev);
int conntrack_table_empty(struct conntrack_tables *ct);
int conntrack_table_cleanup(struct conntrack_tables *ct);
uint32_t conntrack_hash(struct ptype *a, struct ptype *b);
struct conntrack_entry *conntrack_find(struct conntrack_list *lst, struct ptype *fwd_value, struct ptype *rev_value, struct conntrack_entry *parent);
int conntrack_timed_cleanup(void *timer, ptime now);
int conntrack_cleanup(struct conntrack_tables *ct, uint32_t hash, struct conntrack_entry *ce);


int conntrack_timer_process(void *priv, ptime now);

int conntrack_session_bind(struct conntrack_entry *ce, struct conntrack_session *session);
int conntrack_session_refcount_dec(struct conntrack_session *session);

#endif
