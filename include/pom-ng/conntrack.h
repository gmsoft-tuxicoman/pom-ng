/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2010 Guy Martin <gmsoft@tuxicoman.be>
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
#include <pom-ng/proto.h>

#define CT_DIR_FWD 0
#define CT_DIR_REV 1
#define CT_DIR_TOT 2 // Total number of possible directions

struct conntrack_entry {

	uint32_t fwd_hash, rev_hash; ///< Full hash prior to modulo
	struct ptype *fwd_value, *rev_value; ///< Forward and reverse value for hashing
	struct conntrack_entry *parent; ///< Parent conntrack
	struct conntrack_child_list *children; ///< Children of this conntrack
	void *priv; ///< Private data of the protocol
	pthread_mutex_t lock;
	struct timer *cleanup_timer; ///< Cleanup the conntrack when this timer is reached
	struct proto_reg *proto; ///< Proto of this conntrack
};

struct conntrack_child_list {
	struct conntrack_entry *ce; ///< Corresponding conntrack
	struct conntrack_child_list *prev, *next;
};

struct conntrack_list {
	struct conntrack_entry *ce; ///< Corresponding conntrack
	struct conntrack_list *prev, *next; ///< Next and previous connection in the list
	struct conntrack_list *rev; ///< Reverse connection
};

struct conntrack_info {
	unsigned int default_table_size;
	int fwd_pkt_field_id, rev_pkt_field_id;
	int (*cleanup_handler) (struct conntrack_entry *ce);
};

struct conntrack_tables {
	struct conntrack_list **fwd_table;
	struct conntrack_list **rev_table;
	pthread_mutex_t lock;
	size_t tables_size;
};

struct conntrack_entry *conntrack_get(struct proto_reg *proto, struct ptype *fwd_value, struct ptype *rev_value, struct conntrack_entry *parent, int *direction);
struct conntrack_entry* conntrack_get_unique_from_parent(struct proto_reg *proto, struct conntrack_entry *parent);
int conntrack_delayed_cleanup(struct conntrack_entry *ce, unsigned int delay);

#endif
