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

#include "proto.h"
#include "jhash.h"

#include "common.h"

#define INITVAL 0x5de97c2d // random value

int proto_ct_hash(uint32_t *hash, struct ptype *fwd, struct ptype *rev) {

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


struct proto_conntrack_entry *proto_ct_find(struct proto_conntrack_list *lst, struct ptype *fwd_value, struct ptype *rev_value) {

	if (!fwd_value)
		return NULL;


	for (; lst; lst = lst->next) {

		// Check the forward value
		struct proto_conntrack_entry *ce = lst->ce;
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

struct proto_conntrack_entry *proto_ct_get(struct proto_reg *proto, struct ptype *fwd_value, struct ptype *rev_value) {

	if (!proto || !fwd_value)
		return NULL;

	if (!proto->ct.fwd_table) {
		pomlog(POMLOG_ERR "Cannot get conntrack for proto %s as it has no conntrack table allocated", proto->info->name);
		return NULL;
	}

	uint32_t full_hash_fwd = 0, hash_fwd = 0, full_hash_rev = 0, hash_rev = 0;

	if (proto_ct_hash(&full_hash_fwd, fwd_value, rev_value) == POM_ERR) {
		pomlog(POMLOG_ERR "Error while computing forward hash for conntrack");
		return NULL;
	}

	// Try to find the conntrack in the forward table
	hash_fwd = full_hash_fwd % proto->ct.tables_size;

	// Check if we can find this entry in the forward way
	struct proto_conntrack_entry *res = proto_ct_find(proto->ct.fwd_table[hash_fwd], fwd_value, rev_value);
	if (res)
		return res;

	// It wasn't found in the forward way, maybe in the reverse direction ?
	if (rev_value) {
		if (proto_ct_hash(&full_hash_rev, rev_value, fwd_value) == POM_ERR) {
			pomlog(POMLOG_ERR "Error while computing reverse hash for conntrack");
			return NULL;
		}
		hash_rev = full_hash_rev % proto->ct.tables_size;

		res = proto_ct_find(proto->ct.rev_table[hash_rev], rev_value, fwd_value);
		if (res)
			return res;

	}

	// It's not found in the reverse direction either, let's create it then

	// Alloc the conntrack entry
	res = malloc(sizeof(struct proto_conntrack_entry));
	if (!res) {
		pom_oom(sizeof(struct proto_conntrack_entry));
		return NULL;
	}
	memset(res, 0, sizeof(struct proto_conntrack_entry));

	res->fwd_hash = full_hash_fwd;

	res->fwd_value = ptype_alloc_from(fwd_value);
	if (!res->fwd_value) {
		free(res);
		return NULL;
	}

	// Alloc the forward list
	struct proto_conntrack_list *lst_fwd = malloc(sizeof(struct proto_conntrack_list));
	if (!lst_fwd) {
		ptype_cleanup(res->fwd_value);
		free(res);
		pom_oom(sizeof(struct proto_conntrack_list));
		return NULL;
	}
	memset(lst_fwd, 0, sizeof(struct proto_conntrack_list));
	lst_fwd->ce = res;

	// Alloc the reverse list
	if (rev_value) {
		res->rev_hash = full_hash_rev;
		struct proto_conntrack_list *lst_rev = malloc(sizeof(struct proto_conntrack_list));
		if (!lst_rev) {
			ptype_cleanup(res->fwd_value);
			free(res);
			free(lst_fwd);
			pom_oom(sizeof(struct proto_conntrack_list));
			return NULL;
		}
		memset(lst_rev, 0, sizeof(struct proto_conntrack_list));
		lst_rev->ce = res;

		res->rev_value = ptype_alloc_from(rev_value);
		if (!res->rev_value) {
			ptype_cleanup(res->fwd_value);
			free(res);
			free(lst_fwd);
			free(lst_rev);
			return NULL;
		}

		// Insert the reverse direction in the conntrack table
		lst_rev->next = proto->ct.rev_table[hash_rev];
		if (lst_rev->next)
			lst_rev->next->prev = lst_rev;
		proto->ct.rev_table[hash_rev] = lst_rev;


	}

	// Insert the forward direction in the conntrack table
	lst_fwd->next = proto->ct.fwd_table[hash_fwd];
	if (lst_fwd->next)
		lst_fwd->next->prev = lst_fwd;
	proto->ct.fwd_table[hash_fwd] = lst_fwd;

	return res;
}
