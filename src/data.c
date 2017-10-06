/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2014-2017 Guy Martin <gmsoft@tuxicoman.be>
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
#include <pom-ng/data.h>
#include <pom-ng/ptype.h>

struct data *data_alloc_table(struct data_reg *d_reg) {

	struct data *d = malloc(sizeof(struct data) * d_reg->data_count);
	if (!d) {
		pom_oom(sizeof(struct data) * d_reg->data_count);
		return NULL;
	}
	memset(d, 0, sizeof(struct data) * d_reg->data_count);

	int i;
	for (i = 0; i < d_reg->data_count; i++) {
		if (!(d_reg->items[i].flags & (DATA_REG_FLAG_LIST | DATA_REG_FLAG_NO_ALLOC))) {
			d[i].value = ptype_alloc_from_type(d_reg->items[i].value_type);
			if (!d[i].value)
				goto err;
		}
		// Automatically set the non cleanup flag for non allocated data
		if (d_reg->items[i].flags & DATA_REG_FLAG_NO_ALLOC)
			d[i].flags = DATA_FLAG_NO_CLEAN;
	}
	return d;

err:
	for (i = 0; i < d_reg->data_count && d[i].value; i++)
		ptype_cleanup(d[i].value);

	free(d);

	return NULL;
}


void data_cleanup_table(struct data *d, struct data_reg *d_reg) {

	int i;

	for (i = 0; i < d_reg->data_count; i++) {
		if (d[i].flags & DATA_FLAG_NO_CLEAN)
			continue;
		if (d_reg->items[i].flags & DATA_REG_FLAG_LIST) {
			struct data_item *item = d[i].items;
			while (item) {
				struct data_item *tmp = item->next;
				free(item->key);
				ptype_cleanup(item->value);
				free(item);
				item = tmp;
			}
		} else {
			ptype_cleanup(d[i].value);
		}
	}
	free(d);

}

struct ptype *data_item_add(struct data *d, struct data_reg *d_reg, unsigned int data_id, const char *key) {

	struct ptype *value = ptype_alloc_from_type(d_reg->items[data_id].value_type);
	if (!value) 
		return NULL;
	
	if (data_item_add_ptype(d, data_id, key, value) != POM_OK) {
		ptype_cleanup(value);
		return NULL;
	}

	return value;
}

int data_item_add_ptype(struct data *d, unsigned int data_id, const char *key, struct ptype *value) {

	if (!key)
		return POM_ERR;

	struct data_item *item = malloc(sizeof(struct data_item));
	if (!item) {
		pom_oom(sizeof(struct data_item));
		return POM_ERR;
	}
	memset(item, 0, sizeof(struct data_item));
	
	item->key = (char*)key;
	item->value = value;

	item->next = d[data_id].items;
	d[data_id].items = item;
	d[data_id].flags |= DATA_FLAG_SET;

	return POM_OK;
}

int data_item_copy(struct data *src, int data_id_src, struct data* dst, int data_id_dst) {

	// Assume that both source and dest are lists

	if (dst[data_id_dst].items) {
		pomlog(POMLOG_ERR "Destination data item isn't empty.");
		return POM_ERR;
	}

	struct data_item **last = &(dst[data_id_dst].items);
	struct data_item *sitem = src[data_id_src].items;

	while (sitem) {
		struct data_item *ditem = malloc(sizeof(struct data_item));
		if (!ditem) {
			pom_oom(sizeof(struct data_item));
			return POM_ERR;
		}
		memset(ditem, 0, sizeof(struct data_item));
		ditem->key = strdup(sitem->key);
		if (!ditem->key) {
			pom_oom(strlen(sitem->key) + 1);
			free(ditem);
			return POM_ERR;
		}
		ditem->value = ptype_alloc_from(sitem->value);
		if (!ditem->value) {
			free(ditem->key);
			free(ditem);
			return POM_ERR;
		}

		*last = ditem;
		last = &ditem->next;

		sitem = sitem->next;
	}
	dst[data_id_dst].flags |= DATA_FLAG_SET;

	return POM_OK;
}
