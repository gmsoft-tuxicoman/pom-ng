/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2012 Guy Martin <gmsoft@tuxicoman.be>
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

	return POM_OK;
}

