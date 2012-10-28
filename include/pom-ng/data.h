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


#ifndef __POM_NG_DATA_H__
#define __POM_NG_DATA_H__

// Indicate that the data will be an array
#define DATA_REG_FLAG_LIST	0x1
// Indicate that the data should not be allocated automatically
#define DATA_REG_FLAG_NO_ALLOC	0x2
// Indicate that this data is always set by the corresponding module
#define DATA_REG_FLAG_ALWAYS_SET 0x4

// Indicate that the data has been set
#define DATA_FLAG_SET		0x1
// Indicate that the data shouldn't be cleaned up by the API
#define DATA_FLAG_NO_CLEAN	0x2

#define data_set(x) ((x).flags |= DATA_FLAG_SET)
#define data_is_set(x) ((x).flags & DATA_FLAG_SET)

struct data_item {
	char *key;
	struct ptype *value;
	struct data_item *next;
};

struct data {

	union {
		struct ptype *value;
		struct data_item *items;
	};
	unsigned int flags;

};


struct data_reg {
	struct data_item_reg *items;
	int data_count;
};

struct data_item_reg {
	int flags;
	char *name;
	struct ptype_reg *value_type;
};

struct data *data_alloc_table(struct data_reg *d_reg);
void data_cleanup_table(struct data *d, struct data_reg *d_reg);
struct ptype *data_item_add(struct data *d, struct data_reg *d_reg, unsigned int data_id, const char *key);
int data_item_add_ptype(struct data *d, unsigned int data_id, const char *key, struct ptype *value);


#endif
