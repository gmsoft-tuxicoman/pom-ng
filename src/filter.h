/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2012-2015 Guy Martin <gmsoft@tuxicoman.be>
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


#ifndef __FILTER_H__
#define __FILTER_H__

#include <pom-ng/ptype.h>

#define FILTER_OP_NOP	PTYPE_OP_RSVD
#define FILTER_OP_EQ	PTYPE_OP_EQ
#define FILTER_OP_GT	PTYPE_OP_GT
#define FILTER_OP_GE	PTYPE_OP_GE
#define FILTER_OP_LT	PTYPE_OP_LT
#define FILTER_OP_LE	PTYPE_OP_LE
#define FILTER_OP_NEQ	PTYPE_OP_NEQ

#define FILTER_OP_AND	(PTYPE_OP_ALL + 1)
#define FILTER_OP_OR	(PTYPE_OP_ALL + 2)

// Remove this one when merge complete
#define FILTER_OP_NOT	(PTYPE_OP_ALL + 3)

#include <pom-ng/data.h>


#include <pom-ng/ptype_bool.h>
#include <pom-ng/ptype_uint8.h>
#include <pom-ng/ptype_uint16.h>
#include <pom-ng/ptype_uint32.h>
#include <pom-ng/ptype_uint64.h>


enum filter_value_type {
	filter_value_type_unknown,
	filter_value_type_prop,
	filter_value_type_string,
	filter_value_type_int,
	filter_value_type_node,
	filter_value_type_ptype,
};

struct filter_prop {
	void *priv;
	enum filter_value_type out_type;
	struct ptype_reg *out_ptype;
};

union filter_value_u {
	struct filter_prop prop;
	char *string;
	uint64_t integer;
	struct filter_node *node;
	struct ptype *ptype;
};

struct filter_value {
	enum filter_value_type type;
	union filter_value_u val;
};

struct filter_node {

	int op;
	int not;

	struct filter_value value[2];
};

struct filter {

	struct filter_node *n;
	int (*prop_compile) (struct filter *f, char *prop_str, struct filter_value *v);
	int (*prop_get_val) (struct filter_value *inval, struct filter_value *outval, void *obj);
	void (*prop_cleanup) (void *prop);
	void *priv;
};


struct filter *filter_alloc(int (*prop_compile) (struct filter *f, char *prop_str, struct filter_value *v), void *priv, int (*prop_get_val) (struct filter_value *inval, struct filter_value *outval, void *obj), void (*prop_cleanup) (void *(prop)));



int filter_ptype_is_integer(struct ptype_reg *reg);
int filter_ptype_is_string(struct ptype_reg *reg);
uint64_t filter_ptype_int_get(struct ptype* pt);
void filter_ptype_to_value(struct filter_value *v, struct ptype *pt);

int filter_parse_expr(struct filter *f, char *expr, unsigned int len, struct filter_node **n);

int filter_compile(char *filter_expr, struct filter *f);

int filter_node_data_match(struct filter_node *n, struct data *d);

int filter_match(struct filter *n, void *obj);

#endif

