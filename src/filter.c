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


#include "filter.h"
#include "core.h"

int filter_proto_match(struct proto_process_stack *stack, struct filter_proto *f) {

	int res = FILTER_MATCH_NO;

	if (f->proto) {

		unsigned int i;
		for (i = CORE_PROTO_STACK_START; i <= CORE_PROTO_STACK_MAX && stack[i].proto; i++) {
			// Find if we match a specific proto
			if (stack[i].proto == f->proto) {
				if (!f->value) // No value for this filter, we just want to know if a proto exists
					res = FILTER_MATCH_YES;
				if (ptype_compare_val(f->op & PTYPE_OP_ALL, stack[i].pkt_info->fields_value[f->field_id], f->value))
					res = FILTER_MATCH_YES;
				break; // FIXME : Should we break or see if there is another instance of this proto later ?
			}
		}
	} else {
		// It's a branch
		
		int res_a = filter_proto_match(stack, f->a);

		if (f->op & FILTER_OP_OR)
			res = res_a || filter_proto_match(stack, f->b);
		else
			res = res_a && filter_proto_match(stack, f->b);
	}

	return (f->op & FILTER_OP_NOT ? !res : res);
}

struct filter_proto *filter_proto_build(char *proto, char *field, unsigned int op, char *value) {

	struct proto *p = proto_get(proto);
	if (!p)
		return NULL;

	struct proto_pkt_field *fields = p->info->pkt_fields;
	unsigned int field_id;
	for (field_id = 0; fields[field_id].name && strcmp(fields[field_id].name, field); field_id++);
	
	if (!fields[field_id].name) {
		pomlog(POMLOG_ERR "Field %s doesn't exists for proto %s", field, proto);
		return NULL;
	}

	struct ptype *v = ptype_alloc_from_type(fields[field_id].value_type);
	if (!v)
		return NULL;

	if (ptype_parse_val(v, value) != POM_OK) {
		ptype_cleanup(v);
		return NULL;
	}

	struct filter_proto *f = malloc(sizeof(struct filter_proto));
	if (!f) {
		ptype_cleanup(v);
		pom_oom(sizeof(struct filter_proto));
		return NULL;
	}
	memset(f, 0, sizeof(struct filter_proto));

	f->proto = p;
	f->op = op;
	f->value = v;
	f->field_id = field_id;


	return f;
}

struct filter_proto *filter_proto_build_branch(struct filter_proto *a, struct filter_proto *b, unsigned int op) {

	struct filter_proto *f = malloc(sizeof(struct filter_proto));
	if (!f) {
		pom_oom(sizeof(struct filter_proto));
		return NULL;
	}
	memset(f, 0, sizeof(struct filter_proto));

	f->a = a;
	f->b = b;
	f->op = op;

	return f;
}

void filter_proto_cleanup(struct filter_proto *f) {

	if (f->value)
		ptype_cleanup(f->value);

	if (f->a)
		filter_proto_cleanup(f->a);

	if (f->b)
		filter_proto_cleanup(f->b);

	free(f);
}
