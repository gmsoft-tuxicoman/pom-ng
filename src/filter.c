/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2012-2013 Guy Martin <gmsoft@tuxicoman.be>
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
#include "proto.h"

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

int filter_proto_parse(char *expr, unsigned int len, struct filter_proto **f) {

	unsigned int i;
	int stack_size = 0;

	int branch_found = 0;
	int branch_op = 0;

	while (len && *expr == ' ') {
		expr++;
		len--;
	}

	while (len && expr[len - 1] == ' ')
		len--;

	if (!len) {
		*f = NULL;
		return POM_OK;
	}

	for (i = 0; i < len; i++) {
		if (stack_size == 0 && expr[i] == '|' && expr[i + 1] == '|')  {
			branch_found = 1;
			branch_op = FILTER_OP_OR;
		} else if (stack_size == 0 && expr[i] == '&' && expr[i + 1] == '&') {
			branch_found = 1;
			branch_op = FILTER_OP_AND;
		}

		if (expr[i] == '(') {
			stack_size++;
			continue;
		}
		if (expr[i] == ')') {
			if (stack_size == 0) {
				pomlog(POMLOG_ERR "Unmatched ')' at pos %u in expression '%s'", i, expr);
				return POM_ERR;
			}
			stack_size--;
			continue;
		}

		if (branch_found) {
			// A branch was found, parse both sides

			*f = malloc(sizeof(struct filter_proto));
			if (!*f) {
				pom_oom(sizeof(struct filter_proto));
				return POM_ERR;
			}
			memset(*f, 0, sizeof(struct filter_proto));
			
			(*f)->op = branch_op;
			
			if (filter_proto_parse_block(expr, i - 1, &(*f)->a) != POM_OK || filter_proto_parse(expr + i + 2, len - i - 2, &(*f)->b) != POM_OK)
				return POM_ERR;

			if (!(*f)->a || !(*f)->b) {
				pomlog(POMLOG_ERR "Branch of expression empty in expression '%s'", expr);
				return POM_ERR;
			}

			return POM_OK;
		}
	}

	if (stack_size > 0) {
		pomlog(POMLOG_ERR "Unmatched '(' in expression '%s'", expr);
		return POM_ERR;
	}

	// There was no branch, process the whole thing then
	return filter_proto_parse_block(expr, len, f);
	
}

int filter_proto_parse_block(char *expr, unsigned int len, struct filter_proto **f) {

	if (len < 2)
		return POM_ERR;

	while (len && *expr == ' ') {
		expr++;
		len--;
	}

	while (len && expr[len - 1] == ' ')
		len--;

	if (!len) {
		*f = NULL;
		return POM_OK;
	}

	// Find out if there is an inversion
	int inv = 0;
	if (expr[0] == '!') {
		inv = 1;
		expr++;
		len--;
		while (*expr == ' ') {
			expr++;
			len--;
		}

	}

	if (expr[0] == '(' && expr[len - 1] == ')') {
		expr++;
		len -= 2;
		int res = filter_proto_parse(expr, len, f);
		if (inv)
			(*f)->op = ((*f)->op & FILTER_OP_NOT ? (*f)->op & ~FILTER_OP_NOT : (*f)->op | FILTER_OP_NOT);
		return res;
	}

	// At this point we should have 'proto.field op value'
	

	// Search for the first token
	char *dot = memchr(expr, '.', len);
	if (!dot) {
		pomlog(POMLOG_ERR "No field found");
		return POM_ERR;
	}
	
	// Parse and find the protocol
	char *proto_str = strndup(expr, dot - expr);
	if (!proto_str) {
		pom_oom(dot - expr + 1);
		return POM_ERR;
	}
	struct proto *proto = proto_get(proto_str);

	if (!proto) {
		pomlog(POMLOG_ERR "Protocol %s doesn't exists", proto);
		free(proto_str);
		return POM_ERR;
	}
	free(proto_str);

	// Parse and find the field
	char *space = memchr(expr, ' ', len);
	size_t field_len;
	if (space) {
		field_len = space - dot - 1;
		while (*space == ' ')
			space++;
	} else {
		field_len = len - (dot - expr);
	}
	
	char *field = strndup(dot + 1, field_len);
	if (!field) {
		pom_oom(field_len + 1);
		return POM_ERR;
	}

	int field_id;
	for (field_id = 0; proto->info->pkt_fields[field_id].name && strcmp(proto->info->pkt_fields[field_id].name, field); field_id++);

	if (!proto->info->pkt_fields[field_id].name) {
		pomlog(POMLOG_ERR "Field %s doesn't exists for proto %s", field, proto->info->name);
		free(field);
		return POM_ERR;
	}
	free(field);

	*f = malloc(sizeof(struct filter_proto));
	if (!*f) {
		pom_oom(sizeof(struct filter_proto));
		return POM_ERR;
	}
	memset(*f, 0, sizeof(struct filter_proto));

	struct filter_proto *filter = *f;
	filter->field_id = field_id;
	filter->proto = proto;

	if (!space) // Only make sure that the field is set if no value exists
		return POM_OK;

	// Parse the op
	len -= space - expr;
	expr = space;

	space = memchr(expr, ' ', len);

	if (!space) {
		pomlog(POMLOG_ERR "Invalid expression. Missing operation or value");
		goto err;
	}

	char *op_str = strndup(expr, space - expr);
	if (!op_str) {
		pom_oom(space - expr);
		goto err;
	}

	while (*space == ' ')
		space++;

	char *value_str = strndup(space, len - (space - expr));
	if (!value_str) {
		free(op_str);
		pom_oom(len - (space - expr));
		goto err;
	}

	filter->value = ptype_alloc_from_type(proto->info->pkt_fields[field_id].value_type);
	if (!filter->value) {
		free(op_str);
		free(value_str);
		goto err;
	}

	if (ptype_parse_val(filter->value, value_str) != POM_OK) {
		pomlog(POMLOG_ERR "Error while parsing value '%s'", value_str);
		free(op_str);
		free(value_str);
		goto err;
	}


	filter->op = ptype_get_op(filter->value, op_str);
	if (filter->op == POM_ERR) {
		free(value_str);
		pomlog(POMLOG_ERR "Invalid operation '%s'", op_str);
		free(op_str);
		goto err;
	}

	free(op_str);

	if (inv)
		filter->op |= FILTER_OP_NOT;

	return POM_OK;

err:
	if (*f) {
		if ((*f)->value)
			ptype_cleanup((*f)->value);
		free(*f);
		*f = NULL;
	}
	return POM_ERR;
}
