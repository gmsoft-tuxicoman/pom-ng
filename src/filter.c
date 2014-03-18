/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2012-2014 Guy Martin <gmsoft@tuxicoman.be>
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










int filter_parse(char *expr, unsigned int len, struct filter_node **n, enum filter_type type) {

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
		*n = NULL;
		return POM_OK;
	}

	*n = malloc(sizeof(struct filter_node));
	if (!*n) {
		pom_oom(sizeof(struct filter_node));
		return POM_ERR;
	}
	memset(*n, 0, sizeof(struct filter_node));

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
			
			struct filter_branch *branch = &(*n)->branch;
			branch->op = branch_op;

			(*n)->type = filter_node_type_branch;
			
			if (filter_parse(expr, i - 1, &branch->a, type) != POM_OK || filter_parse(expr + i + 2, len - i - 2, &branch->b, type) != POM_OK)
				return POM_ERR;

			if (!branch->a || !branch->b) {
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
	return filter_parse_block(expr, len, n, type);
	
}


int filter_parse_block(char *expr, unsigned int len, struct filter_node **n, enum filter_type type) {

	if (len < 2)
		return POM_ERR;

	while (len && *expr == ' ') {
		expr++;
		len--;
	}

	while (len && expr[len - 1] == ' ')
		len--;

	if (!len) {
		*n = NULL;
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
		int res = filter_parse(expr, len, n, type);
		if (inv)
			(*n)->not = 1;
		return res;
	}

	// At this point we should have only 'what op value' i.e. 'event.data.blah = 2'

	switch (type) {
		case filter_type_payload:
			return filter_pload_parse_block(expr, len, *n);
		case filter_type_event:
			return filter_event_parse_block(expr, len, *n);
	}

	return POM_ERR;
}

int filter_event_parse_block(char *expr, unsigned int len, struct filter_node *n) {

	// Example of value passed : "data.width > 400", "data.request_header[cookies]", "name == some_event_name"

	// There are a few things that we can parse

	if (len >= strlen("time ") && !strncmp(expr, "time ", strlen("time "))) {
		n->type = filter_node_type_event_prop;
		n->data.field_id = filter_evt_prop_type_time;
	} else if (len >= strlen("name ") && !strncmp(expr, "name ", strlen("name "))) {
		n->type = filter_node_type_event_prop;
		n->data.field_id = filter_evt_prop_type_name;
	} else if (len >= strlen("source ") && !strncmp(expr, "source ", strlen("source "))) {
		n->type = filter_node_type_event_prop;
		n->data.field_id = filter_evt_prop_type_source;
	} else if (len >= strlen("descr ") && !strncmp(expr, "descr ", strlen("descr "))) {
		n->type = filter_node_type_event_prop;
		n->data.field_id = filter_evt_prop_type_descr;
	} else if (len >= strlen("data.") && !strncmp(expr, "data.", strlen("data."))) {
		n->type = filter_node_type_event_data;
		expr += strlen("data.");
		len -= strlen("data.");
	} else {
		pomlog(POMLOG_ERR "Unexpected value for event property !");
		return POM_ERR;
	}
	
	char* space = memchr(expr, ' ', len);

	if (space) {
		while (*space == ' ')
			space++;
	}

	if (n->type == filter_node_type_event_data) {
		size_t field_len = len;

		if (space)
			field_len = space - expr - 1;

	
		char *key = memchr(expr, '[', field_len);
		if (key) {
			if (*(expr + field_len - 1) != ']') {
				pomlog(POMLOG_ERR "Missing ']'");
				return POM_ERR;
			}
			key++;
			size_t key_len = expr + field_len - key - 1;
			n->data.key = strndup(key, key_len);
			if (!n->data.key) {
				pom_oom(key_len + 1);
				return POM_ERR;
			}
			field_len = key - expr - 1;
		}

		n->data.name = strndup(expr, field_len);
		if (!n->data.name) {
			pom_oom(field_len + 1);
			return POM_ERR;
		}

		if (!space) {
			// Nothing more to parse
			return POM_OK;
		}

		len -= space - expr;
		expr = space;
		space = memchr(expr, ' ', len);

		if (!space) {
			// Nothing more to parse
			return POM_OK;
		}

		while (*space == ' ')
			space++;
	} else {
		len -= space - expr;
		expr = space;
		space = memchr(expr, ' ', len);

		if (!space) {
			pomlog(POMLOG_ERR "Mandatory argument missing");
			return POM_ERR;
		}

	}

	n->data.op_str = strndup(expr, space - expr - 1);
	if (!n->data.op_str) {
		pom_oom(space - expr);
		return POM_ERR;
	}

	while (*space == ' ')
		space++;

	n->data.value_str = strndup(space, len - (space - expr));
	if (!n->data.value_str) {
		pom_oom(len - (space - expr));
		return POM_ERR;
	}

	return POM_OK;
}

int filter_pload_parse_block(char *expr, unsigned int len, struct filter_node *n) {

	// Example of value passed : "evt.data.width > 400", "data.request_header[cookies]", "name == some_event_name"

	// There are a few things that we can parse

	if (len >= strlen("evt.") && !strncmp(expr, "evt.", strlen("evt."))) {
		// Parse event related stuff
		return filter_pload_parse_block(expr + strlen("evt."), len - strlen("evt."), n);
	} else if (len >= strlen("type.") && !strncmp(expr, "type.", strlen("type."))) {
		n->type = filter_node_type_pload_type;
		expr += strlen("type.");
		len -= strlen("type.");
	} else if (len >= strlen("data.") && !strncmp(expr, "data.", strlen("data."))) {
		n->type = filter_node_type_pload_data;
		expr += strlen("data.");
		len -= strlen("data.");
	} else {
		pomlog(POMLOG_ERR "Unexpected value for pload property !");
		return POM_ERR;
	}
	
	char *space = memchr(expr, ' ', len);

	size_t field_len = len;
	if (space) {
		field_len = space - expr;
		while (*space == ' ')
			space++;
	}

	if (n->type == filter_node_type_pload_data) {
		char *key = memchr(expr, '[', field_len);
		if (key) {
			if (*(expr + field_len - 1) != ']') {
				pomlog(POMLOG_ERR "Missing ']'");
				return POM_ERR;
			}
			key++;
			size_t key_len = expr + field_len - key - 1;
			n->data.key = strndup(key, key_len);
			if (!n->data.key) {
				pom_oom(key_len + 1);
				return POM_ERR;
			}
			field_len = key - expr - 1;
		}
	}

	n->data.name = strndup(expr, field_len);
	if (!n->data.name) {
		pom_oom(field_len + 1);
		return POM_ERR;
	}

	while (*space == ' ')
		space++;

	n->data.op_str = strndup(expr, space - expr);
	if (!n->data.op_str) {
		pom_oom(space - expr);
		return POM_ERR;
	}

	while (*space == ' ')
		space++;

	n->data.value_str = strndup(space, len - (space - expr));
	if (!n->data.value_str) {
		pom_oom(len - (space - expr));
		return POM_ERR;
	}

	return POM_OK;
}


void filter_cleanup(struct filter_node *filter) {
	// TODO
	return;
}


int filter_event_compile(struct filter_node *filter, struct event_reg *evt) {

	if (filter->type == filter_node_type_branch) {
		if (filter_event_compile(filter->branch.a, evt) != POM_OK)
			return POM_ERR;

		if (filter_event_compile(filter->branch.b, evt) != POM_OK)
			return POM_ERR;

	} else if (filter->type == filter_node_type_event_prop) {

		filter->data.op = ptype_get_op(NULL, filter->data.op_str);

		if (filter->data.op == POM_ERR) {
			pomlog(POMLOG_ERR "Invalid operation \"%s\" for event property", filter->data.op_str);
			return POM_ERR;
		}

		if (filter->data.field_id != filter_evt_prop_type_time && (filter->data.op != PTYPE_OP_EQ && filter->data.op != PTYPE_OP_NEQ)) {
			pomlog(POMLOG_ERR "Operation \"%s\" not allowed for event property", filter->data.op_str);
			return POM_ERR;
		}

	} else if (filter->type == filter_node_type_event_data) {
		
		struct event_reg_info *info = event_reg_get_info(evt);

		struct data_reg *data = info->data_reg;

		char *name = filter->data.name;

		// Find the right item
		int i;
		struct data_item_reg *item = NULL;
		for (i = 0; i < data->data_count; i++) {
			item = &data->items[i];
			if (!strcmp(item->name, name))
				break;
		}

		if (i >= data->data_count) {
			pomlog(POMLOG_ERR "Item \"%s\" does not exists", name);
			return POM_ERR;
		}

		filter->data.field_id = i;

		if (item->flags & DATA_REG_FLAG_LIST) {
			if (!filter->data.key) {
				pomlog(POMLOG_ERR "Filter item \"%s\" requires a key as it's a list", name);
				return POM_ERR;
			}
		} else {
			if (filter->data.key) {
				pomlog(POMLOG_ERR "Filter item \"%s\" is not a list, no key should be provided", name);
				return POM_ERR;
			}
		}

		if (!filter->data.op_str)
			return POM_OK;


		if (!filter->data.value_str) {
			pomlog(POMLOG_ERR "No value for item \"%s\"", name);
			return POM_ERR;
		}

		filter->data.value = ptype_alloc_from_type(item->value_type);
		if (!filter->data.value)
			return POM_ERR;

		if (ptype_parse_val(filter->data.value, filter->data.value_str) != POM_OK) {
			pomlog(POMLOG_ERR "Could not parse filter value \"%s\" for item \"%s\"", filter->data.value_str, name);
			return POM_ERR;
		}

		filter->data.op = ptype_get_op(filter->data.value, filter->data.op_str);

		if (filter->data.op == POM_ERR) {
			pomlog(POMLOG_ERR "Invalid ptype operation \"%s\" for item \"%s\"", filter->data.op_str, name);
			return POM_ERR;
		}

	} else {
		pomlog(POMLOG_ERR "Unexpected filter node type %u", filter->type);
		return POM_ERR;
	}

	return POM_OK;

}


int filter_event_match(struct filter_node *filter, struct event *evt) {

	if (filter->type == filter_node_type_branch) {

		int res_a = filter_event_match(filter->branch.a, evt);
		int res_b = filter_event_match(filter->branch.b, evt);

		if (res_a == POM_ERR || res_b == POM_ERR)
			return POM_ERR;

		if (filter->branch.op == FILTER_OP_AND)
			return res_a && res_b;
		
		// FILTER_OP_OR

		return res_a || res_b;

	} else if (filter->type == filter_node_type_event_prop) {

	} else if (filter->type == filter_node_type_event_data) {

		struct data *data = event_get_data(evt);

		if (!data_is_set(data[filter->data.field_id]))
			return FILTER_MATCH_NO;

		if (!filter->data.value)
			return FILTER_MATCH_YES;
		
		return ptype_compare_val(filter->data.op, filter->data.value, data[filter->data.field_id].value);


	}

	pomlog(POMLOG_ERR "Unhandled filter node type");
	return POM_ERR;
}


int filter_event(char *filter_expr, struct event_reg *evt_reg, struct filter_node **filter) {

	if (filter_parse(filter_expr, strlen(filter_expr), filter, filter_type_event) != POM_OK)
		return POM_ERR;

	if (!*filter)
		return POM_OK;

	if (filter_event_compile(*filter, evt_reg) != POM_OK)
		return POM_ERR;

	return POM_OK;
}
