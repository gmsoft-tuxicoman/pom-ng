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

int filter_raw_parse(char *expr, unsigned int len, struct filter_raw_node **n) {

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

	if (!len)
		return POM_OK;

	if (!*n) {

		*n = malloc(sizeof(struct filter_raw_node));
		if (!*n) {
			pom_oom(sizeof(struct filter_raw_node));
			return POM_ERR;
		}
	}
	memset(*n, 0, sizeof(struct filter_raw_node));

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
			
			struct filter_raw_branch *branch = &(*n)->branch;
			branch->op = branch_op;

			(*n)->isbranch = 1;
			
			if (filter_raw_parse(expr, i - 1, &branch->a) != POM_OK || filter_raw_parse(expr + i + 2, len - i - 2, &branch->b) != POM_OK)
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
	return filter_raw_parse_block(expr, len, n);
	
}


int filter_raw_parse_block(char *expr, unsigned int len, struct filter_raw_node **n) {

	if (len < 2)
		return POM_ERR;

	while (len && *expr == ' ') {
		expr++;
		len--;
	}

	while (len && expr[len - 1] == ' ')
		len--;

	if (!len)
		return POM_OK;

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
		int res = filter_raw_parse(expr, len, n);
		if (inv)
			(*n)->not = 1;
		return res;
	}


	char *space = memchr(expr, ' ', len);

	size_t data_len = len;

	if (space) {
		data_len = space - expr;
	}

	(*n)->data.value[0] = strndup(expr, data_len);
	if (!(*n)->data.value[0]) {
		pom_oom(data_len + 1);
		return POM_ERR;
	}

	if (!space)
		return POM_OK;

	len -= data_len;

	expr = space;
	while (*expr == ' ') {
		expr++;
		len--;
	}

	space = memchr(expr, ' ', len);
	if (!space) {
		pomlog(POMLOG_ERR "Incomplete filter expression");
		return POM_ERR;
	}

	data_len = space - expr;
	(*n)->data.op = strndup(expr, data_len);
	if (!(*n)->data.op) {
		pom_oom(data_len + 1);
		return POM_ERR;
	}
	
	expr = space;
	len -= data_len;

	while (*expr == ' ') {
		expr++;
		len--;
	}

	(*n)->data.value[1] = strndup(expr, len);
	if (!((*n)->data.value[1])) {
		pom_oom(len + 1);
		return POM_ERR;
	}
		
	return POM_OK;
}

void filter_raw_cleanup(struct filter_raw_node *fr) {

	if (!fr)
		return;

	if (fr->isbranch) {
		filter_raw_cleanup(fr->branch.a);
		filter_raw_cleanup(fr->branch.b);
		free(fr);
		return;
	}

	if (fr->data.value[0])
		free(fr->data.value[0]);
	if (fr->data.value[1])
		free(fr->data.value[1]);
	if (fr->data.op)
		free(fr->data.op);
	free(fr);

}

int filter_packet_compile(struct filter_node **filter, struct filter_raw_node *filter_raw) {


	if (!*filter) {
		*filter = malloc(sizeof(struct filter_node));
		if (!*filter) {
			pom_oom(sizeof(struct filter_node));
			return POM_ERR;
		}
		memset(*filter, 0, sizeof(struct filter_node));
	}

	struct filter_node *n = *filter;


	if (filter_raw->isbranch) {
		n->type[0] = filter_value_type_node;
		n->type[1] = filter_value_type_node;

		if (filter_packet_compile(&n->value[0].node, filter_raw->branch.a) != POM_OK)
			return POM_ERR;

		if (filter_packet_compile(&n->value[1].node, filter_raw->branch.b) != POM_OK)
			return POM_ERR;

		n->op = filter_raw->branch.op;

		return POM_OK;
	}


	int i;

	for (i = 0; i < 2; i++) {

		char *value = filter_raw->data.value[i];

		if (!value)
			continue;

		char *dot = strchr(value, '.');
		if (dot)
			*dot = 0;

		struct proto *proto = proto_get(value);
		if (!proto) {
			if (dot)
				*dot = '.';

			n->type[i] = filter_value_type_string;
			n->value[i].string = value;
			
			// Prevent the string from beeing freed
			filter_raw->data.value[i] = NULL;
			continue;
		}

		// We are parsing a proto

		n->type[i] = filter_value_type_proto;
		n->value[i].proto.proto = proto;

		if (dot) {
			dot++;

			int field_id;
			for (field_id = 0; proto->info->pkt_fields[field_id].name && strcmp(proto->info->pkt_fields[field_id].name, dot); field_id++);

			if (!proto->info->pkt_fields[field_id].name) {
				pomlog(POMLOG_ERR "Field %s doesn't exists for proto %s", dot, proto->info->name);
				return POM_ERR;
			}
			n->value[i].proto.field_id = field_id;
			n->value[i].proto.pt_reg = proto->info->pkt_fields[field_id].value_type;

		} else  {
			n->value[i].proto.field_id = -1;
			if (i == 1) {
				pomlog(POMLOG_ERR "Proto cannot be compared to anything");
				return POM_ERR;
			}
		}
	}

	if (filter_op_compile(n, filter_raw) != POM_OK)
		return POM_ERR;

	if (n->op == FILTER_OP_NOP)
		return POM_OK;

	if (n->type[0] == filter_value_type_proto && n->type[1] == filter_value_type_proto) {
		if (n->value[0].proto.pt_reg != n->value[1].proto.pt_reg) {
			pomlog(POMLOG_ERR "Cannot compare different types of ptype");
			return POM_ERR;
		}
	} else if (n->type[0] == filter_value_type_proto || n->type[1] == filter_value_type_proto) {

		int data = 0, value = 1;
		if (n->type[0] != filter_value_type_proto) {
			data = 1;
			value = 0;
		}

		if (n->type[value] != filter_value_type_string) {
			pomlog(POMLOG_ERR "Unhandled value of type %u when the other one is of type 'proto'", n->type[value]);
			return POM_ERR;
		}

		struct ptype *v = ptype_alloc_from_type(n->value[data].proto.pt_reg);
		if (!v)
			return POM_ERR;
		if (ptype_parse_val(v, n->value[value].string) != POM_OK)
			return POM_ERR;

		free(n->value[value].string);
		n->type[value] = filter_value_type_ptype;
		n->value[value].ptype = v;

	} else if (n->type[0] == filter_value_type_proto && n->value[0].proto.field_id == -1 && n->op != FILTER_OP_NOP) {
		pomlog(POMLOG_ERR "Proto cannot be compared to anything");
		return POM_ERR;
	}

	return POM_OK;
}

int filter_event_compile(struct filter_node **filter, struct event_reg *evt, struct filter_raw_node *filter_raw) {

	if (!*filter) {
		*filter = malloc(sizeof(struct filter_node));
		if (!*filter) {
			pom_oom(sizeof(struct filter_node));
			return POM_ERR;
		}
		memset(*filter, 0, sizeof(struct filter_node));
	}

	struct filter_node *n = *filter;
	int i;

	if (filter_raw->isbranch) {
		n->type[0] = filter_value_type_node;
		n->type[1] = filter_value_type_node;

		if (filter_event_compile(&n->value[0].node, evt, filter_raw->branch.a) != POM_OK)
			return POM_ERR;

		if (filter_event_compile(&n->value[1].node, evt, filter_raw->branch.b) != POM_OK)
			return POM_ERR;

		n->op = filter_raw->branch.op;

		return POM_OK;
	}



	struct event_reg_info *info = event_reg_get_info(evt);

	for (i = 0; i < 2; i++) {

		char *value = filter_raw->data.value[i];

		if (!value)
			return POM_OK;

		if (!strncmp(value, "data.", strlen("data."))) {
			value += strlen("data.");
			n->type[i] = filter_value_type_data;
			if (filter_data_compile(&n->value[i].data, info->data_reg, value) == POM_ERR)
				return POM_ERR;
		} else if (!strcmp(value, "time")) {
			n->type[i] = filter_value_type_evt_prop;
			n->value[i].integer = filter_evt_prop_time;
		} else if (!strcmp(value, "name")) {
			n->type[i] = filter_value_type_evt_prop;
			n->value[i].integer = filter_evt_prop_name;
		} else if (!strcmp(value, "source")) {
			n->type[i] = filter_value_type_evt_prop;
			n->value[i].integer = filter_evt_prop_source;
		} else {
			n->type[i] = filter_value_type_string;
			n->value[i].string = value;
			
			// Prevent the string from being freed
			filter_raw->data.value[i] = NULL;
		}
	}


	if (filter_op_compile(n, filter_raw) != POM_OK)
		return POM_ERR;


	// Do our specialized compilation
	if (n->type[0] == filter_value_type_evt_prop || n->type[1] == filter_value_type_evt_prop) {
		
		int prop = 0, value = 1;

		if (n->type[0] == filter_value_type_evt_prop && n->type[1] == filter_value_type_evt_prop) {
			pomlog(POMLOG_ERR "Cannot match even property against another one");
			return POM_ERR;
		}
		
		if (n->type[1] == filter_value_type_evt_prop) {
			prop = 1;
			value = 0;
		}

		if (n->value[prop].integer == filter_evt_prop_time) {
			// FIXME
			pomlog(POMLOG_WARN "Timestamp parsing not implemented yet");
			return POM_ERR;
		} else if (n->type[value] != filter_value_type_string) {

			pomlog(POMLOG_WARN "Unexpected combination of value type with even property");
			return POM_ERR;
		}

	}

	if (n->type[0] == filter_value_type_data && n->type[1] == filter_value_type_data) {
		if (n->value[0].data.pt_reg != n->value[1].data.pt_reg) {
			pomlog(POMLOG_ERR "Cannot compare different types of ptype");
			return POM_ERR;
		}
	} else if (n->type[0] == filter_value_type_data || n->type[1] == filter_value_type_data) {
		int data = 0, value = 1;
		if (n->type[0] != filter_value_type_data) {
			data = 1;
			value = 0;
		}

		if (n->type[value] == filter_value_type_string) {

			struct ptype *v = ptype_alloc_from_type(n->value[data].data.pt_reg);
			if (!v)
				return POM_ERR;
			if (ptype_parse_val(v, n->value[value].string) != POM_OK)
				return POM_ERR;

			free(n->value[value].string);
			n->type[value] = filter_value_type_ptype;
			n->value[value].ptype = v;
		} else if (n->type[value] != filter_value_type_ptype) {
			pomlog(POMLOG_ERR "Unhandled value type %u when the other one is of type 'data'", n->type[value]);
			return POM_ERR;
		}

	} else {
		pomlog(POMLOG_ERR "Unhandled combination of data types");
		return POM_ERR;
	}

	return POM_OK;
}

int filter_pload_compile(struct filter_node **filter, struct filter_raw_node *filter_raw) {

	if (!*filter) {
		*filter = malloc(sizeof(struct filter_node));
		if (!*filter) {
			pom_oom(sizeof(struct filter_node));
			return POM_ERR;
		}
		memset(*filter, 0, sizeof(struct filter_node));
	}

	struct filter_node *n = *filter;
	int i;

	if (filter_raw->isbranch) {
		n->type[0] = filter_value_type_node;
		n->type[1] = filter_value_type_node;

		if (filter_pload_compile(&n->value[0].node, filter_raw->branch.a) != POM_OK)
			return POM_ERR;

		if (filter_pload_compile(&n->value[1].node, filter_raw->branch.b) != POM_OK)
			return POM_ERR;

		n->op = filter_raw->branch.op;

		return POM_OK;
	}

	if (filter_op_compile(n, filter_raw) != POM_OK)
		return POM_ERR;

	for (i = 0; i < 2; i++) {
		
		char *value = filter_raw->data.value[i];

		if (!value)
			return POM_OK;

		if (!strncmp(value, "data.", strlen("data."))) {
			value += strlen("data.");
			n->type[i] = filter_value_type_pload_data;
			filter_data_raw_compile(&n->value[i].data_raw, value);

		} else if (!strncmp(value, "evt.", strlen("evt."))) {
			value += strlen("evt.");

			if (!strncmp(value, "data.", strlen("data."))) {
				value += strlen("data.");
				n->type[i] = filter_value_type_pload_evt_data;
				filter_data_raw_compile(&n->value[i].data_raw, value);
			} else if (!strcmp(value, "time")) {
				n->type[i] = filter_value_type_evt_prop;
				n->value[i].integer = filter_evt_prop_time;
			} else if (!strcmp(value, "name")) {
				n->type[i] = filter_value_type_evt_prop;
				n->value[i].integer = filter_evt_prop_name;
			} else if (!strcmp(value, "source")) {
				n->type[i] = filter_value_type_evt_prop;
				n->value[i].integer = filter_evt_prop_source;
			} else {
				pomlog(POMLOG_ERR "Invalid value for event filter");
			}
		} else {
			n->type[i] = filter_value_type_string;
			n->value[i].string = value;
			
			// Prevent the string from being freed
			filter_raw->data.value[i] = NULL;
		}
	}
	
	return POM_OK;
}


int filter_data_compile(struct filter_data *d, struct data_reg *dr, char *value) {

	char *key = strchr(value, '[');
	if (key) {
		*key = 0;
		key++;
		char *key_end = strchr(key, ']');
		if (!key_end) {
			pomlog(POMLOG_ERR "Missing ] for data key in filter for item %s", value);
			return POM_ERR;
		}
		*key_end = 0;
	}

	
	int i;
	for (i = 0; strcmp(dr->items[i].name, value) && i < dr->data_count; i ++);

	if (i >= dr->data_count) {
		pomlog(POMLOG_ERR "Data item %s not found", value);
		return POM_ERR;
	}

	struct data_item_reg *item = &dr->items[i];

	d->field_id = i;
	d->pt_reg = item->value_type;

	if (key) {
		if (!(item->flags & DATA_REG_FLAG_LIST)) {
			pomlog(POMLOG_ERR "Key provided for item %s while it's not a list", value);
			return POM_ERR;
		}
		d->key = strdup(key);
		if (!d->key) {
			pom_oom(strlen(key) + 1);
			return POM_ERR;
		}
	} else if (item->flags & DATA_REG_FLAG_LIST) {
		pomlog(POMLOG_ERR "Key not provided for filter value %s", value);
		return POM_ERR;
	}

	return POM_OK;
}

int filter_data_raw_compile(struct filter_data_raw *d, char *value) {

	char *key = strchr(value, '[');


	if (key) {
		*key = 0;
		key++;
		char *key_end = strchr(key, ']');
		if (!key_end) {
			pomlog(POMLOG_ERR "Missing ] for data key in filter for item %s", value);
			return POM_ERR;
		}
		d->key = strdup(key);
		if (!d->key) {
			pom_oom(strlen(key) + 1);
			return POM_ERR;
		}
	}

	d->field_name = strdup(value);
	if (!d->field_name) {
		pom_oom(strlen(value) + 1);
		return POM_ERR;
	}

	return POM_OK;
}

int filter_op_compile(struct filter_node *n, struct filter_raw_node *fr) {

	char *op = fr->data.op;

	n->op = FILTER_OP_NOP;
	if (!op) {
		return POM_OK;
	} else if (!strcmp(op, "eq") || !strcmp(op, "==") || !strcmp(op, "equals")) {
		n->op = FILTER_OP_EQ;
	} else if (!strcmp(op, "gt") || !strcmp(op, ">")) {
		n->op = FILTER_OP_GT;
	} else if (!strcmp(op, "ge") || !strcmp(op, ">=")) {
		n->op = FILTER_OP_GE;
	} else if (!strcmp(op, "lt") || !strcmp(op, "<")) {
		n->op = FILTER_OP_LT;
	} else if (!strcmp(op, "le") || !strcmp(op, "<=")) {
		n->op = FILTER_OP_LE;
	} else if (!strcmp(op, "neq") || !strcmp(op, "!=")) {
		n->op = FILTER_OP_NEQ;
	}

	if (n->op == FILTER_OP_NOP)
		return POM_ERR;

	return POM_OK;
}

int filter_node_data_match(struct filter_node *n, struct data *d) {

	int res = FILTER_MATCH_NO;

	struct ptype *v[2] = { 0 };

	int i;
	for (i = 0; i < 2; i++) {
		if (n->type[i] == filter_value_type_data) {
			int id = n->value[i].data.field_id;

			if (!data_is_set(d[id]))
				continue;

			if (n->value[i].data.key) {
				struct data_item *itm;
				for (itm = d[id].items; itm && strcmp(itm->key, n->value[i].data.key); itm = itm->next);
				if (!itm) {
					res = FILTER_MATCH_NO;
					break;
				}
				v[i] = itm->value;
			} else {
				v[i] = d[id].value;
			}

		} else if (n->type[i] == filter_value_type_ptype) {
			v[i] = n->value[i].ptype;
		} else if (n->type[i] != filter_value_type_none) {
			pomlog(POMLOG_WARN "Unexpected filter value");
			return POM_ERR;
		}

	}

	if (n->op == FILTER_OP_NOP) {
		if (v[0] || v[1]) { // Only v[0] should be set but for safety we match both
			res = FILTER_MATCH_YES;
		}
	} else {

		if (!v[0] || !v[1]) {
			pomlog(POMLOG_ERR "Missing value for comparison");
			return POM_ERR;
		}

		res = ptype_compare_val(n->op, v[0], v[1]);
	}

	return res;
}

int filter_packet_match(struct filter_node *n, struct proto_process_stack *stack) {

	int res = FILTER_MATCH_NO;

	if (n->type[0] == filter_value_type_node && n->type[1] == filter_value_type_node) {
		int res_a, res_b;

		res_a = filter_packet_match(n->value[0].node, stack);
		if (res_a == POM_ERR)
			return POM_ERR;

		res_b = filter_packet_match(n->value[1].node, stack);
		if (res_b == POM_ERR)
			return POM_ERR;


		if (n->op == FILTER_OP_AND) {
			res = res_a && res_b;
		} else if (n->op == FILTER_OP_OR) {
			res = res_a || res_b;
		} else {
			pomlog(POMLOG_ERR "Invalid operation for nodes");
			return POM_ERR;
		}

		if (n->not)
			return !res;

		return res;
	}


	// Fetch values
	struct ptype *values[2] = { 0 };

	int i;
	for (i = 0; i < 2; i++) {

		if (n->type[i] == filter_value_type_proto) {

			unsigned int j;
			for (j = CORE_PROTO_STACK_START; j <= CORE_PROTO_STACK_MAX && stack[j].proto && stack[j].proto != n->value[i].proto.proto; j++);

			if (!stack[j].proto)
				break;
			
			if (n->value[i].proto.field_id == -1) {
				// Set value to whatever
				values[i] = (void*)-1;
				break;
			}

			values[i] = stack[j].pkt_info->fields_value[n->value[i].proto.field_id];
		} else if (n->type[i] == filter_value_type_ptype) {
			values[i] = n->value[i].ptype;
		}
	}


	if (n->op == FILTER_OP_NOP) {
		if (values[0] || values[1]) { // Only v[0] should be set but for safety we match both
			res = FILTER_MATCH_YES;
		}
	} else {

		if (values[0] && values[1])
			res = ptype_compare_val(n->op, values[0], values[1]);

	}

	if (n->not)
		return !res;

	return res;
}

int filter_event_match(struct filter_node *n, struct event *evt) {

	int res = FILTER_MATCH_NO;

	if (n->type[0] == filter_value_type_node && n->type[1] == filter_value_type_node) {
		int res_a, res_b;

		res_a = filter_event_match(n->value[0].node, evt);
		if (res_a == POM_ERR)
			return POM_ERR;

		res_b = filter_event_match(n->value[1].node, evt);
		if (res_b == POM_ERR)
			return POM_ERR;


		if (n->op == FILTER_OP_AND) {
			res = res_a && res_b;
		} else if (n->op == FILTER_OP_OR) {
			res = res_a || res_b;
		} else {
			pomlog(POMLOG_ERR "Invalid operation for nodes");
			return POM_ERR;
		}

		if (n->not)
			return !res;

		return res;
	}

	if (n->type[0] == filter_value_type_evt_prop || n->type[1] == filter_value_type_evt_prop) {
		pomlog(POMLOG_WARN "Event property matching not implemented yet");
		return POM_ERR;
	} else if (n->type[0] == filter_value_type_data || n->type[1] == filter_value_type_data) {
			struct data *d = event_get_data(evt);
			res = filter_node_data_match(n, d);
			if (res == POM_ERR)
				return POM_ERR;

	} else {
		pomlog(POMLOG_ERR "Unhandled combination of data types");
		return POM_ERR;
	}


	if (n->not)
		return !res;

	return res;
}

int filter_pload_match(struct filter_node *n, struct pload *p) {

	int res = FILTER_MATCH_NO;

	if (n->type[0] == filter_value_type_node && n->type[1] == filter_value_type_node) {

		int res_a, res_b;

		res_a = filter_pload_match(n->value[0].node, p);
		if (res_a == POM_ERR)
			return POM_ERR;

		res_b = filter_pload_match(n->value[1].node, p);
		if (res_b == POM_ERR)
			return POM_ERR;

		if (n->op == FILTER_OP_AND) {
			res = res_a && res_b;
		} else if (n->op == FILTER_OP_OR) {
			res = res_a || res_b;
		} else {
			pomlog(POMLOG_ERR "Invalid operaiton for nodes");
			return POM_ERR;
		}

		if (n->not)
			return !res;

		return res;

	}

	struct ptype *values[2] = { 0 };
	int i;

	// Get the value for pload_data or pload_evt_data
	for (i = 0; i < 2; i++) {

		if (n->type[i] == filter_value_type_pload_data || n->type[i] == filter_value_type_pload_evt_data) {

			struct filter_data_raw *data_raw = &n->value[i].data_raw;
			struct data *data = NULL;
			struct data_reg *dr = NULL;
			
			if (n->type[i] == filter_value_type_pload_data) {
				data = pload_get_data(p);
				dr = pload_get_data_reg(p);
			} else {
				struct event *evt = pload_get_related_event(p);
				data = event_get_data(evt);

				struct event_reg_info *info = event_get_info(evt);
				dr = info->data_reg;
			}

			if (!data || !dr)
				continue;

			int j;
			for (j = 0; j < dr->data_count && strcmp(dr->items[j].name, data_raw->field_name); j++);

			if (j >= dr->data_count)
				continue;

			struct data_item_reg *item = &dr->items[j];
			if (data_raw->key) {
				if (!(item->flags & DATA_REG_FLAG_LIST))
					// Specific item isn't a list
					continue;

				// Find the right entry
				
				struct data_item *itm;
				for (itm = data[j].items; itm && strcmp(itm->key, n->value[i].data.key); itm = itm->next);
				if (!itm)
					continue;
				values[i] = itm->value;

			} else if (item->flags & DATA_REG_FLAG_LIST) {
				// Key not provided
				continue;
			} else {
				values[i] = data[j].value;
			}
		}
	}

	if (n->op == FILTER_OP_NOP) {
		if (values[0] || values[1]) { // Only v[0] should be set but for safety we match both
			res = FILTER_MATCH_YES;
		}
	} else {

		for (i = 0; i < 2; i++) {
			if (n->type[i] == filter_value_type_string) {
				// Try to parse this value like the other value
				int rev = (i == 0 ? 1 : 0);
				if (!values[rev])
					break;
				values[i] = ptype_alloc_from(values[rev]);
				if (!values[i]) {
					res = POM_ERR;
					goto err;
				}

				if (ptype_parse_val(values[i], n->value[i].string) != POM_OK) {
					pomlog(POMLOG_ERR "Error while parsing filter value '%s'\n", n->value[i].string);
					res = POM_ERR;
					goto err;
				}
				break;
			}
		}

		if (values[0] && values[1])
			res = ptype_compare_val(n->op, values[0], values[1]);
	}


	if (n->not)
		return !res;

err:
	for (i = 0; i < 2; i++) {
		if (values[i] && (n->type[i] != filter_value_type_pload_data && n->type[i] != filter_value_type_pload_evt_data))
			ptype_cleanup(values[i]);
	}

	return res;
}

int filter_packet(char *filter_expr, struct filter_node **filter) {

	struct filter_raw_node *fr = NULL;

	if (*filter) {
		filter_cleanup(*filter);
		*filter = NULL;
	}

	if (filter_raw_parse(filter_expr, strlen(filter_expr), &fr) != POM_OK) {
		filter_raw_cleanup(fr);
		return POM_ERR;
	}

	if (!fr)
		return POM_OK;

	if (filter_packet_compile(filter, fr) != POM_OK) {
		filter_raw_cleanup(fr);
		return POM_ERR;
	}

	filter_raw_cleanup(fr);
	return POM_OK;
}

int filter_event(char *filter_expr, struct event_reg *evt_reg, struct filter_node **filter) {

	struct filter_raw_node *fr = NULL;

	if (*filter) {
		filter_cleanup(*filter);
		*filter = NULL;
	}

	if (filter_raw_parse(filter_expr, strlen(filter_expr), &fr) != POM_OK) {
		filter_raw_cleanup(fr);
		return POM_ERR;
	}

	if (!fr)
		return POM_OK;

	if (filter_event_compile(filter, evt_reg, fr) != POM_OK) {
		filter_raw_cleanup(fr);
		return POM_ERR;
	}

	filter_raw_cleanup(fr);
	return POM_OK;
}

int filter_pload(char *filter_expr, struct filter_node **filter) {

	struct filter_raw_node *fr = NULL;

	if (*filter) {
		filter_cleanup(*filter);
		*filter = NULL;
	}

	if (filter_raw_parse(filter_expr, strlen(filter_expr), &fr) != POM_OK) {
		filter_raw_cleanup(fr);
		return POM_ERR;
	}

	if (!fr)
		return POM_OK;

	if (filter_pload_compile(filter, fr) != POM_OK) {
		filter_raw_cleanup(fr);
		return POM_ERR;
	}

	filter_raw_cleanup(fr);
	return POM_OK;

}

void filter_cleanup(struct filter_node *n) {

	if (!n)
		return;

	int i;
	for (i = 0; i < 2; i++) {
		if (n->type[i] == filter_value_type_node) {
			filter_cleanup(n->value[i].node);
		} else if (n->type[i] == filter_value_type_data) {
			if (n->value[i].data.key)
				free(n->value[i].data.key);
		} else if (n->type[i] == filter_value_type_ptype) {
			if (n->value[i].ptype)
				ptype_cleanup(n->value[i].ptype);
		} else if (n->type[i] == filter_value_type_string) {
			if (n->value[i].string)
				free(n->value[i].string);
		} else if (n->type[i] == filter_value_type_pload_data || n->type[i] == filter_value_type_pload_evt_data) {
			if (n->value[i].data_raw.field_name)
				free(n->value[i].data_raw.field_name);
			if (n->value[i].data_raw.key)
				free(n->value[i].data_raw.key);
		}
	}
	
	free(n);

}
