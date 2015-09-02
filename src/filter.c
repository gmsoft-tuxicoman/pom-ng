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


#include "filter.h"
#include "core.h"
#include "proto.h"
#include "ptype.h"

#include <pom-ng/ptype_string.h>

static struct ptype_reg *ptype_string = NULL, *ptype_bool = NULL, *ptype_uint8 = NULL, *ptype_uint16 = NULL, *ptype_uint32 = NULL, *ptype_uint64 = NULL;
static int addon_ptype_initialized = 0;

//
// Init and cleanup functions
//
static int filter_ptype_init() {

	if (addon_ptype_initialized)
		return POM_OK;

	ptype_string = ptype_get_type("string");
	ptype_bool = ptype_get_type("bool");
	ptype_uint8 = ptype_get_type("uint8");
	ptype_uint16 = ptype_get_type("uint16");
	ptype_uint32 = ptype_get_type("uint32");
	ptype_uint64 = ptype_get_type("uint64");

	addon_ptype_initialized = 1;

	if (!ptype_string || !ptype_bool || !ptype_uint8 || !ptype_uint16 || !ptype_uint32 || !ptype_uint64) {
		pomlog(POMLOG_ERR "Failed to initialize addon ptypes.");
		return POM_ERR;
	}

	return POM_OK;
}

struct filter *filter_alloc(int (*prop_compile) (struct filter *f, char *prop_str, struct filter_value *v),
				void *priv,
				int (*prop_get_val) (struct filter_value *inval, struct filter_value *outval, void *obj),
				void (*prop_cleanup) (void *prop)
				) {

	struct filter *f = malloc(sizeof(struct filter));
	if (!f) {
		pom_oom(sizeof(struct filter));
		return NULL;
	}
	memset(f, 0, sizeof(struct filter));

	f->prop_compile = prop_compile;
	f->priv = priv;
	f->prop_get_val = prop_get_val;
	f->prop_cleanup = prop_cleanup;

	return f;
}

void filter_node_cleanup(struct filter *f, struct filter_node *n) {

	if (!n)
		return;

	int i;
	for (i = 0; i < 2; i++) {
		if (n->value[i].type == filter_value_type_node) {
			filter_node_cleanup(f, n->value[i].val.node);
		} else if (n->value[i].type == filter_value_type_prop) {
			if (f->prop_cleanup && n->value[i].val.prop.priv)
				f->prop_cleanup(n->value[i].val.prop.priv);
		} else if (n->value[i].type == filter_value_type_string) {
			free(n->value[i].val.string);
		} else if (n->value[i].type == filter_value_type_ptype) {
			ptype_cleanup(n->value[i].val.ptype);
		}
	}

	free(n);
}


void filter_cleanup(struct filter *f) {

	filter_node_cleanup(f, f->n);
	free(f);
}

//
// Helper functions
//

int filter_ptype_is_integer(struct ptype_reg *reg) {

	filter_ptype_init();

	return (reg == ptype_bool || reg == ptype_uint8 || reg == ptype_uint16 || reg == ptype_uint32 || reg == ptype_uint64);
}

int filter_ptype_is_string(struct ptype_reg *reg) {

	filter_ptype_init();

	return (reg == ptype_string);

}

uint64_t filter_ptype_int_get(struct ptype* pt) {

	if (pt->type == ptype_bool) {
		return *PTYPE_BOOL_GETVAL(pt);
	} else if (pt->type == ptype_uint8) {
		return *PTYPE_UINT8_GETVAL(pt);
	} else if (pt->type == ptype_uint16) {
		return *PTYPE_UINT16_GETVAL(pt);
	} else if (pt->type == ptype_uint32) {
		return *PTYPE_UINT32_GETVAL(pt);
	} else if (pt->type == ptype_uint64) {
		return *PTYPE_UINT64_GETVAL(pt);
	}

	pomlog(POMLOG_ERR "Error, ptype is not an integer");
	return POM_ERR;
}

void filter_ptype_to_value(struct filter_value *v, struct ptype *pt) {
	if (filter_ptype_is_integer(pt->type)) {
		v->type = filter_value_type_int;
		v->val.integer = filter_ptype_int_get(pt);
	} else if (filter_ptype_is_string(pt->type)) {
		v->type = filter_value_type_string;
		v->val.string = PTYPE_STRING_GETVAL(pt);
	} else {
		v->type = filter_value_type_ptype;
		v->val.ptype = pt;
	}
}

//
// Compilation functions
//

// Parse a token into a node value (i.e. "ipv4", "some string", "10.2.4.6")
int filter_parse_expr_token(struct filter *f, char *tok, unsigned int len, struct filter_node *n, int tok_idx) {


	// Check if it's a string
	if (*tok == '"') {
		// It's a string
		if (tok[len - 1] != '"' || len < 2) {
			pomlog(POMLOG_ERR "Unterminated double quoted string");
			return POM_ERR;
		}
		n->value[tok_idx].type = filter_value_type_string;
		n->value[tok_idx].val.string = strndup(tok + 1, len - 2);
		if (!n->value[tok_idx].val.string) {
			pom_oom(len + 1);
			return POM_ERR;
		}

		len -= 2;

		char *str = n->value[tok_idx].val.string;
		char *dq = str + 1;
		len--;
		while ( (dq = memchr(dq, '"', len)) ) {
			// The dquote must be escaped at this point
			memmove(dq - 1, dq, len);
			len--;
		}

		return POM_OK;
	} else if (!strncasecmp(tok, "true", len) || !strncasecmp(tok, "yes", len)) {
		n->value[tok_idx].type = filter_value_type_int;
		n->value[tok_idx].val.integer = 1;
	} else if (!strncasecmp(tok, "false", len) || !strncasecmp(tok, "no", len)) {
		n->value[tok_idx].type = filter_value_type_int;
		n->value[tok_idx].val.integer = 0;
	}

	// Check if it's a special ptype
	char *special[] = {
		"ipv4",
		"ipv6",
		"mac"
	};
	int i;
	for (i = 0; i < 3; i ++) {
		struct ptype *val = ptype_alloc(special[i]);
		if (!val)
			return POM_ERR;

		if (ptype_parse_val(val, tok) != POM_OK) {
			ptype_cleanup(val);
		} else {
			n->value[tok_idx].type = filter_value_type_ptype;
			n->value[tok_idx].val.ptype = val;
			return POM_OK;
		}
	}

	// Check if it's an integer
	int is_int = 1;
	for (i = 0; i < len; i++) {
		if (tok[i] < '0' || tok[i] > '9') {
			is_int = 0;
			break;
		}
	}

	if (is_int) {
		n->value[tok_idx].type = filter_value_type_int;
		if (sscanf(tok, "%"SCNu64, &n->value[tok_idx].val.integer) != 1) {
			pomlog(POMLOG_ERR "Error while parsing integer");
			return POM_ERR;
		}
		return POM_OK;
	}

	// It's a property then
	
	char *prop_str = strndup(tok, len);
	if (!prop_str) {
		pom_oom(len + 1);
		return POM_ERR;
	}

	int res = f->prop_compile(f, prop_str, &n->value[tok_idx]);
	free(prop_str);

	return res;
}

// Parse an operation

int filter_op_compile(struct filter_node *n, char *op) {

	n->op = FILTER_OP_NOP;
	if (!op) {
		return POM_OK;
	} else if (!strncmp(op, "eq", 2) || !strncmp(op, "==", 2) || !strncmp(op, "equals", strlen("equals"))) {
		n->op = FILTER_OP_EQ;
	} else if (!strncmp(op, "gt", 2) || !strncmp(op, ">", 1)) {
		n->op = FILTER_OP_GT;
	} else if (!strncmp(op, "ge", 2) || !strncmp(op, ">=", 2)) {
		n->op = FILTER_OP_GE;
	} else if (!strncmp(op, "lt", 2) || !strncmp(op, "<", 1)) {
		n->op = FILTER_OP_LT;
	} else if (!strncmp(op, "le", 2) || !strncmp(op, "<=", 2)) {
		n->op = FILTER_OP_LE;
	} else if (!strncmp(op, "neq", 3) || !strncmp(op, "!=", 2)) {
		n->op = FILTER_OP_NEQ;
	}

	if (n->op == FILTER_OP_NOP)
		return POM_ERR;

	return POM_OK;
}

// Parse a block of 2 tokens and a operation (i.e. : "icmp.code == 4")

int filter_parse_expr_block(struct filter *f, char *expr, unsigned int len, struct filter_node **n) {

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
		int res = filter_parse_expr(f, expr, len, n);
		if (inv)
			(*n)->not = 1;
		return res;
	}

	char *end = NULL;
	if (expr[0] == '"') {
		char *tmp = expr + 1;
		size_t tmp_len = len - 1;
		while ((end = memchr(tmp, '"', tmp_len))) {
			if (*(end - 1) != '\\')
				break;

			tmp_len -= end - tmp + 1;
			tmp = end + 1;
		}

		if (!end && expr[len - 1] != '"') {
			pomlog(POMLOG_ERR "Unterminated string betweend double quote");
			return POM_ERR;
		}

		end++;
	} else {
		end = memchr(expr, ' ', len);
	}

	size_t data_len = len;

	if (end) {
		data_len = end - expr;
	}

	if (filter_parse_expr_token(f, expr, data_len, *n, 0) != POM_OK)
		return POM_ERR;


	len -= data_len;

	expr = end;
	while (*expr == ' ' && len >= 1) {
		expr++;
		len--;
	}

	if (!len)
		return POM_OK;

	// Check for the end of the operation
	end = memchr(expr, ' ', len);
	if (!end) {
		pomlog(POMLOG_ERR "Incomplete filter expression");
		return POM_ERR;
	}

	data_len = end - expr;
	if (filter_op_compile(*n, expr) != POM_OK)
		return POM_ERR;

	expr = end;
	len -= data_len;

	while (*expr == ' ' && len >= 1) {
		expr++;
		len--;
	}

	if (filter_parse_expr_token(f, expr, len, *n, 1) != POM_OK)
		return POM_ERR;

	return POM_OK;
}

// Parse the whole filter expression

int filter_parse_expr(struct filter *f, char *expr, unsigned int len, struct filter_node **n) {

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

		*n = malloc(sizeof(struct filter_node));
		if (!*n) {
			pom_oom(sizeof(struct filter_node));
			return POM_ERR;
		}
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

			(*n)->op = branch_op;

			(*n)->value[0].type = filter_value_type_node;
			(*n)->value[1].type = filter_value_type_node;

			if (filter_parse_expr(f, expr, i - 1, &(*n)->value[0].val.node) != POM_OK || filter_parse_expr(f, expr + i + 2, len - i - 2, &(*n)->value[1].val.node) != POM_OK)
				return POM_ERR;

			if (!(*n)->value[0].val.node || !(*n)->value[1].val.node) {
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
	return filter_parse_expr_block(f, expr, len, n);
}

// Validate a compile filter for inconsitencies (e.g. matching a string with an integer)

int filter_validate(struct filter_node *n) {

	if (n->op == FILTER_OP_NOP)
		return POM_OK;

	enum filter_value_type type[2] = { 0 };

	int i;
	for (i = 0; i < 2; i++) {
		switch (n->value[i].type) {
			case filter_value_type_node:
				if (filter_validate(n->value[i].val.node) != POM_OK)
					return POM_ERR;
				break;
			case filter_value_type_unknown:
			case filter_value_type_string:
			case filter_value_type_int:
			case filter_value_type_ptype:
				type[i] = n->value[i].type;
				break;
			case filter_value_type_prop:
				type[i] = n->value[i].val.prop.out_type;
				break;
		}
	}

	if (type[0] == filter_value_type_unknown || type[1] == filter_value_type_unknown)
		return POM_OK;

	if (type[0] != type[1]) {
		pomlog(POMLOG_ERR "Trying to match incompatible types");
		return POM_ERR;
	}

	if (type[0] == filter_value_type_string) {
		if (n->op != FILTER_OP_EQ && n->op != FILTER_OP_NEQ) {
			pomlog(POMLOG_ERR "Invalid operation for string or pointer");
			return POM_ERR;
		}
	}


	return POM_OK;
}

int filter_compile(char *filter_expr, struct filter *f) {

	if (f->n) {
		pomlog(POMLOG_ERR "Filter already compiled");
		return POM_ERR;
	}


	if (filter_parse_expr(f, filter_expr, strlen(filter_expr), &f->n) != POM_OK)
		return POM_ERR;

	if (filter_validate(f->n) != POM_OK) {
		return POM_ERR;
	}

	return POM_OK;
}

//
// Matching funtions
//

int filter_match_node(struct filter *f, struct filter_node *n, void *obj) {

	int res = FILTER_MATCH_NO;

	struct filter_value value[2] = { { 0 } };
	value[0].type = n->value[0].type;
	value[1].type = n->value[1].type;


	int i;

	// Fetch both values
	for (i = 0; i < 2; i++) {
		switch (n->value[i].type) {
			case filter_value_type_unknown:
				// Nothing to do
				break;
			case filter_value_type_prop: {
				value[i].type = filter_value_type_unknown;
				if (f->prop_get_val(&n->value[i], &value[i], obj) != POM_OK)
					return POM_ERR;
				break;
			}
			case filter_value_type_string:
				value[i].val.string = n->value[i].val.string;
				break;
			case filter_value_type_int:
				value[i].val.integer = n->value[i].val.integer;
				break;
			case filter_value_type_node:
				value[i].val.node = n->value[i].val.node;
				break;
			case filter_value_type_ptype:
				value[i].val.ptype = n->value[i].val.ptype;
				break;
		}
	}


	if (n->op != FILTER_OP_NOP) {
		if (value[0].type == filter_value_type_unknown || value[1].type == filter_value_type_unknown)
			return FILTER_MATCH_NO;

		if (value[0].type != value[1].type) {
			pomlog(POMLOG_DEBUG "Cannot compare different values");
			return FILTER_MATCH_NO;
		}
	}

	// Match the values
	switch (value[0].type) {
		case filter_value_type_unknown:
			res = FILTER_MATCH_NO;
			break;

		case filter_value_type_prop:
			pomlog(POMLOG_ERR "Internal error, invalid value type");
			res = POM_ERR;
			break;

		case filter_value_type_string:
			if (n->op == FILTER_OP_NOP) {
				res = value[0].val.string || value[1].val.string;
			} else if (n->op == FILTER_OP_EQ) {
				res = !strcmp(value[0].val.string, value[1].val.string);
			} else if (n->op == FILTER_OP_NEQ) {
				res = strcmp(value[0].val.string, value[1].val.string);
			} else {
				res = POM_ERR;
			}
			break;

		case filter_value_type_int:
			switch (n->op) {
				case FILTER_OP_NOP:
					res = FILTER_MATCH_YES;
					break;
				case FILTER_OP_EQ:
					res = (value[0].val.integer == value[1].val.integer);
					break;
				case FILTER_OP_GT:
					res = (value[0].val.integer > value[1].val.integer);
					break;
				case FILTER_OP_GE:
					res = (value[0].val.integer >= value[1].val.integer);
					break;
				case FILTER_OP_LT:
					res = (value[0].val.integer < value[1].val.integer);
					break;
				case FILTER_OP_LE:
					res = (value[0].val.integer <= value[1].val.integer);
					break;
				case FILTER_OP_NEQ:
					res = (value[0].val.integer != value[1].val.integer);
					break;
			}
			break;

		case filter_value_type_node: {
			res = filter_match_node(f, value[0].val.node, obj);
			if (res == POM_ERR)
				return POM_ERR;

			if (n->op == FILTER_OP_AND && !res) {
				// First value is false so expression will be false
				break;
			} else if (n->op == FILTER_OP_OR && res) {
				// First value is true so expression will be true
				break;
			} else {
				res = filter_match_node(f, value[1].val.node, obj);

				if (res == POM_ERR)
					return POM_ERR;

				// If it's AND, first value was true, the second one sets the whole expression value
				// If it's OR, first was false, the second one sets the whole expression value

			}
			break;
		}

		case filter_value_type_ptype:
			if (n->op == FILTER_OP_NOP) {
				res = value[0].val.ptype || value[1].val.ptype;
			} else {
				res = ptype_compare_val(n->op, value[0].val.ptype, value[1].val.ptype);
			}
			break;

	}

	if (n->not)
		return !res;

	return res;
}

int filter_match(struct filter *f, void *obj) {

	return filter_match_node(f, f->n, obj);

}

