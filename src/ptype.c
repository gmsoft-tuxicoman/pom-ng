/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2010-2012 Guy Martin <gmsoft@tuxicoman.be>
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


#include <pom-ng/ptype.h>

#include "ptype.h"
#include "mod.h"
#include "jhash.h"

#include <pthread.h>
#include <string.h>

#define INITVAL 0x69db45f0 // random value for hashing

static struct ptype_reg *ptype_reg_head = NULL;

int ptype_register(struct ptype_reg_info *reg_info, struct mod_reg *mod) {

	pomlog(POMLOG_DEBUG "Registering ptype %s", reg_info->name);

	if (reg_info->api_ver != PTYPE_API_VER) {
		pomlog(POMLOG_ERR "API version of ptype %s does not match : expected %u got %u", reg_info->name, PTYPE_API_VER, reg_info->api_ver);
		return POM_ERR;
	}

	struct ptype_reg *reg = malloc(sizeof(struct ptype_reg));
	if (!reg) {
		pom_oom(sizeof(struct ptype_reg));
		return POM_ERR;
	}
	memset(reg, 0, sizeof(struct ptype_reg));

	struct ptype_reg *tmp;
	for (tmp = ptype_reg_head; tmp && strcmp(tmp->info->name, reg_info->name); tmp = tmp->next);
	if (tmp) {
		pomlog(POMLOG_ERR "Ptype %s already registered", reg_info->name);
		free(reg);
		return POM_ERR;
	}

	reg->info = reg_info;
	reg->module = mod;

	mod_refcount_inc(mod);

	reg->next = ptype_reg_head;
	ptype_reg_head = reg;
	if (reg->next)
		reg->next->prev = reg;

	return POM_OK;
}

struct ptype *ptype_alloc(const char* type) {

	return ptype_alloc_unit(type, NULL);
}

struct ptype* ptype_alloc_unit(const char* type, char* unit) {

	struct ptype_reg *reg;
	for (reg = ptype_reg_head; reg && strcmp(reg->info->name, type); reg = reg->next);

	if (!reg) {
		// This should only be needed at startup
		pomlog(POMLOG_DEBUG "Ptype of type %s not found, trying to load module", type);
		char ptype_mod_name[64] = { 0 };
		strcat(ptype_mod_name, "ptype_");
		strncat(ptype_mod_name, type, sizeof(ptype_mod_name) - 1 - strlen(ptype_mod_name));
		if (!mod_load(ptype_mod_name)) {
			pomlog(POMLOG_ERR "Ptype of type %s not found", type);
			return NULL;
		}
		for (reg = ptype_reg_head; reg && strcmp(reg->info->name, type); reg = reg->next);
		if (!reg) {
			pomlog(POMLOG_ERR "Ptype of type %s not found even after loading module", type);
			return NULL;
		}
	}
	
	struct ptype *ret = malloc(sizeof(struct ptype));
	if (!ret) {
		pom_oom(sizeof(struct ptype));
		return NULL;
	}

	memset(ret, 0, sizeof(struct ptype));
	ret->type = reg;
	if (reg->info->alloc) {
		if (reg->info->alloc(ret) != POM_OK) {
			pomlog(POMLOG_ERR "Error while allocating ptype %s", type);
			free(ret);
			return NULL;
		}
	}

	if (unit) {
		ret->unit = strdup(unit);
		if (!ret->unit)
			pom_oom(strlen(unit));
	}

	return ret;
}

struct ptype* ptype_alloc_from(struct ptype *pt) {

	struct ptype *res = ptype_alloc_from_type(pt->type);

	if (!res)
		return NULL;

	res->flags = pt->flags;
	
	if (pt->type->info->copy) {
		if (pt->type->info->copy(res, pt) != POM_OK) {
			pomlog(POMLOG_ERR "Ptype copy failed while copying from another ptype");
			goto err;
		}
	}

	if (pt->unit) {
		res->unit = strdup(pt->unit);
		if (!res->unit) {
			pom_oom(strlen(pt->unit));
			goto err;
		}
	}

	return res;

err:

	if (res->type->info->cleanup)
		res->type->info->cleanup(res);
	
	if (pt->unit)
		free(pt->unit);

	free(res);

	return NULL;
}

struct ptype *ptype_alloc_from_type(struct ptype_reg *type) {

	struct ptype *res = malloc(sizeof(struct ptype));
	if (!res) {
		pom_oom(sizeof(struct ptype));
		return NULL;
	}

	memset(res, 0, sizeof(struct ptype));
	res->type = type;


	if (type->info->alloc) {
		if (type->info->alloc(res) != POM_OK) {
			pomlog(POMLOG_ERR "Ptype allocation failed");
			free(res);
			return NULL;
		}
	}

	return res;

}

int ptype_parse_val(struct ptype *pt, char *val) {

	int res = POM_ERR;
	if (pt->type->info->parse_val)
		res = pt->type->info->parse_val(pt, val);
	
	return res;
}

int ptype_print_val(struct ptype *pt, char *val, size_t size, char *format) {
	
	return pt->type->info->print_val(pt, val, size, format);
}

char *ptype_print_val_alloc(struct ptype *pt, char *format) {

	char *res = NULL;

	int size, new_size = DEFAULT_PRINT_VAL_ALLOC_BUFF;
	do {
		size = new_size;
		res = realloc(res, size + 1);
		if (!res) {
			pom_oom(size + 1);
			return NULL;
		}
		new_size = ptype_print_val(pt, res, size, format);
		new_size = (new_size < 1) ? new_size * 2 : new_size + 1;
	} while (new_size > size);

	return res;
}

int ptype_get_op(struct ptype *pt, char *op) {

	int o = 0;

	if (!strcmp(op, "eq") || !strcmp(op, "==") || !strcmp(op, "equals"))
		o = PTYPE_OP_EQ;
	else if (!strcmp(op, "gt") || !strcmp(op, ">")) 
		o = PTYPE_OP_GT;
	else if (!strcmp(op, "ge") || !strcmp(op, ">=")) 
		o = PTYPE_OP_GE;
	else if (!strcmp(op, "lt") || !strcmp(op, "<")) 
		o = PTYPE_OP_LT;
	else if (!strcmp(op, "le") || !strcmp(op, "<=")) 
		o = PTYPE_OP_LE;
	else if (!strcmp(op, "neq") || !strcmp(op, "!="))
		o = PTYPE_OP_NEQ;

	if (pt->type->info->ops & o)
		return o;

	pomlog(POMLOG_ERR "Invalid operation %s for ptype %s", op, pt->type->info->name);
	return POM_ERR;
}

char *ptype_get_op_sign(int op) {
	switch (op) {
		case PTYPE_OP_EQ:
			return "==";
		case PTYPE_OP_GT:
			return ">";
		case PTYPE_OP_GE:
			return ">=";
		case PTYPE_OP_LT:
			return "<";
		case PTYPE_OP_LE:
			return "<=";
		case PTYPE_OP_NEQ:
			return "!=";

	}
	return NULL;
}

char *ptype_get_op_name(int op) {
	switch (op) {
		case PTYPE_OP_EQ:
			return "eq";
		case PTYPE_OP_GT:
			return "gt";
		case PTYPE_OP_GE:
			return "ge";
		case PTYPE_OP_LT:
			return "lt";
		case PTYPE_OP_LE:
			return "le";
		case PTYPE_OP_NEQ:
			return "neq";

	}
	return NULL;
}

int ptype_compare_val(int op, struct ptype *a, struct ptype *b) {

	int res = 0;

	if (!a || !b || a->type != b->type)
		return 0;

	if (!(a->type->info->ops & op)) {
		pomlog(POMLOG_ERR "Invalid operation %s for ptype %s", ptype_get_op_sign(op), a->type->info->name);
		return 0;
	}

	if (op == PTYPE_OP_NEQ)
		res = !(a->type->info->compare_val(PTYPE_OP_EQ, a->value, b->value));
	else
		res = (a->type->info->compare_val(op, a->value, b->value));
	return res;
}

int ptype_serialize(struct ptype *pt, char *val, size_t size) {

	return pt->type->info->serialize(pt, val, size);
}

int ptype_unserialize(struct ptype *pt, char *val) {

	return pt->type->info->unserialize(pt, val);
}


int ptype_copy(struct ptype *dst, struct ptype *src) {

	if (dst->type != src->type) {
		pomlog(POMLOG_ERR "Error, trying to copy ptypes of different type");
		return POM_ERR;
	}

	return  src->type->info->copy(dst, src);
}

int ptype_cleanup(struct ptype* pt) {

	if (!pt)
		return POM_ERR;

	if (pt->type->info->cleanup)
		pt->type->info->cleanup(pt);

	if (pt->unit)
		free(pt->unit);
	
	free(pt);

	return POM_OK;
}

int ptype_unregister(char *name) {

	struct ptype_reg *reg;

	for (reg = ptype_reg_head; reg && strcmp(reg->info->name, name); reg = reg->next);
	if (!reg) {
		pomlog(POMLOG_WARN "Ptype %s is not registered, cannot unregister it.", name);
		return POM_OK; // Do not return an error so module unloading proceeds
	}

	if (reg->prev)
		reg->prev->next = reg->next;
	else
		ptype_reg_head = reg->next;
	
	if (reg->next)
		reg->next->prev = reg->prev;

	reg->next = NULL;
	reg->prev = NULL;

	mod_refcount_dec(reg->module);

	free(reg);

	return POM_OK;
}

char *ptype_get_name(struct ptype *p) {

	return p->type->info->name;
}

struct ptype_reg *ptype_get_type(char *name) {
	struct ptype_reg *tmp;
	
	for (tmp = ptype_reg_head; tmp && strcmp(tmp->info->name, name); tmp = tmp->next);

	if (!tmp)
		pomlog(POMLOG_WARN "Warning, requested ptype %s not found", name);

	return tmp;
}

size_t ptype_get_value_size(struct ptype *pt) {
	return pt->type->info->value_size(pt);
}

uint32_t ptype_get_hash(struct ptype *pt) {

	size_t size = pt->type->info->value_size(pt);

	
	// Try to use the best hash function
	if (size == sizeof(uint32_t)) { // exactly one word
		return jhash_1word(*((uint32_t*)pt->value), INITVAL);
	} else if (size == 2 * sizeof(uint32_t))  { // exactly two words
		return jhash_2words(*((uint32_t*)pt->value), *((uint32_t*)(pt->value + sizeof(uint32_t))), INITVAL);
	} else if (size == 3 * sizeof(uint32_t)) { // exactly 3 words
		return jhash_3words(*((uint32_t*)pt->value), *((uint32_t*)(pt->value + sizeof(uint32_t))), *((uint32_t*)(pt->value + (2 * sizeof(uint32_t)))), INITVAL);
	}

	// Fallback on all size function
	return jhash((char*)pt->value, size, INITVAL);
}
