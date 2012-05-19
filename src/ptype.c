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

#include <pthread.h>
#include <string.h>

static pthread_rwlock_t ptype_reg_rwlock = PTHREAD_RWLOCK_INITIALIZER;
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

	ptype_reg_lock(1);

	struct ptype_reg *tmp;
	for (tmp = ptype_reg_head; tmp && strcmp(tmp->info->name, reg_info->name); tmp = tmp->next);
	if (tmp) {
		pomlog(POMLOG_ERR "Ptype %s already registered", reg_info->name);
		free(reg);
		ptype_reg_unlock();
		return POM_ERR;
	}

	reg->info = reg_info;
	reg->module = mod;

	mod_refcount_inc(mod);

	reg->next = ptype_reg_head;
	ptype_reg_head = reg;
	if (reg->next)
		reg->next->prev = reg;
	ptype_reg_unlock();

	return POM_OK;
}

struct ptype *ptype_alloc(const char* type) {

	return ptype_alloc_unit(type, NULL);
}

struct ptype* ptype_alloc_unit(const char* type, char* unit) {

	ptype_reg_lock(1);

	struct ptype_reg *reg;
	for (reg = ptype_reg_head; reg && strcmp(reg->info->name, type); reg = reg->next);

	if (!reg) {
		ptype_reg_unlock();
		// This should only be needed at startup
		pomlog("Ptype of type %s not found, trying to load module", type);
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
		ptype_reg_lock(1);
	}
	
	struct ptype *ret = malloc(sizeof(struct ptype));
	if (!ret) {
		ptype_reg_unlock();
		pom_oom(sizeof(struct ptype));
		return NULL;
	}

	memset(ret, 0, sizeof(struct ptype));
	ret->type = reg;
	if (reg->info->alloc) {
		if (reg->info->alloc(ret) != POM_OK) {
			ptype_reg_unlock();
			pomlog(POMLOG_ERR "Error while allocating ptype %s", type);
			free(ret);
			return NULL;
		}
	}

	reg->refcount++;
	ptype_reg_unlock();

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

	ptype_reg_lock(1);
	pt->type->refcount--;
	ptype_reg_unlock();
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

	ptype_reg_lock(1);
	type->refcount++;
	ptype_reg_unlock();

	return res;

}

int ptype_parse_val(struct ptype *pt, char *val) {

	int res = POM_ERR;
	if (pt->type->info->parse_val)
		res = pt->type->info->parse_val(pt, val);
	
	return res;
}

int ptype_print_val(struct ptype *pt, char *val, size_t size) {
	
	return pt->type->info->print_val(pt, val, size);
}

char *ptype_print_val_alloc(struct ptype *pt) {

	char *res = NULL;

	int size, new_size = DEFAULT_PRINT_VAL_ALLOC_BUFF;
	do {
		size = new_size;
		res = realloc(res, size + 1);
		if (!res) {
			pom_oom(size + 1);
			return NULL;
		}
		new_size = ptype_print_val(pt, res, size);
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

	if (a->type != b->type) {
		pomlog(POMLOG_ERR "Cannot compare ptypes, type differs. What about you try not to compare pears with apples ...");
		goto err; // false
	}

	if (!(a->type->info->ops & op)) {
		pomlog(POMLOG_ERR "Invalid operation %s for ptype %s", ptype_get_op_sign(op), a->type->info->name);
		goto err;
	}

	if (op == PTYPE_OP_NEQ)
		res = !(a->type->info->compare_val(PTYPE_OP_EQ, a->value, b->value));
	else
		res = (a->type->info->compare_val(op, a->value, b->value));

err:

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
	
	ptype_reg_lock(1);
	pt->type->refcount--;
	ptype_reg_unlock();

	free(pt);

	return POM_OK;
}

int ptype_unregister(char *name) {

	ptype_reg_lock(1);
	struct ptype_reg *reg;

	for (reg = ptype_reg_head; reg && strcmp(reg->info->name, name); reg = reg->next);
	if (!reg) {
		pomlog(POMLOG_WARN "Ptype %s is not registered, cannot unregister it.", name);
		ptype_reg_unlock();
		return POM_OK; // Do not return an error so module unloading proceeds
	}

	if (reg->refcount) {
		pomlog(POMLOG_WARN "Cannot unregister ptype %s as it's still in use", name);
		ptype_reg_unlock();
		return POM_ERR;
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

	ptype_reg_unlock();

	return POM_OK;
}

unsigned int ptype_get_refcount(struct ptype_reg *reg) {

	unsigned int refcount = 0;
	ptype_reg_lock(0);
	refcount = reg->refcount;
	ptype_reg_unlock();
	return refcount;
}


void ptype_reg_lock(int write) {
	
	int res = 0;
	
	if (write)
		res = pthread_rwlock_wrlock(&ptype_reg_rwlock);
	else
		res = pthread_rwlock_rdlock(&ptype_reg_rwlock);

	if (res) {
		pomlog(POMLOG_ERR "Error while locking the ptype_reg lock");
		abort();
	}

}

void ptype_reg_unlock() {

	if (pthread_rwlock_unlock(&ptype_reg_rwlock)) {
		pomlog(POMLOG_ERR "Error while unlocking the ptype_reg lock");
		abort();
	}

}

char *ptype_get_name(struct ptype *p) {

	return p->type->info->name;
}

struct ptype_reg *ptype_get_type(char *name) {
	ptype_reg_lock(0);
	struct ptype_reg *tmp;
	
	for (tmp = ptype_reg_head; tmp && strcmp(tmp->info->name, name); tmp = tmp->next);
	ptype_reg_unlock();

	return tmp;
}

size_t ptype_get_value_size(struct ptype *pt) {

	if (!pt->type->info->value_size)
		return -1;
	return pt->type->info->value_size(pt);
}

