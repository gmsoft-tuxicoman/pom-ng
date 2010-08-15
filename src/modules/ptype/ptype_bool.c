/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2010 Guy Martin <gmsoft@tuxicoman.be>
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
#include <string.h>

#include <stdint.h>
#include <stdio.h>



#include "ptype_bool.h"


struct mod_reg_info* ptype_bool_reg_info() {

	static struct mod_reg_info reg_info;
	memset(&reg_info, 0, sizeof(struct mod_reg_info));
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = ptype_bool_mod_register;
	reg_info.unregister_func = ptype_bool_mod_unregister;

	return &reg_info;
}

int ptype_bool_mod_register(struct mod_reg *mod) {

	static struct ptype_reg_info pt_bool;
	memset(&pt_bool, 0, sizeof(struct ptype_reg_info));

	pt_bool.name = "bool";
	pt_bool.api_ver = PTYPE_API_VER;

	pt_bool.alloc = ptype_bool_alloc;
	pt_bool.cleanup = ptype_bool_cleanup;
	
	pt_bool.parse_val = ptype_bool_parse;
	pt_bool.print_val = ptype_bool_print;
	pt_bool.compare_val = ptype_bool_compare;
	pt_bool.serialize = ptype_bool_print;
	pt_bool.unserialize = ptype_bool_parse;
	pt_bool.copy = ptype_bool_copy;

	pt_bool.ops = PTYPE_OP_ALL;

	return ptype_register(&pt_bool, mod);

}

int ptype_bool_mod_unregister() {

	return ptype_unregister("bool");
}


int ptype_bool_alloc(struct ptype *p) {

	p->value = malloc(sizeof(int));
	if (!p->value) {
		pom_oom(sizeof(int));
		return POM_ERR;
	}
	int *v = p->value;
	*v = 0;

	return POM_OK;

}

int ptype_bool_cleanup(struct ptype *p) {

	free(p->value);
	return POM_OK;
}

int ptype_bool_parse(struct ptype *p, char *val) {

	int *v = p->value;

	if(!strcasecmp(val, "yes") ||
		!strcasecmp(val, "true") ||
		!strcasecmp(val, "on") ||
		!strcasecmp(val, "1"))
		*v = 1;
	else if(!strcasecmp(val, "no") ||
		!strcasecmp(val, "false") ||
		!strcasecmp(val, "off") ||
		!strcasecmp(val, "0"))
		*v = 0;
	else
		return POM_ERR;

	return POM_OK;

};

int ptype_bool_print(struct ptype *p, char *val, size_t size) {

	int *v = p->value;

	if (*v) {
		strncpy(val, "yes", size);
		return strlen("yes");
	}

	strncpy(val, "no", size);
	return strlen("no");

}

int ptype_bool_compare(int op, void *val_a, void* val_b) {

	int *a = val_a;
	int *b = val_b;

	if (op == PTYPE_OP_EQ)
		return *a == *b;

	return 0;
}

int ptype_bool_copy(struct ptype *dst, struct ptype *src) {

	*((int*)dst->value) = *((int*) src->value);
	return POM_OK;

}
