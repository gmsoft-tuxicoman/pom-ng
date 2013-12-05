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
	pt_bool.serialize = ptype_bool_serialize;
	pt_bool.unserialize = ptype_bool_parse;
	pt_bool.copy = ptype_bool_copy;
	pt_bool.value_size = ptype_bool_value_size;

	pt_bool.ops = PTYPE_OP_ALL;

	return ptype_register(&pt_bool, mod);

}

int ptype_bool_mod_unregister() {

	return ptype_unregister("bool");
}


int ptype_bool_alloc(struct ptype *p) {

	p->value = malloc(sizeof(char));
	if (!p->value) {
		pom_oom(sizeof(char));
		return POM_ERR;
	}
	char *v = p->value;
	*v = 0;

	return POM_OK;

}

int ptype_bool_cleanup(struct ptype *p) {

	free(p->value);
	return POM_OK;
}

int ptype_bool_parse(struct ptype *p, char *val) {

	char *v = p->value;

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

int ptype_bool_serialize(struct ptype *p, char *val, size_t size) {
	return ptype_bool_print(p, val, size, NULL);
}

int ptype_bool_print(struct ptype *p, char *val, size_t size, char *format) {

	char *yes = "yes", *no = "no";

	if (format) {
		if (!strcmp(format, "binary")) {
			yes = "1";
			no = "0";
		} else if (!strcmp(format, "true_false")) {
			yes = "true";
			no = "false";
		} else if (strcmp(format, "yes_no")) {
			pomlog(POMLOG_WARN "Invalid format for ptype_bool : %s", format);
		}
	}

	char *v = p->value;

	if (*v) {
		strncpy(val, yes, size);
		return strlen(yes);
	}

	strncpy(val, no, size);
	return strlen(no);

}

int ptype_bool_compare(int op, void *val_a, void* val_b) {

	char *a = val_a;
	char *b = val_b;

	if (op == PTYPE_OP_EQ)
		return *a == *b;

	return 0;
}

int ptype_bool_copy(struct ptype *dst, struct ptype *src) {

	*((char*)dst->value) = *((char*) src->value);
	return POM_OK;

}

size_t ptype_bool_value_size(struct ptype *pt) {

	return sizeof(char);
}
