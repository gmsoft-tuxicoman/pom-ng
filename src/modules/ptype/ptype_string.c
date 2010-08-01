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
#include <stdio.h>

#include "ptype_string.h"

struct mod_reg_info* ptype_string_reg_info() {
	static struct mod_reg_info reg_info;
	memset(&reg_info, 0, sizeof(struct mod_reg_info));
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = ptype_string_mod_register;
	reg_info.unregister_func = ptype_string_mod_unregister;

	return &reg_info;
}


int ptype_string_mod_register(struct mod_reg *mod) {

	static struct ptype_reg_info pt_string;
	memset(&pt_string, 0, sizeof(struct ptype_reg_info));

	pt_string.name = "string";
	pt_string.api_ver = PTYPE_API_VER;

	pt_string.cleanup = ptype_string_cleanup;
	pt_string.parse_val = ptype_string_parse;
	pt_string.print_val = ptype_string_print;
	pt_string.compare_val = ptype_string_compare;

	pt_string.serialize = ptype_string_print;
	pt_string.unserialize = ptype_string_parse;

	pt_string.copy = ptype_string_copy;

	pt_string.ops = PTYPE_OP_EQ;


	return ptype_register(&pt_string, mod);
}

int ptype_string_mod_unregister() {
	return ptype_unregister("string");
}


int ptype_string_cleanup(struct ptype *p) {

	if (p->value)
		free(p->value);
	return POM_OK;
}


int ptype_string_parse(struct ptype *p, char *val) {

	char *str = realloc(p->value, strlen(val) + 1);
	strcpy(str, val);
	p->value = str;

	return POM_OK;

}

int ptype_string_print(struct ptype *p, char *val, size_t size) {

	char *str = p->value;
	return snprintf(val, size, "%s", str);

}

int ptype_string_compare(int op, void *val_a, void *val_b) {

	char *a = val_a;
	char *b = val_b;

	if (op == PTYPE_OP_EQ)
		return !strcmp(a, b);
	
	return 0;
}

int ptype_string_copy(struct ptype *dst, struct ptype *src) {

	if (!src->value) {
		if (dst->value) {
			free(dst->value);
			dst->value = 0;
		}
		return POM_OK;
	}

	dst->value = realloc(dst->value, strlen(src->value) + 1);
	strcpy(dst->value, src->value);

	return POM_OK;
}
