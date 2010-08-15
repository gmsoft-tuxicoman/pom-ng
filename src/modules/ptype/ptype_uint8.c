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

#include "ptype_uint8.h"
#include <pom-ng/ptype_uint8.h>


struct mod_reg_info* ptype_uint8_reg_info() {

	static struct mod_reg_info reg_info;
	memset(&reg_info, 0, sizeof(struct mod_reg_info));
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = ptype_uint8_mod_register;
	reg_info.unregister_func = ptype_uint8_mod_unregister;

	return &reg_info;
}

int ptype_uint8_mod_register(struct mod_reg *mod) {

	static struct ptype_reg_info pt_u32;
	memset(&pt_u32, 0, sizeof(struct ptype_reg_info));

	pt_u32.name = "uint8";
	pt_u32.api_ver = PTYPE_API_VER;

	pt_u32.alloc = ptype_uint8_alloc;
	pt_u32.cleanup = ptype_uint8_cleanup;
	
	pt_u32.parse_val = ptype_uint8_parse;
	pt_u32.print_val = ptype_uint8_print;
	pt_u32.compare_val = ptype_uint8_compare;
	pt_u32.serialize = ptype_uint8_print;
	pt_u32.unserialize = ptype_uint8_parse;
	pt_u32.copy = ptype_uint8_copy;

	pt_u32.ops = PTYPE_OP_ALL;

	return ptype_register(&pt_u32, mod);

}

int ptype_uint8_mod_unregister() {

	return ptype_unregister("uint8");
}

int ptype_uint8_alloc(struct ptype *p) {

	p->value = malloc(sizeof(uint8_t));
	if (!p->value) {
		pom_oom(sizeof(uint8_t));
		return POM_ERR;
	}
	uint8_t *v = p->value;
	*v = 0;

	return POM_OK;

}


int ptype_uint8_cleanup(struct ptype *p) {

	free(p->value);
	return POM_OK;
}


int ptype_uint8_parse(struct ptype *p, char *val) {


	uint8_t *v = p->value;
	if (sscanf(val, "0x%hhx", v) == 1)
		return POM_OK;
	if (sscanf(val, "%hhu", v) == 1)
		return POM_OK;

	return POM_ERR;

};

int ptype_uint8_print(struct ptype *p, char *val, size_t size) {

	uint8_t *v = p->value;

	switch (p->print_mode) {
		case PTYPE_UINT8_PRINT_HEX:
			return snprintf(val, size, "0x%X", *v);
		default:
		case PTYPE_UINT8_PRINT_DECIMAL:
			return snprintf(val, size, "%u", *v);
	}

	return 0;

}

int ptype_uint8_compare(int op, void *val_a, void* val_b) {

	uint8_t *a = val_a;
	uint8_t *b = val_b;

	switch (op) {
		case PTYPE_OP_EQ:
			return *a == *b;
		case PTYPE_OP_GT:
			return *a > *b;
		case PTYPE_OP_GE:
			return *a >= *b;
		case PTYPE_OP_LT:
			return *a < *b;
		case PTYPE_OP_LE:
			return *a <= *b;

	}

	return 0;
}

int ptype_uint8_serialize(struct ptype *p, char *val, size_t size) {
	uint8_t *v = p->value;
	return snprintf(val, size, "%u", *v);
}

int ptype_uint8_copy(struct ptype *dst, struct ptype *src) {

	*((uint8_t*)dst->value) = *((uint8_t*)src->value);
	return POM_OK;
}
