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
#include <stdio.h>
#include <printf.h>

#include "ptype_uint16.h"
#include <pom-ng/ptype_uint16.h>


struct mod_reg_info* ptype_uint16_reg_info() {

	static struct mod_reg_info reg_info;
	memset(&reg_info, 0, sizeof(struct mod_reg_info));
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = ptype_uint16_mod_register;
	reg_info.unregister_func = ptype_uint16_mod_unregister;

	return &reg_info;
}

int ptype_uint16_mod_register(struct mod_reg *mod) {

	static struct ptype_reg_info pt_u16;
	memset(&pt_u16, 0, sizeof(struct ptype_reg_info));

	pt_u16.name = "uint16";
	pt_u16.api_ver = PTYPE_API_VER;

	pt_u16.alloc = ptype_uint16_alloc;
	pt_u16.cleanup = ptype_uint16_cleanup;
	
	pt_u16.parse_val = ptype_uint16_parse;
	pt_u16.print_val = ptype_uint16_print;
	pt_u16.compare_val = ptype_uint16_compare;
	pt_u16.serialize = ptype_uint16_serialize;
	pt_u16.unserialize = ptype_uint16_parse;
	pt_u16.copy = ptype_uint16_copy;
	pt_u16.value_size = ptype_uint16_value_size;

	pt_u16.ops = PTYPE_OP_ALL;

	return ptype_register(&pt_u16, mod);

}

int ptype_uint16_mod_unregister() {

	return ptype_unregister("uint16");
}

int ptype_uint16_alloc(struct ptype *p) {

	p->value = malloc(sizeof(uint16_t));
	if (!p->value) {
		pom_oom(sizeof(uint16_t));
		return POM_ERR;
	}
	uint16_t *v = p->value;
	*v = 0;

	return POM_OK;

}


int ptype_uint16_cleanup(struct ptype *p) {

	free(p->value);
	return POM_OK;
}


int ptype_uint16_parse(struct ptype *p, char *val) {


	uint16_t *v = p->value;
	if (sscanf(val, "0x%hx", v) == 1) {
		return POM_OK;
	} else if (sscanf(val, "%hu", v) == 1) {
		char suffix = val[strlen(val) - 1];
		switch (suffix) {
			case 'k':
				*v *= 1000;
				break;
			case 'K':
				*v <<= 10;
				break;
			case 'm':
				*v *= 1000000ll;
				break;
			case 'M':
				*v <<= 20;
				break;
			default:
				if (suffix < '0' || suffix > '9')
					return POM_ERR;
		}

		return POM_OK;
	}

	return POM_ERR;

};

int ptype_uint16_print(struct ptype *p, char *val, size_t size, char *format) {

	uint16_t *v = p->value;

	if (format) {
		int argtypes[1];

		int tot = parse_printf_format(format, 1, argtypes);
		if (tot > 1 || (argtypes[0] & ~PA_FLAG_MASK) != PA_INT) {
			format = "%u";
		}
	}

	return snprintf(val, size, format, (unsigned int)*v);
}

int ptype_uint16_compare(int op, void *val_a, void* val_b) {

	uint16_t *a = val_a;
	uint16_t *b = val_b;

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

int ptype_uint16_serialize(struct ptype *p, char *val, size_t size) {

	uint16_t *v = p->value;
	return snprintf(val, size, "%u", *v);
}

int ptype_uint16_copy(struct ptype *dst, struct ptype *src) {

	*((uint16_t*)dst->value) = *((uint16_t*)src->value);
	return POM_OK;
}

size_t ptype_uint16_value_size(struct ptype *p) {
	return sizeof(uint16_t);
}
