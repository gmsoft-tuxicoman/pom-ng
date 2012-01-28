/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2012 Guy Martin <gmsoft@tuxicoman.be>
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

#include "ptype_uint64.h"
#include <pom-ng/ptype_uint64.h>


struct mod_reg_info* ptype_uint64_reg_info() {

	static struct mod_reg_info reg_info;
	memset(&reg_info, 0, sizeof(struct mod_reg_info));
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = ptype_uint64_mod_register;
	reg_info.unregister_func = ptype_uint64_mod_unregister;

	return &reg_info;
}

int ptype_uint64_mod_register(struct mod_reg *mod) {

	static struct ptype_reg_info pt_u64;
	memset(&pt_u64, 0, sizeof(struct ptype_reg_info));

	pt_u64.name = "uint64";
	pt_u64.api_ver = PTYPE_API_VER;

	pt_u64.alloc = ptype_uint64_alloc;
	pt_u64.cleanup = ptype_uint64_cleanup;
	
	pt_u64.parse_val = ptype_uint64_parse;
	pt_u64.print_val = ptype_uint64_print;
	pt_u64.compare_val = ptype_uint64_compare;
	pt_u64.serialize = ptype_uint64_serialize;
	pt_u64.unserialize = ptype_uint64_parse;
	pt_u64.copy = ptype_uint64_copy;
	pt_u64.value_size = ptype_uint64_value_size;

	pt_u64.ops = PTYPE_OP_ALL;

	return ptype_register(&pt_u64, mod);

}

int ptype_uint64_mod_unregister() {

	return ptype_unregister("uint64");
}

int ptype_uint64_alloc(struct ptype *p) {

	p->value = malloc(sizeof(uint64_t));
	if (!p->value) {
		pom_oom(sizeof(uint64_t));
		return POM_ERR;
	}
	uint64_t *v = p->value;
	*v = 0;

	return POM_OK;

}


int ptype_uint64_cleanup(struct ptype *p) {

	free(p->value);
	return POM_OK;
}


int ptype_uint64_parse(struct ptype *p, char *val) {


	uint64_t *v = p->value;
	if (sscanf(val, "0x%lx", v) == 1) {
		return POM_OK;
	} else if (sscanf(val, "%lu", v) == 1) {
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

int ptype_uint64_print(struct ptype *p, char *val, size_t size) {

	uint64_t *v = p->value;

	switch (p->flags & PTYPE_FLAG_RESERVED) {
		case PTYPE_UINT64_PRINT_HEX:
			return snprintf(val, size, "0x%lX", *v);
		case PTYPE_UINT64_PRINT_HUMAN: {
			uint64_t value = *v;
			if (value > 99999) {
				value = (value + 500) / 1000;
				if (value > 9999) {
					value = (value + 500) / 1000;
					return snprintf(val, size, "%lum", value);
				} else
					return snprintf(val, size, "%luk", value);
			} else
				return snprintf(val, size, "%lu", value);
			break;
		}
		case PTYPE_UINT64_PRINT_HUMAN_1024: {
			uint64_t value = *v;
			if (value > 99999) {
				value = (value + 512) / 1024;
				if (value > 9999) {
					value = (value + 512) / 1024;
					return snprintf(val, size, "%luM", value);
				} else
					return snprintf(val, size, "%luK", value);
			} else
				return snprintf(val, size, "%lu", value);
			break;
		}
		default:
		case PTYPE_UINT64_PRINT_DECIMAL:
			return snprintf(val, size, "%lu", *v);
	}

	return 0;

}

int ptype_uint64_compare(int op, void *val_a, void* val_b) {

	uint64_t *a = val_a;
	uint64_t *b = val_b;

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

int ptype_uint64_serialize(struct ptype *p, char *val, size_t size) {

	uint64_t *v = p->value;
	return snprintf(val, size, "%lu", *v);
}

int ptype_uint64_copy(struct ptype *dst, struct ptype *src) {

	*((uint64_t*)dst->value) = *((uint64_t*)src->value);
	return POM_OK;
}

size_t ptype_uint64_value_size(struct ptype *p) {
	return sizeof(uint64_t);
}
