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



#include "ptype_mac.h"


struct mod_reg_info* ptype_mac_reg_info() {

	static struct mod_reg_info reg_info;
	memset(&reg_info, 0, sizeof(struct mod_reg_info));
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = ptype_mac_mod_register;
	reg_info.unregister_func = ptype_mac_mod_unregister;

	return &reg_info;
}

int ptype_mac_mod_register(struct mod_reg *mod) {

	static struct ptype_reg_info pt_mac;
	memset(&pt_mac, 0, sizeof(struct ptype_reg_info));

	pt_mac.name = "mac";
	pt_mac.api_ver = PTYPE_API_VER;

	pt_mac.alloc = ptype_mac_alloc;
	pt_mac.cleanup = ptype_mac_cleanup;
	
	pt_mac.parse_val = ptype_mac_parse;
	pt_mac.print_val = ptype_mac_print;
	pt_mac.compare_val = ptype_mac_compare;
	pt_mac.serialize = ptype_mac_print;
	pt_mac.unserialize = ptype_mac_parse;
	pt_mac.copy = ptype_mac_copy;

	pt_mac.ops = PTYPE_OP_EQ;

	return ptype_register(&pt_mac, mod);

}

int ptype_mac_mod_unregister() {

	return ptype_unregister("mac");
}


int ptype_mac_alloc(struct ptype *p) {

	p->value = malloc(sizeof(struct ptype_mac_val));
	if (!p->value) {
		pom_oom(sizeof(struct ptype_mac_val));
		return POM_ERR;
	}
	struct ptype_mac_val *v = p->value;
	memset(v->addr, 0, sizeof(v->addr));
	memset(v->mask, 0xff, sizeof(v->mask));

	return POM_OK;

}


int ptype_mac_cleanup(struct ptype *p) {

	free(p->value);
	return POM_OK;
}


int ptype_mac_parse(struct ptype *p, char *val) {

	// TODO : HANDLE MASK

	struct ptype_mac_val *v = p->value;

	if (sscanf(val, "%hhX:%hhX:%hhX:%hhX:%hhX:%hhX", v->addr, v->addr + 1, v->addr + 2, v->addr + 3, v->addr + 4, v->addr + 5) == 6) {
		memset(v->mask, 0xff, sizeof(v->mask));
		return POM_OK;
	}

	return POM_ERR;

}

int ptype_mac_print(struct ptype *p, char *val, size_t size) {

	// TODO : HANDLE MASK

	struct ptype_mac_val *v = p->value;

	return snprintf(val, size, "%02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX",
		v->addr[0],
		v->addr[1],
		v->addr[2],
		v->addr[3],
		v->addr[4],
		v->addr[5]);

}

int ptype_mac_compare(int op, void *val_a, void *val_b) {

	struct ptype_mac_val *a = val_a;
	struct ptype_mac_val *b = val_b;

	if(op == PTYPE_OP_EQ)
		return (memcmp(a->addr, b->addr, sizeof(a->addr)) == 0);

	return 0;
}

int ptype_mac_copy(struct ptype *dst, struct ptype *src) {

	struct ptype_mac_val *d = dst->value;
	struct ptype_mac_val *s = src->value;
	memcpy(d, s, sizeof(struct ptype_mac_val));

	return POM_OK;

}
