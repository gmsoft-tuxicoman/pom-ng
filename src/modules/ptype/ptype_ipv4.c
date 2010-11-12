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

#include <arpa/inet.h>

#include "ptype_ipv4.h"


struct mod_reg_info* ptype_ipv4_reg_info() {

	static struct mod_reg_info reg_info;
	memset(&reg_info, 0, sizeof(struct mod_reg_info));
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = ptype_ipv4_mod_register;
	reg_info.unregister_func = ptype_ipv4_mod_unregister;

	return &reg_info;
}

int ptype_ipv4_mod_register(struct mod_reg *mod) {

	static struct ptype_reg_info pt_ipv4;
	memset(&pt_ipv4, 0, sizeof(struct ptype_reg_info));

	pt_ipv4.name = "ipv4";
	pt_ipv4.api_ver = PTYPE_API_VER;

	pt_ipv4.alloc = ptype_ipv4_alloc;
	pt_ipv4.cleanup = ptype_ipv4_cleanup;
	
	pt_ipv4.parse_val = ptype_ipv4_parse;
	pt_ipv4.print_val = ptype_ipv4_print;
	pt_ipv4.compare_val = ptype_ipv4_compare;
	pt_ipv4.serialize = ptype_ipv4_print;
	pt_ipv4.unserialize = ptype_ipv4_parse;
	pt_ipv4.copy = ptype_ipv4_copy;
	pt_ipv4.value_size = ptype_ipv4_value_size;

	pt_ipv4.ops = PTYPE_OP_ALL;

	return ptype_register(&pt_ipv4, mod);

}

int ptype_ipv4_mod_unregister() {

	return ptype_unregister("ipv4");
}


int ptype_ipv4_alloc(struct ptype *p) {

	p->value = malloc(sizeof(struct ptype_ipv4_val));
	if (!p->value) {
		pom_oom(sizeof(struct ptype_ipv4_val));
		return POM_ERR;
	}
	struct ptype_ipv4_val *v = p->value;
	memset(v, 0, sizeof(struct ptype_ipv4_val));
	v->mask = 32;

	return POM_OK;

}


int ptype_ipv4_cleanup(struct ptype *p) {

	free(p->value);
	return POM_OK;
}


int ptype_ipv4_parse(struct ptype *p, char *val) {

	struct ptype_ipv4_val *v = p->value;

	
	// Let's see first if there is a /
	int i;
	for (i = 0; i < strlen(val); i++) {
		if (val[i] == '/') {
			char ip[INET_ADDRSTRLEN];
			memset(ip, 0, INET_ADDRSTRLEN);
			strncpy(ip, val, i);
			unsigned char mask;
			if (sscanf(val + i + 1, "%hhu", &mask) != 1)
				return POM_ERR;
			if (mask > 32)
				return POM_ERR;
			v->mask = mask;
			if (inet_pton(AF_INET, ip, &v->addr) <= 0)
				return POM_ERR;

			return POM_OK;
		}
	}

	// Looks like there are no /


	if (inet_pton(AF_INET, val, &v->addr) <= 0)
		return POM_ERR;
	v->mask = 32;

	return POM_OK;

}

int ptype_ipv4_print(struct ptype *p, char *val, size_t size) {

	struct ptype_ipv4_val *v = p->value;
	if (v->mask < 32)
		return snprintf(val, size, "%s/%hhu", inet_ntoa(v->addr), v->mask);

	return snprintf(val, size, "%s", inet_ntoa(v->addr));
}

int ptype_ipv4_compare(int op, void *val_a, void *val_b) {

	struct ptype_ipv4_val *a = val_a;
	struct ptype_ipv4_val *b = val_b;

	if (op != PTYPE_OP_EQ)
		return 0;

	
	uint32_t masked_addr_a, masked_addr_b;
	int mask = a->mask;
	if (b->mask < mask)
		mask = b->mask;
	masked_addr_a = ntohl(a->addr.s_addr);
	masked_addr_b = ntohl(b->addr.s_addr);
	masked_addr_a &= (0xffffffff << (32 - mask));
	masked_addr_b &= (0xffffffff << (32 - mask));
	return (masked_addr_a == masked_addr_b);

}

int ptype_ipv4_copy(struct ptype *dst, struct ptype *src) {

	struct ptype_ipv4_val *d = dst->value;
	struct ptype_ipv4_val *s = src->value;
	memcpy(d, s, sizeof(struct ptype_ipv4_val));

	return POM_OK;
}

size_t ptype_ipv4_value_size(struct ptype *pt) {

	return sizeof(struct in_addr);
}
