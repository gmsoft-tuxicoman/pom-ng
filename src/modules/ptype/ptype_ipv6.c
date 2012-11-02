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

#include "ptype_ipv6.h"

#include <stdio.h>
#include <arpa/inet.h>


struct mod_reg_info* ptype_ipv6_reg_info() {

	static struct mod_reg_info reg_info;
	memset(&reg_info, 0, sizeof(struct mod_reg_info));
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = ptype_ipv6_mod_register;
	reg_info.unregister_func = ptype_ipv6_mod_unregister;

	return &reg_info;
}

int ptype_ipv6_mod_register(struct mod_reg *mod) {

	static struct ptype_reg_info pt_ipv6;
	memset(&pt_ipv6, 0, sizeof(struct ptype_reg_info));

	pt_ipv6.name = "ipv6";
	pt_ipv6.api_ver = PTYPE_API_VER;

	pt_ipv6.alloc = ptype_ipv6_alloc;
	pt_ipv6.cleanup = ptype_ipv6_cleanup;
	
	pt_ipv6.parse_val = ptype_ipv6_parse;
	pt_ipv6.print_val = ptype_ipv6_print;
	pt_ipv6.compare_val = ptype_ipv6_compare;
	pt_ipv6.serialize = ptype_ipv6_print;
	pt_ipv6.unserialize = ptype_ipv6_parse;
	pt_ipv6.copy = ptype_ipv6_copy;
	pt_ipv6.value_size = ptype_ipv6_value_size;

	pt_ipv6.ops = PTYPE_OP_ALL;

	return ptype_register(&pt_ipv6, mod);

}

int ptype_ipv6_mod_unregister() {

	return ptype_unregister("ipv6");
}

int ptype_ipv6_alloc(struct ptype *p) {

	p->value = malloc(sizeof(struct ptype_ipv6_val));
	if (!p->value) {
		pom_oom(sizeof(struct ptype_ipv6_val));
		return POM_ERR;
	}
	struct ptype_ipv6_val *v = p->value;
	memset(v, 0, sizeof(struct ptype_ipv6_val));
	v->mask = 128;

	return POM_OK;

}

int ptype_ipv6_cleanup(struct ptype *p) {

	free(p->value);
	return POM_OK;
}

int ptype_ipv6_parse(struct ptype *p, char *val) {

	struct ptype_ipv6_val *v = p->value;

	
	// Let's see first if there is a /
	size_t i;
	for (i = 0; i < strlen(val); i++) {
		if (val[i] == '/') {
			char ip[INET6_ADDRSTRLEN];
			memset(ip, 0, INET6_ADDRSTRLEN);
			strncpy(ip, val, i);
			unsigned char mask;
			if (sscanf(val + i + 1, "%hhu", &mask) != 1)
				return POM_ERR;
			if (mask > 128)
				return POM_ERR;
			v->mask = mask;
			if (inet_pton(AF_INET6, ip, &v->addr) <= 0)
				return POM_ERR;

			return POM_OK;
		}
	}

	// Looks like there are no /


	if (inet_pton(AF_INET6, val, &v->addr) <= 0)
		return POM_ERR;
	v->mask = 128;

	return POM_OK;

}

int ptype_ipv6_print(struct ptype *p, char *val, size_t size) {

	struct ptype_ipv6_val *v = p->value;
	char buff[INET6_ADDRSTRLEN + 1];
	inet_ntop(AF_INET6, &v->addr, buff, INET6_ADDRSTRLEN);
	if (v->mask < 128)
		return snprintf(val, size, "%s/%hhu", buff, v->mask);

	return snprintf(val, size, "%s", buff);
}

int ptype_ipv6_compare(int op, void *val_a, void *val_b) {

	struct ptype_ipv6_val *a = val_a;
	struct ptype_ipv6_val *b = val_b;

	if (op != PTYPE_OP_EQ)
		return 0;

	int minmask = a->mask;
	if (b->mask < minmask)
		minmask = b->mask;
	
	uint32_t mask[4];
	if (minmask <= 32) {
		mask[0] = (0xffffffff << (32 - minmask));
		mask[1] = 0;
		mask[2] = 0;
		mask[3] = 0;
	} else if (minmask <= 64) {
		mask[0] = 0xffffffff;
		mask[1] = (0xffffffff << (64 - minmask));
		mask[2] = 0;
		mask[3] = 0;
	} else if (minmask <= 96) {
		mask[0] = 0xffffffff;
		mask[1] = 0xffffffff;
		mask[2] = (0xffffffff << (96 - minmask));
		mask[3] = 0;
	} else {
		mask[0] = 0xffffffff;
		mask[1] = 0xffffffff;
		mask[2] = 0xffffffff;
		mask[3] = (0xffffffff << (128 - minmask));
	}
	
	return ((a->addr.s6_addr32[0] & mask[0]) == (b->addr.s6_addr32[0] & mask[0])
		&& (a->addr.s6_addr32[1] & mask[1]) == (b->addr.s6_addr32[1] & mask[1])
		&& (a->addr.s6_addr32[2] & mask[2]) == (b->addr.s6_addr32[2] & mask[2])
		&& (a->addr.s6_addr32[3] & mask[3]) == (b->addr.s6_addr32[3] & mask[3]));

}

int ptype_ipv6_copy(struct ptype *dst, struct ptype *src) {

	struct ptype_ipv6_val *d = dst->value;
	struct ptype_ipv6_val *s = src->value;
	memcpy(d, s, sizeof(struct ptype_ipv6_val));

	return POM_OK;
}

size_t ptype_ipv6_value_size(struct ptype *pt) {

	return sizeof(struct in6_addr);
}
