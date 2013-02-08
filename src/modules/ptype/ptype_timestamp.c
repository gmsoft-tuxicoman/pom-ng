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

#include "ptype_timestamp.h"


struct mod_reg_info* ptype_timestamp_reg_info() {

	static struct mod_reg_info reg_info;
	memset(&reg_info, 0, sizeof(struct mod_reg_info));
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = ptype_timestamp_mod_register;
	reg_info.unregister_func = ptype_timestamp_mod_unregister;

	return &reg_info;
}

int ptype_timestamp_mod_register(struct mod_reg *mod) {

	static struct ptype_reg_info pt_timestamp;
	memset(&pt_timestamp, 0, sizeof(struct ptype_reg_info));

	pt_timestamp.name = "timestamp";
	pt_timestamp.api_ver = PTYPE_API_VER;

	pt_timestamp.alloc = ptype_timestamp_alloc;
	pt_timestamp.cleanup = ptype_timestamp_cleanup;
	
	pt_timestamp.print_val = ptype_timestamp_print;
	pt_timestamp.compare_val = ptype_timestamp_compare;
	pt_timestamp.serialize = ptype_timestamp_serialize;
	pt_timestamp.unserialize = ptype_timestamp_unserialize;
	pt_timestamp.copy = ptype_timestamp_copy;
	pt_timestamp.value_size = ptype_timestamp_value_size;

	pt_timestamp.ops = PTYPE_OP_ALL;

	return ptype_register(&pt_timestamp, mod);

}

int ptype_timestamp_mod_unregister() {

	return ptype_unregister("timestamp");
}


int ptype_timestamp_alloc(struct ptype *p) {

	p->value = malloc(sizeof(ptime));
	if (!p->value) {
		pom_oom(sizeof(ptime));
		return POM_ERR;
	}
	ptime *v = p->value;
	*v = 0;

	return POM_OK;

}


int ptype_timestamp_cleanup(struct ptype *p) {

	free(p->value);
	return POM_OK;
}

int ptype_timestamp_print(struct ptype *p, char *val, size_t size) {

	ptime *v = p->value;

	// TODO handle multiple format

	char *format = "%Y-%m-%d %H:%M:%S";
	struct tm tmp;
	time_t sec = pom_ptime_sec(*v);
	localtime_r(&sec, &tmp);
	char buff[4 + 1 + 2 + 1 + 2 + 1 + 2 + 1 + 2 + 1 + 2 + 1];
	memset(buff, 0, sizeof(buff));
	strftime(buff, sizeof(buff), format, &tmp);

	// We must return what would have been written
	size_t len = strlen(buff);
	if (len > size - 1) {
		strncpy(val, buff, size - 1);
		val[size] = 0;
	} else {
		strcpy(val, buff);
	}

	return len;
}

int ptype_timestamp_compare(int op, void *val_a, void *val_b) {

	ptime *a = val_a;
	ptime *b = val_b;

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

int ptype_timestamp_serialize(struct ptype *p, char *val, size_t size) {

	ptime *v = p->value;
	return snprintf(val, size, "%lu.%lu", pom_ptime_sec(*v), pom_ptime_usec(*v));

}

int ptype_timestamp_unserialize(struct ptype *p, char *val) {

	ptime *v = p->value;
	unsigned long long sec, usec;
	if (sscanf(val, "%llu.%llu", &sec, &usec) != 2)
		return POM_ERR;

	*v = (sec * 1000000ULL) + usec;
	
	return POM_OK;

}

int ptype_timestamp_copy(struct ptype *dst, struct ptype *src) {

	ptime *d = dst->value;
	ptime *s = src->value;
	*d = *s;

	return POM_OK;
}

size_t ptype_timestamp_value_size(struct ptype *pt) {

	return sizeof(struct timeval);
}
