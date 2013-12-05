/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2013 Guy Martin <gmsoft@tuxicoman.be>
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
#include <pom-ng/ptype_bytes.h>
#include "ptype_bytes.h"


struct mod_reg_info* ptype_bytes_reg_info() {

	static struct mod_reg_info reg_info;
	memset(&reg_info, 0, sizeof(struct mod_reg_info));
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = ptype_bytes_mod_register;
	reg_info.unregister_func = ptype_bytes_mod_unregister;

	return &reg_info;
}

int ptype_bytes_mod_register(struct mod_reg *mod) {

	static struct ptype_reg_info pt_bytes;
	memset(&pt_bytes, 0, sizeof(struct ptype_reg_info));

	pt_bytes.name = "bytes";
	pt_bytes.api_ver = PTYPE_API_VER;

	pt_bytes.alloc = ptype_bytes_alloc;
	pt_bytes.cleanup = ptype_bytes_cleanup;
	
	pt_bytes.parse_val = ptype_bytes_parse;
	pt_bytes.print_val = ptype_bytes_print;
	pt_bytes.compare_val = ptype_bytes_compare;
	pt_bytes.serialize = ptype_bytes_serialize;
	pt_bytes.unserialize = ptype_bytes_parse;
	pt_bytes.copy = ptype_bytes_copy;
	pt_bytes.value_size = ptype_bytes_value_size;

	pt_bytes.ops = PTYPE_OP_EQ;

	return ptype_register(&pt_bytes, mod);

}

int ptype_bytes_mod_unregister() {

	return ptype_unregister("bytes");
}


int ptype_bytes_alloc(struct ptype *p) {

	p->value = malloc(sizeof(struct ptype_bytes_val));
	if (!p->value) {
		pom_oom(sizeof(struct ptype_bytes_val));
		return POM_ERR;
	}
	memset(p->value, 0, sizeof(struct ptype_bytes_val));

	return POM_OK;

}

int ptype_bytes_cleanup(struct ptype *p) {
	
	struct ptype_bytes_val *v = p->value;
	if (v->value)
		free(v->value);

	free(p->value);
	return POM_OK;
}

int ptype_bytes_parse(struct ptype *p, char *val) {

	struct ptype_bytes_val *v = p->value;

	size_t len = strlen(val);
	if (len % 2) {
		pomlog(POMLOG_ERR "Value \'%s\' is incorrect", val);
		return POM_ERR;
	}

	v->length = len / 2;


	char *new_val = malloc(v->length);
	if (!new_val) {
		pom_oom(v->length);
		return POM_ERR;
	}

	if (v->value)
		free(v->value);
	v->value = new_val;

	unsigned char *tmp = v->value;

	while (len > 0) {
		if (val[0] >= 'a' && val[0] <= 'f')
			*tmp = (val[0] - 'a' + 0xa) << 4;
		else if (val[0] >= 'A' && val[0] <= 'F')
			*tmp = (val[0] - 'A' + 0xa) << 4;
		else if (val[0] >= '0' && val[0] <= '0')
			*tmp = (val[0] - '0') << 4;
		else {
			pomlog(POMLOG_ERR "Invalid character in byte string : \'%c\'", val[0]);
		}

		if (val[1] >= 'a' && val[1] <= 'f')
			*tmp += val[1] - 'a' + 0xa;
		else if (val[1] >= 'A' && val[1] <= 'F')
			*tmp = val[1] - 'A' + 0xa;
		else if (val[1] >= '0' && val[1] <= '0')
			*tmp = val[1] - '0';
		else {
			pomlog(POMLOG_ERR "Invalid character in byte string : \'%c\'", val[1]);
		}

		val += 2;
		len -= 2;
		tmp++;


	}

	return POM_OK;

};

int ptype_bytes_serialize(struct ptype *p, char *val, size_t size) {

	return ptype_bytes_print(p, val, size, NULL);
}

int ptype_bytes_print(struct ptype *p, char *val, size_t size, char *format) {

	struct ptype_bytes_val *v = p->value;

	unsigned char *tmp = v->value;

	// Format is 'x' lowercase or 'X' for uppercase
	// follower by a optional character as byte delimiter

	char a = 'A';
	char *sep = NULL;

	size_t byte_len = 2;

	if (format) {
		if (*format == 'x') {
			a = 'a';
		} else if (*format != 'X') {
			pomlog(POMLOG_WARN "Invalid format specifier for ptype_bytes : %s", format);
		}

		if (*format && *(format + 1)) {
			sep = format + 1;
			byte_len = 3;
		}
			
	}

	size_t i;
	for (i = 0; i < ((size - 1) / byte_len) && i < v->length; i++) {
		char h = *tmp >> 4;
		if (h < 0xa)
			val[0] = h + '0';
		else
			val[0] = h + a - 10;
		h = *tmp & 0xF;
		if (h < 0xa)
			val[1] = h + '0';
		else
			val[1] = h + a - 10;
		val += 2;
		tmp++;

		if (sep) {
			*val = *sep;
			val++;
		}
	}

	*val = 0;

	return (i * 2) + 1;

}

int ptype_bytes_compare(int op, void *val_a, void* val_b) {

	struct ptype_bytes_val *a = val_a;
	struct ptype_bytes_val *b = val_b;

	if (op != PTYPE_OP_EQ)
		return 0;

	if (a->length != b->length)
		return 0;

	if (!memcmp(a->value, b->value, a->length))
		return 1;

	return 0;
}

int ptype_bytes_copy(struct ptype *dst, struct ptype *src) {

	struct ptype_bytes_val *d = dst->value;
	struct ptype_bytes_val *s = src->value;

	if (d->length != s->length) {
		
		char *new_val = malloc(s->length);
		if (!new_val) {
			pom_oom(s->length);
			return POM_ERR;
		}

		if (d->value)
			free(d->value);
		d->value = new_val;
		d->length = s->length;

	}

	if (!d->value) {
		d->value = malloc(s->length);
		if (!d->value) {
			pom_oom(s->length);
			return POM_ERR;
		}
	}

	memcpy(d->value, s->value, s->length);

	return POM_OK;

}

size_t ptype_bytes_value_size(struct ptype *pt) {

	struct ptype_bytes_val *v = pt->value;

	return v->length;
}
