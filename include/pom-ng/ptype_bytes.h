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

#ifndef __POM_NG_PTYPE_BYTES_H__
#define __PON_NG_PTYPE_BYTES_H__

#include <pom-ng/ptype.h>

struct ptype_bytes_val {
	size_t length;
	void *value;
};

// x is the struct ptype, y is the new length
#define PTYPE_BYTES_SETLEN(x, y) {				\
	struct ptype_bytes_val *v = (x)->value;			\
	if (v->length != (y)) {					\
		if ((y) == 0 && v->value)			\
			free(v);				\
		else						\
			v->value = realloc(v->value, (y));	\
		v->length = (y);				\
	}							\
}

/// x is the struct ptype
#define PTYPE_BYTES_GETVAL(x) \
	((struct ptype_bytes_val *)((x)->value))->value;
	

/// x is the struct ptype, y the value
#define PTYPE_BYTES_SETVAL(x, y) {		\
	struct ptype_bytes_val *v = (x)->value;	\
	memcpy(v->value, y, v->length);		\
}

#endif
