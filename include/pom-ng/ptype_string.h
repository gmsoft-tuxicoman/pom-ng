/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2010-2012 Guy Martin <gmsoft@tuxicoman.be>
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

#ifndef __POM_NG_PTYPE_STRING_H__
#define __PON_NG_PTYPE_STRING_H__

#include <pom-ng/ptype.h>

/// x is the struct ptype
#define PTYPE_STRING_GETVAL(x) \
	(char*) x->value

/// x is the struct ptype, y the string
#define PTYPE_STRING_SETVAL(x, y) {		\
	if ((x)->value)				\
		free((x)->value);		\
	(x)->value = strdup(y);			\
	if (!(x)->value)			\
		pom_oom(strlen(y));		\
}

/// x is the struct ptype, y is the string
#define PTYPE_STRING_SETVAL_N(x, y, n) {	\
	if ((x)->value)				\
		free((x)->value);		\
	(x)->value = strndup(y, n);		\
	if (!(x)->value)			\
		pom_oom(strlen(y));		\
}

/// x is the struct ptype, y the string pointer
#define PTYPE_STRING_SETVAL_P(x, y) {		\
	if ((x)->value)				\
		free((x)->value);		\
	(x)->value = y;				\
}

#endif
