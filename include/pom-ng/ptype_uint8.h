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

#ifndef __POM_NG_PTYPE_UINT8_H__
#define __POM_NG_PTYPE_UINT8_H__

#include <pom-ng/ptype.h>

#define PTYPE_UINT8_PRINT_DECIMAL	0x1
#define PTYPE_UINT8_PRINT_HEX		0x2

/// x is the struct ptype, y is a pointer for the value
#define PTYPE_UINT8_GETVAL(x, y) {				\
	if (x->flags & PTYPE_FLAG_HASLOCK) {			\
		pom_mutex_lock(&x->lock);			\
		static uint8_t value;				\
		value = (uint8_t) *((uint8_t*) (x)->value);	\
		pom_mutex_unlock(&x->lock);			\
		y = &value;					\
	} else							\
		y = (uint8_t*) (x)->value;			\
} 


/// x is the struct ptype, y the value
#define PTYPE_UINT8_SETVAL(x, y) {		\
	if (x->flags & PTYPE_FLAG_HASLOCK)	\
		pom_mutex_lock(&x->lock);	\
	uint8_t *v = (x)->value;		\
	*v = (y);				\
	if (x->flags & PTYPE_FLAG_HASLOCK)	\
		pom_mutex_unlock(&x->lock);	\
}

/// x is the struct ptype, y the increment
#define PTYPE_UINT8_INC(x, y) {		\
	if (x->flags & PTYPE_FLAG_HASLOCK)	\
		pom_mutex_lock(&x->lock);	\
	*((uint8_t*)(x)->value) += (y);	\
	if (x->flags & PTYPE_FLAG_HASLOCK)	\
		pom_mutex_unlock(&x->lock);	\
}


#endif
