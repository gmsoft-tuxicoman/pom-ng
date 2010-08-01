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

#ifndef __PTYPE_STRING_H__
#define __PTYPE_STRING_H__

#include <pom-ng/ptype.h>

int ptype_string_mod_register(struct mod_reg *r);
int ptype_string_mod_unregister();


int ptype_string_cleanup(struct ptype *p);
int ptype_string_parse(struct ptype *p, char *val);
int ptype_string_print(struct ptype *pt, char *val, size_t size);
int ptype_string_compare(int op, void *val_a, void *val_b);
int ptype_string_copy(struct ptype *dst, struct ptype *src);

#endif
