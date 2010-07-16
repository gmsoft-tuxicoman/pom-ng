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

#ifndef __PTYPE_H__
#define __PTYPE_H__

#include <pom-ng/ptype.h>

/// Maximum number of registered
#define MAX_PTYPE 256

/// Default size for first allocation in ptype_print_val_alloc()
#define DEFAULT_PRINT_VAL_ALLOC_BUFF 64


struct ptype_reg {

	struct ptype_reg_info *info;
	struct mod_reg *module;

	struct ptype_reg *next, *prev;
	

};

/// Allocate a new struct ptype.
struct ptype* ptype_alloc(const char* type, char* unit);

/// Allocate a clone of a given ptype.
struct ptype* ptype_alloc_from(struct ptype *pt);

/// Parse a string into a useable value.
int ptype_parse_val(struct ptype *pt, char *val);

/// Print the value of the ptype in a string.
int ptype_print_val(struct ptype *pt, char *val, size_t size);

/// Allocate a new string and save it's value
char *ptype_print_val_alloc(struct ptype *pt);

/// Give the type of the ptype from its name.
int ptype_get_type(char* ptype_name);

/// Give the name of the ptype type
char *ptype_get_name(unsigned int type);

/// Give the refcount of the ptype
unsigned int ptype_get_refcount(unsigned int type);

/// Give the ptype operation identifier from it's string representation.
int ptype_get_op(struct ptype *pt, char *op);

/// Give the alphanumeric string representation of a ptype operation from its identifier.
char *ptype_get_op_name(int op);

/// Give the arithmetic operator string representaion of a ptype operation from its identifier.
char *ptype_get_op_sign(int op);

/// Compare two ptype values using the specified operation.
int ptype_compare_val(int op, struct ptype *a, struct ptype *b);

/// Serialize the ptype value for storage in a config file.
int ptype_serialize(struct ptype *pt, char *val, size_t size);

/// Unserialize a ptype value.
int ptype_unserialize(struct ptype *pt, char *val);

/// Copy ptype values.
int ptype_copy(struct ptype *dst, struct ptype *src);

void ptype_reg_lock(int write);
void ptype_reg_unlock();
#endif
