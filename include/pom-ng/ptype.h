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


#ifndef __POM_NG_PTYPE_H__
#define __POM_NG_PTYPE_H__

#include <pom-ng/base.h>
#include <pom-ng/mod.h>

#include <stdlib.h>

/// Ptype operation reserved number
#define PTYPE_OP_RSVD	0x00

/// Ptype operation equal
#define PTYPE_OP_EQ	0x01

/// Ptype operation greater than
#define PTYPE_OP_GT	0x02

/// Ptype operation greater or equal
#define PTYPE_OP_GE	0x04

/// Ptype operation less than
#define PTYPE_OP_LT	0x08

/// Ptype operation less or equal
#define PTYPE_OP_LE	0x10

/// Ptype operation not equal
#define PTYPE_OP_NEQ	0x20


/// Ptype mask for all valid operations
#define PTYPE_OP_ALL	0x3f


// Current ptype API version
#define PTYPE_API_VER	0


/// This structure hold all the informations about a ptype and its attibutes
struct ptype {
	int type; ///< Type of the ptype
	char *unit; ///< Unity to be displayed
	void *value; ///< Pointer to private data storing the actual value
	unsigned int print_mode; ///< How to display the ptype on the screen
};


struct ptype_reg_info {
	
	char *name;
	unsigned int api_ver;

	int ops; ///< Bitmaks of the operations handled by this ptype

	/// Pointer to the allocate function
	/**
	 * The alloc function will allocate the field value to store the actual value
	 * @param pt Ptype to allocate value to
	 * @return POM_OK on success, POM_ERR on failure.
	 */
	int (*alloc) (struct ptype* pt);

	/// Pointer to the cleanup function
	/**
	 * The cleanup function should free the memory used by the value.
	 * @param pt Ptype to allocate value to
	 * @return POM_OK on success, POM_ERR on failure.
	 */
	int (*cleanup) (struct ptype* pt);

	/// Pointer to the parse function
	/**
	 * This function should parse the value provided in val and store in in the ptype.
	 * @param pt Ptype to store value to
	 * @param val Value to parse
	 * @return POM_OK on success, POM_ERR on failure.
	 */
	int (*parse_val) (struct ptype *pt, char *val);

	/// Pointer to the print function
	/**
	 * This function should store a string representation of the ptype value into val.
	 * @param pt Ptype to display value from
	 * @param val Buffer to store value to
	 * @param size Size of the buffer
	 * @return Number of bytes stored in the buffer
	 */
	int (*print_val) (struct ptype *pt, char *val, size_t size);

	/// Pointer to the compare function
	/**
	 * Do a logical comparison and return the result. Comparison si done this way : a op b.
	 * @param op Operation to perform for comparison
	 * @param val_a First value from the ptype
	 * @param val_b Second value from the ptype
	 * @return Result of the comparison. True or false.
	 */
	int (*compare_val) (int op, void* val_a, void* val_b);

	/// Pointer to the serialize function
	/**
	 * Serialize the value to store in the config.
	 * @param pt Ptype to serialize value from
	 * @param val Buffer to store the serialized value
	 * @param size size of the buffer
	 * @return POM_OK on success, POM_ERR on failure.
	 */
	int (*serialize) (struct ptype *pt, char *val, size_t size);

	/// Pointer to the unserialization function
	/**
	 * This function will initialize the value previously serialized with the above function.
	 * @param pt Ptype to store the unserialized value to
	 * @param val String representation of the serialized value
	 * @return POM_OK on success, POM_ERR on failure.
	 */
	int (*unserialize) (struct ptype *pt, char *val);

	/// Pointer to the copy function
	/**
	 * This function will copy the value of a ptype into another.
	 * @param dst Ptype to store the value to
	 * @param src Ptype to copy the value from
	 * @return POM_OK on success, POM_ERR on failure.
	 */
	int (*copy) (struct ptype *dst, struct ptype *src);


};

// Full decl is private
struct ptype_reg;

/// Register a new ptype.
int ptype_register(struct ptype_reg_info *reg, struct mod_reg *mod);

#endif
