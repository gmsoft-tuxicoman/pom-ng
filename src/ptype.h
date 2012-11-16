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

#include <stdint.h>

/// Maximum number of registered
#define MAX_PTYPE 256

/// Default size for first allocation in ptype_print_val_alloc()
#define DEFAULT_PRINT_VAL_ALLOC_BUFF 64


struct ptype_reg {

	struct ptype_reg_info *info;
	struct mod_reg *module;

	struct ptype_reg *next, *prev;
	

};


void ptype_reg_lock(int write);
void ptype_reg_unlock();

size_t ptype_get_value_size(struct ptype *pt);
#endif
