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

#ifndef __POM_NG_MODULES_H__
#define __POM_NG_MODULES_H__

// Will be used later once the API is stable
#define MOD_API_VER 1

#include <pom-ng/base.h>

// Full decl is private
struct mod_reg;

struct mod_reg_info {
	
	unsigned int api_ver;
	int (*register_func)(struct mod_reg *reg);
	int (*unregister_func)(void);
	char *dependencies;

};

#endif
