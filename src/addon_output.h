/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2012 Guy Martin <gmsoft@tuxicoman.be>
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


#ifndef __ADDON_OUTPUT_H__
#define __ADDON_OUTPUT_H__

#include <output.h>

#define ADDON_OUTPUT_METATABLE "addon.output"

struct addon_output {

	struct output_reg_info reg_info;

	struct addon_output *prev, *next;
};

struct addon_output_priv {

	lua_State *L; // Each output has it's own lua state

};

int addon_output_lua_register(lua_State *L);
int addon_output_register(lua_State *L);

int addon_output_init(struct output *o);
int addon_output_cleanup(struct output *o);


#endif


