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


#ifndef __ADDON_H__
#define __ADDON_H__

#include <lua.h>
#include <lauxlib.h>
#include "mod.h"

#define ADDON_REGISTRY "addon"

#define ADDON_DIR DATAROOT "/addons/"
#define ADDON_EXT ".lua"
#define ADDON_REGISTER_FUNC_SUFFIX "_register"
#define ADDON_POM_LIB "pom"
#define ADDON_REG_REGISTRY_KEY "addon_reg"

struct addon {

	char *name;
	char *filename;
	lua_State *L;
	struct mod_reg_info mod_info;
	struct mod_reg *mod;

	struct addon *prev, *next;
};

int addon_init();
int addon_mod_register(struct mod_reg *mod);
lua_State *addon_create_state(char *file);
int addon_cleanup();

int addon_error(lua_State *L);

struct addon *addon_get_from_registry(lua_State *L);

int addon_instance_call(lua_State *L, const char *function, void *instance);


#define addon_oom(L, x) luaL_error((L), "Not enough memory to allocate %u bytes", (x))

#endif
