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
#define ADDON_LIBS_PATH ADDON_DIR "libs/?.lua"
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

struct addon_param {
	char *name;
	struct ptype *value;

	struct addon_param *next;
};

struct addon_instance_priv {

	lua_State *L; // Main lua state for the output
	pthread_mutex_t lock;
	void *instance;
	struct addon_param *params;

};

int addon_init();
int addon_mod_register(struct mod_reg *mod);
lua_State *addon_create_state(char *file);
int addon_cleanup();
void addon_lua_register(lua_State *L);

struct addon *addon_get_from_registry(lua_State *L);

int addon_get_instance(struct addon_instance_priv *p);
lua_State *addon_get_instance_and_thread(struct addon_instance_priv *p);
int addon_pcall(lua_State *L, int nargs, int nresults);

void addon_pomlib_register(lua_State *L, const char *sub, luaL_Reg *l);
int addon_log(lua_State *L);

#define addon_oom(L, x) luaL_error((L), "Not enough memory to allocate %u bytes", (x))

#endif
