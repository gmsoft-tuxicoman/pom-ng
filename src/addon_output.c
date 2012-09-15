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

#include "addon.h"
#include "addon_output.h"

struct addon_output *addon_output_head = NULL;

static int addon_output_gc(lua_State *L) {
	struct output_reg_info *output_reg = lua_touserdata(L, 1);
	if (output_reg)
		free(output_reg->name);
	return 0;
}

int addon_output_lua_register(lua_State *L) {
	struct luaL_Reg l[] = {
		{ "output_register", addon_output_register },
		{ 0 }
	};

	luaL_newmetatable(L, ADDON_OUTPUT_METATABLE);
	lua_pushstring(L, "__gc");
	lua_pushcfunction(L, addon_output_gc);
	lua_settable(L, -3);

	luaL_register(L, ADDON_POM_LIB, l);

	return POM_OK;
}

int addon_output_register(lua_State *L) {

	struct addon *addon = addon_get_from_registry(L);

	// Get the name of the output
	lua_pushliteral(L, "name");
	lua_gettable(L, 1);
	const char *name = lua_tostring(L, -1);

	pomlog(POMLOG_DEBUG "Registering addon output %s ...", name);

	struct output_reg_info *output_info = lua_newuserdata(L, sizeof(struct output_reg_info));
	memset(output_info, 0, sizeof(struct output_reg_info));
	
	output_info->name = strdup(name);
	if (!output_info->name)
		addon_oom(L, strlen(name) + 1);

	luaL_getmetatable(L, ADDON_OUTPUT_METATABLE);
	lua_setmetatable(L, -2);

	output_info->api_ver = OUTPUT_API_VER;
	output_info->mod = addon->mod;
	output_info->init = addon_output_init;
	output_info->open = addon_output_open;
	output_info->close = addon_output_close;
	output_info->cleanup = addon_output_cleanup;

	if (output_register(output_info) != POM_OK)
		luaL_error(L, "Error while registering addon input %s", name);

	// Save our template in the registry
	lua_pushlightuserdata(L, output_info);
	lua_pushvalue(L, 1);
	lua_settable(L, LUA_REGISTRYINDEX);

	pomlog(POMLOG_DEBUG "Registered addon output %s", name);

	return 0;
}

int addon_output_init(struct output *o) {

	struct addon *addon = o->info->reg_info->mod->priv;

	struct addon_output_priv *p = malloc(sizeof(struct addon_output_priv));
	if (!p) {
		pom_oom(sizeof(struct addon_output_priv));
		return POM_ERR;
	}
	memset(p, 0, sizeof(struct addon_output_priv));

	o->priv = p;

	p->L = lua_newthread(addon->L);

	if (!p->L) {
		pomlog(POMLOG_ERR "Error while creating new lua state for output %s", o->info->reg_info->name);
		free(p);
		return POM_ERR;
	}

	// Create a new global table for this thread to avoid memory corruption
	lua_newtable(p->L);
	// Create a new metatable to 'inherit' the main thread global
	lua_newtable(p->L);
	lua_pushliteral(p->L, "__index");
	lua_pushvalue(p->L, LUA_GLOBALSINDEX);
	lua_settable(p->L, -3);
	// Set the metatable to the new global table
	lua_setmetatable(p->L, -2);
	// Replace the old table
	lua_replace(p->L, LUA_GLOBALSINDEX);


	// Create a new instance of the class
	lua_pushlightuserdata(p->L, o);
	lua_newtable(p->L);

	// Do the inheritence
	lua_newtable(p->L);
	lua_pushliteral(p->L, "__index");
	lua_pushlightuserdata(p->L, o->info->reg_info);
	lua_gettable(p->L, LUA_REGISTRYINDEX);
	lua_settable(p->L, -3);
	lua_setmetatable(p->L, -2);

	// Add the new instance in the registry
	lua_settable(p->L, LUA_REGISTRYINDEX);
	
	pomlog(POMLOG_DEBUG "Output test created");

	return POM_OK;
}

int addon_output_cleanup(struct output *o) {
	
	struct addon_output_priv *p = o->priv;

	lua_pushlightuserdata(p->L, o);
	lua_pushnil(p->L);
	lua_settable(p->L, LUA_REGISTRYINDEX);

	free(p);
	return POM_OK;
}

int addon_output_open(struct output *o) {

	struct addon_output_priv *p = o->priv;
	return addon_instance_call(p->L, "open", o);
}

int addon_output_close(struct output *o) {

	struct addon_output_priv *p = o->priv;
	return addon_instance_call(p->L, "close", o);
}

