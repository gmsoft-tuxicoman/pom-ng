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
#include "registry.h"

#include "addon_event.h"
#include "addon_output.h"

#include <dirent.h>
#include <lualib.h>



static struct registry_class *addon_registry_class = NULL;
static struct addon *addon_head = NULL;

int addon_init() {

	addon_registry_class = registry_add_class(ADDON_REGISTRY);
	if (!addon_registry_class)
		return POM_ERR;

	// Load all the scripts
	
	DIR *d;
	d = opendir(ADDON_DIR);
	if (!d) {
		pomlog(POMLOG_ERR "Could not open addon directory %s for browsing : %s", ADDON_DIR, pom_strerror(errno));
		goto err;
	}

	struct dirent tmp, *dp;
	while (1) {
		if (readdir_r(d, &tmp, &dp) < 0) {
			pomlog(POMLOG_ERR "Error while reading directory entry : %s", pom_strerror(errno));
			goto err;
		}

		if (!dp) // EOF
			break;

		size_t len = strlen(dp->d_name);
		if (len < strlen(ADDON_EXT) + 1)
			continue;

		size_t name_len = strlen(dp->d_name) - strlen(ADDON_EXT);
		if (!strcmp(dp->d_name + name_len, ADDON_EXT)) {
			pomlog(POMLOG_DEBUG "Loading %s", dp->d_name);

			struct addon *addon = malloc(sizeof(struct addon));
			if (!addon) {
				pom_oom(sizeof(struct addon));
				goto err;
			}
			memset(addon, 0, sizeof(struct addon));

			addon->name = strdup(dp->d_name);
			if (!addon->name) {
				free(addon);
				pom_oom(strlen(dp->d_name) + 1);
				goto err;
			}

			addon->filename = malloc(strlen(ADDON_DIR) + strlen(dp->d_name) + 1);
			if (!addon->filename) {
				free(addon->name);
				free(addon);
				pom_oom(strlen(ADDON_DIR) + strlen(dp->d_name) + 1);
				goto err;
			}
			strcpy(addon->filename, ADDON_DIR);
			strcat(addon->filename, dp->d_name);

			addon->L = addon_create_state(addon->filename);
			if (!addon->L) {
				free(addon->filename);
				free(addon->name);
				free(addon);
				goto err;
			}

			// TODO fetch dependencies from a global variable

			addon->mod_info.api_ver = MOD_API_VER;
			addon->mod_info.register_func = addon_mod_register;

			struct mod_reg *mod = mod_register(dp->d_name, &addon->mod_info, addon);
			if (!mod) {
				if (addon->prev)
					addon->prev->next = addon->next;
				if (addon->next)
					addon->next->prev = addon->prev;

				if (addon_head == addon)
					addon_head = addon->next;
				
				lua_close(addon->L);
				free(addon->filename);
				free(addon->name);
				free(addon);
				pomlog("Failed to load addon \"%s\"", dp->d_name);
			} else {
				pomlog("Loaded addon : %s", dp->d_name);
			}
		
		}
	}

	closedir(d);

	return POM_OK;

err:

	if (d)
		closedir(d);

	registry_remove_class(addon_registry_class);
	addon_registry_class = NULL;
	return POM_ERR;
}

int addon_mod_register(struct mod_reg *mod) {

	struct addon *addon = mod->priv;
	addon->mod = mod;

	char *dot = strrchr(addon->name, '.');
	size_t name_len = strlen(addon->name);
	if (dot)
		name_len = dot - addon->name;
	
	size_t reg_func_len = name_len + strlen(ADDON_REGISTER_FUNC_SUFFIX) + 1;
	char *reg_func_name = malloc(reg_func_len);
	if (!reg_func_name) {
		pom_oom(reg_func_len);
		return POM_ERR;
		
	}

	memset(reg_func_name, 0, reg_func_len);
	memcpy(reg_func_name, addon->name, name_len);
	strcat(reg_func_name, ADDON_REGISTER_FUNC_SUFFIX);

	// Add the addon_reg structure in the registry
	lua_pushstring(addon->L, ADDON_REG_REGISTRY_KEY);
	lua_pushlightuserdata(addon->L, addon);
	lua_settable(addon->L, LUA_REGISTRYINDEX);

	// Add our error handler
	lua_pushcfunction(addon->L, addon_error);

	// Call the register function
	lua_getglobal(addon->L, reg_func_name);
	if (!lua_isfunction(addon->L, -1)) {
		pomlog(POMLOG_ERR "Failed load addon %s. Register function %s() not found.", addon->name, reg_func_name);
		free(reg_func_name);
		return POM_ERR;
	}
	free(reg_func_name);

	switch (lua_pcall(addon->L, 0, 0, -2)) {
		case LUA_ERRRUN:
			pomlog(POMLOG_ERR "Error while registering addon \"%s\"", addon->name);
			goto err;
		case LUA_ERRMEM:
			pomlog(POMLOG_ERR "Not enough memory to register addon \"%s\"", addon->name);
			goto err;
		case LUA_ERRERR:
			pomlog(POMLOG_ERR "Error while running the error handler while registering addon \"%s\"", addon->name);
			goto err;
	}
	
	addon->next = addon_head;
	if (addon->next)
		addon->next->prev = addon;
	addon_head = addon;

	return POM_OK;

err:
	// Remove the addon from the lua registry
	lua_pushstring(addon->L, ADDON_REG_REGISTRY_KEY);
	lua_pushnil(addon->L);
	lua_settable(addon->L, LUA_REGISTRYINDEX);

	return POM_ERR;

}

lua_State *addon_create_state(char *file) {

	lua_State *L = luaL_newstate();
	if (!L) {
		pomlog(POMLOG_ERR "Error while creating lua state");
		goto err;
	}

	// Register standard libraries
	luaL_openlibs(L);

	// Register our own
	addon_event_lua_register(L);
	addon_output_lua_register(L);

	// Add our error handler
	lua_pushcfunction(L, addon_error);

	// Load the chunk
	if (luaL_loadfile(L, file)) {
		pomlog(POMLOG_ERR "Could not load file %s : %s", file, lua_tostring(L, -1));
		goto err;
	}

	// Run the lua file
	switch (lua_pcall(L, 0, 0, -2)) {
		case LUA_ERRRUN:
			pomlog(POMLOG_ERR "Error while loading addon \"%s\"", file);
			goto err;
		case LUA_ERRMEM:
			pomlog(POMLOG_ERR "Not enough memory to load addon \"%s\"", file);
			goto err;
		case LUA_ERRERR:
			pomlog(POMLOG_ERR "Error while running the error handler for addon \"%s\"", file);
			goto err;
	}

	return L;

err:
	lua_close(L);
	return NULL;
}

int addon_cleanup() {


	while (addon_head) {
		struct addon *tmp = addon_head;
		addon_head = tmp->next;

		mod_unload(tmp->mod);

		lua_close(tmp->L);
		free(tmp->name);
		free(tmp->filename);
		free(tmp);
	}

	if (addon_registry_class)
		registry_remove_class(addon_registry_class);
	addon_registry_class = NULL;


	return POM_OK;
}


int addon_error(lua_State *L) {
	const char *err_str = luaL_checkstring(L, -1);
	pomlog(POMLOG_ERR "%s", err_str);
	return 0;
}

struct addon *addon_get_from_registry(lua_State *L) {

	lua_pushstring(L, ADDON_REG_REGISTRY_KEY);
	lua_gettable(L, LUA_REGISTRYINDEX);
	struct addon *tmp = lua_touserdata(L, -1);
	return tmp;
}


int addon_get_instance(struct addon_instance_priv *p) {

	// Fetch the corresponding instance
	lua_pushlightuserdata(p->L, p);
	lua_gettable(p->L, LUA_REGISTRYINDEX);
	if (!lua_istable(p->L, -1)) {
		pomlog(POMLOG_ERR, "Could not find instance %p", p->instance);
		return POM_ERR;
	}
	return POM_OK;
}

int addon_call(lua_State *L, const char *function, int nargs) {
	
	// We assume the instance table is at the top of the stack followed by arguments

	// Push the error handler
	lua_pushcfunction(L, addon_error);

	// Fetch the open function
	lua_pushstring(L, function);
	lua_gettable(L, -(nargs + 3));

	// Add self
	lua_pushvalue(L, -(nargs + 3));

	// Put the arguments in front
	int i;
	for (i = 0; i < nargs; i++) {
		lua_pushvalue(L, -(nargs + 3));
		lua_remove(L, -(nargs + 4));
	}

	switch (lua_pcall(L, nargs + 1, 0, -(nargs + 3))) {
		case LUA_ERRRUN:
			pomlog(POMLOG_ERR "Error while calling function \"%s\"", function);
			return POM_ERR;
		case LUA_ERRMEM:
			pomlog(POMLOG_ERR "Not enough memory to call function \"%s\"", function);
			return POM_ERR;
		case LUA_ERRERR:
			pomlog(POMLOG_ERR "Error while running the error handler for function \"%s\"", function);
			return POM_ERR;
	}
	
	return POM_OK;
}

