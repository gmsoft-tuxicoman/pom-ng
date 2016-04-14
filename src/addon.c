/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2012-2013 Guy Martin <gmsoft@tuxicoman.be>
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

#include "addon_event.h"
#include "addon_output.h"
#include "addon_plugin.h"
#include "addon_pload.h"
#include "addon_data.h"

#include <dirent.h>
#include <lualib.h>

#include <pom-ng/dns.h>


static struct addon *addon_head = NULL;

int addon_init() {

	// Load all the scripts
	
	DIR *d;
	d = opendir(ADDON_DIR);
	if (!d) {
		pomlog(POMLOG_INFO "Could not open addon directory %s for browsing : %s", ADDON_DIR, pom_strerror(errno));
		pomlog(POMLOG_INFO "You might want to install addons.", ADDON_DIR, pom_strerror(errno));
		closedir(d);
		return POM_OK;
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
				continue;
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

	return POM_ERR;
}

int addon_mod_register(struct mod_reg *mod) {

	struct addon *addon = mod->priv;
	addon->mod = mod;

	// Register all declared objects
	addon_output_register_all(addon);

	// Add the addon structure in the registry to store it
	lua_pushstring(addon->L, ADDON_REG_REGISTRY_KEY);
	lua_pushlightuserdata(addon->L, addon);
	lua_settable(addon->L, LUA_REGISTRYINDEX);

	addon->next = addon_head;
	if (addon->next)
		addon->next->prev = addon;
	addon_head = addon;

	return POM_OK;

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
	addon_lua_register(L);
	addon_event_lua_register(L);
	addon_output_lua_register(L);
	addon_plugin_lua_register(L);
	addon_pload_lua_register(L);
	addon_data_lua_register(L);

	// Set the path for addon libs
	lua_getglobal(L, "package");
	lua_pushliteral(L, ADDON_LIBS_PATH);
	lua_setfield(L, -2, "path");

	// Load the chunk
	if (luaL_loadfile(L, file)) {
		pomlog(POMLOG_ERR "Could not load file %s : %s", file, lua_tostring(L, -1));
		goto err;
	}

	// Run the lua file
	if (addon_pcall(L, 0, 0) != POM_OK)
		goto err;
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


	return POM_OK;
}

void addon_lua_register(lua_State *L) {
	struct luaL_Reg l[] = {
		{ "log", addon_log },
		{ 0 }
	};
	addon_pomlib_register(L, NULL, l);

	// Register the POMLOG_* variables
	lua_pushinteger(L, 1);
	lua_setglobal(L, "POMLOG_ERR");
	//lua_setfield(L, LUA_GLOBALSINDEX, "POMLOG_ERR");

	lua_pushinteger(L, 2);
	lua_setglobal(L, "POMLOG_WARN");
	//lua_setfield(L, LUA_GLOBALSINDEX, "POMLOG_WARN");

	lua_pushinteger(L, 3);
	lua_setglobal(L, "POMLOG_INFO");
	//lua_setfield(L, LUA_GLOBALSINDEX, "POMLOG_INFO");

	lua_pushinteger(L, 4);
	lua_setglobal(L, "POMLOG_DEBUG");
	//lua_setfield(L, LUA_GLOBALSINDEX, "POMLOG_DEBUG");

	// Replace print() by our logging function
	
	lua_pushcfunction(L, addon_log);
	lua_setglobal(L, "print");
	//lua_setfield(L, LUA_GLOBALSINDEX, "print");

	struct luaL_Reg dns_l[] = {
		{ "forward_lookup", addon_dns_forward_lookup },
		{ "reverse_lookup", addon_dns_reverse_lookup },
		{ 0 }
	};
	addon_pomlib_register(L, "dns", dns_l);

}

struct addon *addon_get_from_registry(lua_State *L) {

	lua_pushstring(L, ADDON_REG_REGISTRY_KEY);
	lua_gettable(L, LUA_REGISTRYINDEX);
	struct addon *tmp = lua_touserdata(L, -1);
	return tmp;
}

int addon_pcall(lua_State *L, int nargs, int nresults) {

	if (!lua_isfunction(L, -(nargs + 1))) {
		pomlog(POMLOG_ERR "Internal error : Trying to call something that is not a function");
		return POM_ERR;
	}

	int res = lua_pcall(L, nargs, nresults, 0);

	if (!res)
		return POM_OK;


	const char *err_str_lua = lua_tostring(L, -1);
	lua_pop(L, 1); // Remove the error message
	const char *err_str = "Unknown error";

	switch (res) {
		case LUA_ERRRUN:
			err_str = "Error while calling lua";
			break;
		case LUA_ERRMEM:
			err_str = "Not enough memory to lua";
			break;
		case LUA_ERRERR:
			err_str = "Error while running the error handler";
			break;
	}

	pomlog(POMLOG_ERR "Error : %s : %s", err_str, err_str_lua);
	
	return POM_OK;
}

void addon_pomlib_register(lua_State *L, const char *sub, luaL_Reg *l) {

	lua_getglobal(L, ADDON_POM_LIB); // Stack : pom (or nil)

	if (lua_isnil(L, -1)) {
		lua_pop(L, 1); // Stack : <empty>
		lua_newtable(L); // Stack : pom
		lua_pushvalue(L, -1); // Stack : pom, pom
		lua_setglobal(L, ADDON_POM_LIB); // Stack : pom
	}

	if (sub) {
		lua_getfield(L, -1, sub); // Stack : pom, sub (or nil)
		if (lua_isnil(L, -1)) { // Stack : pom, nil
			lua_pop(L, 1); // Stack : pom
			lua_newtable(L); // Stack : pom, sub
			lua_pushvalue(L, -1); // Stack : pom, sub, sub
			lua_setfield(L, -3, sub); // Stack : pom, sub
		}
	}
	
	int i;
	for (i = 0; l[i].name; i++) {
		lua_pushcfunction(L, l[i].func);
		lua_setfield(L, -2, l[i].name);
	}

}

int addon_log(lua_State *L) {

	// Get the filename
	lua_Debug ar;
	lua_getstack(L, 1, &ar);
	lua_getinfo(L, "S", &ar);

	// Get the log line

	// Check if first arg is integer
	if (lua_isnumber(L, 1)) {
		const char *line = luaL_checkstring(L, 2);
		int level = lua_tointeger(L, 1);
		switch (level) {
			case 1:
				pomlog_internal(ar.source, POMLOG_ERR "%s", line);
				break;
			case 2:
				pomlog_internal(ar.source, POMLOG_WARN "%s", line);
				break;
			case 3:
				pomlog_internal(ar.source, POMLOG_INFO "%s", line);
				break;
			case 4:
				pomlog_internal(ar.source, POMLOG_DEBUG "%s", line);
				break;
		}

		return 0;
	}


	const char *line = luaL_checkstring(L, 1);
	pomlog_internal(ar.source, "%s", line);

	return 0;
}

int addon_dns_forward_lookup(lua_State *L) {

	const char *name = luaL_checkstring(L, 1);

	char *out = dns_forward_lookup(name);
	if (out) {
		lua_pushstring(L, out);
		free(out);
	} else {
		lua_pushnil(L);
	}

	return 1;
}

int addon_dns_reverse_lookup(lua_State *L) {

	const char *name = luaL_checkstring(L, 1);

	char *out = dns_reverse_lookup(name);
	if (out) {
		lua_pushstring(L, out);
		free(out);
	} else {
		lua_pushnil(L);
	}

	return 1;
}

