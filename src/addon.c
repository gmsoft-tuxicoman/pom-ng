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

#include <dirent.h>
#include <lualib.h>



static struct registry_class *addon_registry_class = NULL;
static struct addon_reg *addon_reg_head = NULL;

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


	struct addon_reg *reg = NULL;
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
			reg = malloc(sizeof(struct addon_reg));
			if (!reg) {
				pom_oom(sizeof(struct addon_reg));
				goto err;
			}
			memset(reg, 0, sizeof(struct addon_reg));
			
			reg->name = malloc(name_len + 1);
			if (!reg->name) {
				pom_oom(name_len + 1);
				goto err;
			}
			memcpy(reg->name, dp->d_name, name_len);
			reg->name[name_len] = 0;

			reg->filename = malloc(strlen(ADDON_DIR) + strlen(dp->d_name) + 1);
			if (!reg->filename) {
				pom_oom(strlen(ADDON_DIR) + strlen(dp->d_name) + 1);
				goto err;
			}
			strcpy(reg->filename, ADDON_DIR);
			strcat(reg->filename, dp->d_name);

			reg->L = luaL_newstate();
			if (!reg->L) {
				pomlog(POMLOG_ERR "Error while creating lua state");
				goto err;
			}

			// Register standard libraries
			luaL_openlibs(reg->L);

			// Register our own
			addon_event_lua_register(reg->L);

			// Add our error handler
			lua_pushcfunction(reg->L, addon_error);

			// Load the chunk
			if (luaL_loadfile(reg->L, reg->filename)) {
				pomlog(POMLOG_ERR "Could not load file %s : %s", dp->d_name, lua_tostring(reg->L, -1));
				goto err;
			}

			// Run the lua file
			switch (lua_pcall(reg->L, 0, 0, -2)) {
				case LUA_ERRRUN:
					pomlog(POMLOG_ERR "Error while loading addon \"%s\"", dp->d_name);
					goto failed;
				case LUA_ERRMEM:
					pomlog(POMLOG_ERR "Not enough memory to load addon \"%s\"", dp->d_name);
					goto err;
				case LUA_ERRERR:
					pomlog(POMLOG_ERR "Error while running the error handler for addon \"%s\"", dp->d_name);
					goto err;
			}

			/*
			size_t reg_func_len = strlen(reg->name) + strlen(ADDON_REGISTER_FUNC_SUFFIX) + 1;
			char *reg_func_name = malloc(reg_func_len);
			if (!reg_func_name) {
				pom_oom(reg_func_len);
				goto err;
			}
			strcpy(reg_func_name, reg->name);
			strcat(reg_func_name, ADDON_REGISTER_FUNC_SUFFIX);

			// Call the register function
			lua_getglobal(reg->L, reg_func_name);
			if (lua_isnil(reg->L, -1)) {
				pomlog(POMLOG_ERR "Failed load addon %s. Register function %s() not found.", reg->name, reg_func_name);
				free(reg_func_name);
				goto failed;
			}
			free(reg_func_name);

			lua_pcall(reg->L, 0, 0, 0);
			*/

			reg->next = addon_reg_head;
			if (reg->next)
				reg->next->prev = reg;
			addon_reg_head = reg;
			reg = NULL;

			pomlog("Loaded addon : %s", dp->d_name);
		}
		
		continue;
		failed:

		if (reg->name)
			free(reg->name);
		if (reg->filename)
			free(reg->filename);
		if (reg->L)
			lua_close(reg->L);
		free(reg);

	}

	closedir(d);

	return POM_OK;

err:

	if (reg) {
		if (reg->name)
			free(reg->name);
		if (reg->filename)
			free(reg->filename);
		if (reg->L)
			lua_close(reg->L);
		free(reg);
	}

	if (d)
		closedir(d);

	registry_remove_class(addon_registry_class);
	addon_registry_class = NULL;
	return POM_ERR;
}

int addon_cleanup() {


	while (addon_reg_head) {
		struct addon_reg *tmp = addon_reg_head;
		addon_reg_head = tmp->next;

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

