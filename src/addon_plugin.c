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

#include "addon_plugin.h"
#include "addon_ptype.h"

struct addon_plugin_reg *addon_plugin_head = NULL;

static int addon_plugin_new(lua_State *L) {

	const char *name = luaL_checkstring(L, 1);
	
	struct addon_plugin_reg *tmp;
	for (tmp = addon_plugin_head; tmp && strcmp(tmp->name, name); tmp = tmp->next);
	if (!tmp)
		luaL_error(L, "Plugin %s not found", name);

	struct addon_plugin *p = lua_newuserdata(L, sizeof(struct addon_plugin));
	memset(p, 0, sizeof(struct addon_plugin));

	p->reg = tmp;

	luaL_getmetatable(L, ADDON_PLUGIN_METATABLE);
	lua_setmetatable(L, -2);

	if (tmp->init && tmp->init(p) != POM_OK)
		luaL_error(L, "Error while initializing plugin %s", name);

	return 1;

}

static int addon_plugin_open(lua_State *L) {

	struct addon_plugin *a = luaL_checkudata(L, 1, ADDON_PLUGIN_METATABLE);

	if (a->reg->open && a->reg->open(a->priv) != POM_OK)
		luaL_error(L, "Error while opening plugin %s", a->reg->name);

	a->open = 1;

	return 0;
}

static int addon_plugin_close(lua_State *L) {

	struct addon_plugin *a = luaL_checkudata(L, 1, ADDON_PLUGIN_METATABLE);

	if (a->reg->close && a->reg->close(a->priv) != POM_OK)
		luaL_error(L, "Error while closing plugin %s", a->reg->name);

	a->open = 0;

	return 0;
}

static int addon_plugin_gc(lua_State *L) {

	struct addon_plugin *a = luaL_checkudata(L, 1, ADDON_PLUGIN_METATABLE);

	if (a->reg->cleanup && a->reg->cleanup(a->priv) != POM_OK)
		luaL_error(L, "Error while cleaning up plugin %s", a->reg->name);

	while (a->params) {
		struct addon_plugin_param *tmp = a->params;
		a->params = tmp->next;
		free(tmp->name);
		free(tmp);
	}

	return 0;
}

static int addon_plugin_event_listen_start(lua_State *L) {
	
	// Args should be :
	// 1) self
	// 2) event name
	
	struct addon_plugin *a = luaL_checkudata(L, 1, ADDON_PLUGIN_METATABLE);
	if (!a->reg->event_begin && !a->reg->event_end)
		luaL_error(L, "Plugin %s cannot listen to events", a->reg->name);

	const char *evt_name = luaL_checkstring(L, 2);

	struct event_reg *evt = event_find(evt_name);
	if (!evt)
		luaL_error(L, "Event %s does not exists", evt_name);

	if (event_listener_register(evt, a->priv, a->reg->event_begin, a->reg->event_end) != POM_OK)
		luaL_error(L, "Error while listening to event %s", evt_name);

	return 0;
}

static int addon_plugin_event_listen_stop(lua_State *L) {

	// Args should be :
	// 1) self
	// 2) event name
	
	struct addon_plugin *a = luaL_checkudata(L, 1, ADDON_PLUGIN_METATABLE);

	const char *evt_name = luaL_checkstring(L, 2);

	struct event_reg *evt = event_find(evt_name);
	if (!evt)
		luaL_error(L, "Event %s does not exists", evt_name);
	
	if (event_listener_unregister(evt, a->priv) != POM_OK)
		luaL_error(L, "Error while unregistering event listener");

	return 0;

}

static int addon_plugin_param_get(lua_State *L) {

	struct addon_plugin *a = luaL_checkudata(L, 1, ADDON_PLUGIN_METATABLE);

	const char *name = luaL_checkstring(L, 2);

	struct addon_plugin_param *tmp;
	for (tmp = a->params; tmp && strcmp(tmp->name, name); tmp = tmp->next);
	
	if (!tmp)
		luaL_error(L, "No such parameter %s to plugin %s", name, a->reg->name);

	addon_ptype_push(L, tmp->value);

	return 1;
}

static int addon_plugin_param_set(lua_State *L) {

	struct addon_plugin *a = luaL_checkudata(L, 1, ADDON_PLUGIN_METATABLE);

	if (a->open)
		luaL_error(L, "Cannot change plugin parameter when plugin is open");

	const char *name = luaL_checkstring(L, 2);

	const char *value = luaL_checkstring(L, 3);

	struct addon_plugin_param *tmp;
	for (tmp = a->params; tmp && strcmp(tmp->name, name); tmp = tmp->next);
	
	if (!tmp)
		luaL_error(L, "No such parameter %s to plugin %s", name, a->reg->name);

	if (ptype_parse_val(tmp->value, (char*)value) != POM_OK)
		luaL_error(L, "Cannot parse value %s", value);

	return 0;
}

int addon_plugin_lua_register(lua_State *L) {

	struct luaL_Reg l[] = {
		{ "new", addon_plugin_new },
		{ 0 }
	};

	luaL_register(L, ADDON_PLUGIN_LIB, l);

	struct luaL_Reg m[] = {
		{ "open", addon_plugin_open },
		{ "close", addon_plugin_close },
		{ "__gc", addon_plugin_gc },

		{ "event_listen_start", addon_plugin_event_listen_start },
		{ "event_listen_stop", addon_plugin_event_listen_stop },

		{ "param_get", addon_plugin_param_get },
		{ "param_set", addon_plugin_param_set },

		{ 0 }
	};

	luaL_newmetatable(L, ADDON_PLUGIN_METATABLE);
	
	// Assign __index to itself
	lua_pushliteral(L, "__index");
	lua_pushvalue(L, -2);
	lua_settable(L, -3);

	// Register the functions
	luaL_register(L, NULL, m);

	return POM_OK;
}


int addon_plugin_register(struct addon_plugin_reg *reg_info) {

	reg_info->next = addon_plugin_head;
	if (reg_info->next)
		reg_info->next->prev = reg_info;
	addon_plugin_head = reg_info;

	mod_refcount_inc(reg_info->mod);
	
	return POM_OK;
}

int addon_plugin_unregister(char *name) {
	
	struct addon_plugin_reg *tmp;
	for (tmp = addon_plugin_head; tmp && strcmp(tmp->name, name); tmp = tmp->next);

	if (!tmp)
		return POM_OK;
	
	if (tmp->prev)
		tmp->prev->next = tmp->next;
	else
		addon_plugin_head = tmp->next;

	if (tmp->next)
		tmp->next->prev = tmp->prev;

	mod_refcount_dec(tmp->mod);

	return POM_OK;
}

void addon_plugin_set_priv(struct addon_plugin *a, void *priv) {
	a->priv = priv;
}

int addon_plugin_add_params(struct addon_plugin *a, char *name, char *defval, struct ptype *value) {

	if (ptype_parse_val(value, defval) != POM_OK)
		return POM_ERR;

	struct addon_plugin_param *p = malloc(sizeof(struct addon_plugin_param));
	if (!p) {
		pom_oom(sizeof(struct addon_plugin_param));
		return POM_ERR;
	}
	memset(p, 0, sizeof(struct addon_plugin_param));

	p->name = strdup(name);
	if (!p->name) {
		pom_oom(strlen(name) + 1);
		free(p);
		return POM_ERR;
	}

	p->value = value;

	p->next = a->params;
	a->params = p;

	return POM_OK;
}
