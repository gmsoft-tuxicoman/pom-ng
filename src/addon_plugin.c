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
#include "addon_pload.h"
#include "addon_output.h"
#include "addon_event.h"
#include "analyzer.h"

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
		struct addon_param *tmp = a->params;
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
	if (a->reg->type != addon_plugin_type_event)
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
	if (a->reg->type != addon_plugin_type_event)
		luaL_error(L, "Plugin %s cannot listen to events", a->reg->name);

	const char *evt_name = luaL_checkstring(L, 2);

	struct event_reg *evt = event_find(evt_name);
	if (!evt)
		luaL_error(L, "Event %s does not exists", evt_name);
	
	if (event_listener_unregister(evt, a->priv) != POM_OK)
		luaL_error(L, "Error while unregistering event listener");

	return 0;

}

static int addon_plugin_event_process(lua_State *L) {

	// Args should be :
	// 1) self
	// 2) event object
	
	struct addon_plugin *a = luaL_checkudata(L, 1, ADDON_PLUGIN_METATABLE);
	if (a->reg->type != addon_plugin_type_event)
		luaL_error(L, "Plugin %s cannot listen to events", a->reg->name);

	struct addon_event *e = luaL_checkudata(L, 2, ADDON_EVENT_METATABLE);

	if (event_add_listener(e->evt, a->priv, a->reg->event_begin, a->reg->event_end) != POM_OK)
		luaL_error(L, "Error while adding event to plugin");

	return 0;
}

static int addon_plugin_param_get(lua_State *L) {

	struct addon_plugin *a = luaL_checkudata(L, 1, ADDON_PLUGIN_METATABLE);

	const char *name = luaL_checkstring(L, 2);

	struct addon_param *tmp;
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

	struct addon_param *tmp;
	for (tmp = a->params; tmp && strcmp(tmp->name, name); tmp = tmp->next);
	
	if (!tmp)
		luaL_error(L, "No such parameter %s to plugin %s", name, a->reg->name);

	addon_ptype_parse(L, 3, tmp->value);

	return 0;
}

static int addon_plugin_pload_process(lua_State *L) {


	// Args should be :
	// 1) self
	// 2) pload
	// 3) parameters

	struct addon_plugin *a = luaL_checkudata(L, 1, ADDON_PLUGIN_METATABLE);

	if (a->reg->type != addon_plugin_type_pload)
		luaL_error(L, "Plugin %s cannot process payloads", a->reg->name);

	// Get the output pload_instance
	struct analyzer_pload_instance* output_pi = addon_pload_get_instance(L, 2);

	if (!lua_istable(L, 3))
		luaL_error(L, "Third argument must be parameter table");

	// Create a new instance for our pload plugin
	struct addon_output_pload_plugin *pload_plugin = addon_output_pload_plugin_alloc(a->reg, output_pi->o, output_pi->pload);
	if (!pload_plugin)
		return 0;

	// Allocate the parameters
	size_t params_size = sizeof(struct ptype *) * (a->reg->pload_param_count + 1);
	struct ptype **params = malloc(params_size);
	if (!params) {
		free(pload_plugin);
		addon_oom(L, params_size);
	}

	memset(params, 0, params_size);

	int i;
	for (i = 0; i < a->reg->pload_param_count; i++) {
		params[i] = ptype_alloc(a->reg->pload_params[i].ptype_type);
		if (!params[i]) {
			free(pload_plugin);
			goto err;
		}

		lua_pushstring(L, a->reg->pload_params[i].name);
		lua_gettable(L, 3);
		if (lua_isnil(L, -1)) {
			if (ptype_parse_val(params[i], a->reg->pload_params[i].defval) != POM_OK) {
				free(pload_plugin);
				pomlog(POMLOG_ERR "Error while parsing default value %s", a->reg->pload_params[i].defval);
				goto err;
			}
		} else {
			addon_ptype_parse(L, -1, params[i]);
		}

	}

	if (a->reg->pload_open(&pload_plugin->pi , a->priv, params) != POM_OK) {
		pomlog(POMLOG_WARN "Error while opening pload for plugin %s", a->reg->name);
		free(pload_plugin);
		goto err;
	}

	// Add the pload_instance to the output
	struct addon_output_pload_priv *output_pi_priv = output_pi->priv;
	pload_plugin->next = output_pi_priv->plugins;
	if (pload_plugin->next)
		pload_plugin->next->prev = pload_plugin->prev;
	output_pi_priv->plugins = pload_plugin;

err:

	for (i = 0; params[i]; i++)
		ptype_cleanup(params[i]);
	free(params);

	return 0;
}

static int addon_plugin_metatable(lua_State *L) {

	struct addon_plugin *a = luaL_checkudata(L, 1, ADDON_PLUGIN_METATABLE);	
	const char *key = luaL_checkstring(L, 2);

	if (!strcmp(key, "open")) {
		lua_pushcfunction(L, addon_plugin_open);
	} else if (!strcmp(key, "close")) {
		lua_pushcfunction(L, addon_plugin_close);
	} else if (!strcmp(key, "param_get")) {
		lua_pushcfunction(L, addon_plugin_param_get);
	} else if (!strcmp(key, "param_set")) {
		lua_pushcfunction(L, addon_plugin_param_set);
	} else if (!strcmp(key, "event_listen_start")) {
		if (a->reg->type != addon_plugin_type_event)
			return 0;
		lua_pushcfunction(L, addon_plugin_event_listen_start);
	} else if (!strcmp(key, "event_listen_stop")) {
		if (a->reg->type != addon_plugin_type_event)
			return 0;
		lua_pushcfunction(L, addon_plugin_event_listen_stop);
	} else if (!strcmp(key, "event_process")) {
		if (a->reg->type != addon_plugin_type_event)
			return 0;
		lua_pushcfunction(L, addon_plugin_event_process);
	} else if (!strcmp(key, "pload_process")) {
		if (a->reg->type != addon_plugin_type_pload)
			return 0;
		lua_pushcfunction(L, addon_plugin_pload_process);
	} else {
		return 0;
	}

	return 1;
}

int addon_plugin_lua_register(lua_State *L) {

	struct luaL_Reg l[] = {
		{ "new", addon_plugin_new },
		{ 0 }
	};

	addon_pomlib_register(L, "plugin", l);

	struct luaL_Reg m[] = {
		{ "__index", addon_plugin_metatable },
		{ "__gc", addon_plugin_gc },
		{ 0 }
	};

	luaL_newmetatable(L, ADDON_PLUGIN_METATABLE);

	// Register the functions
	luaL_register(L, NULL, m);

	return POM_OK;
}


int addon_plugin_event_register(struct addon_plugin_event_reg *reg_info) {

	struct addon_plugin_reg *reg = malloc(sizeof(struct addon_plugin_reg));
	if (!reg) {
		pom_oom(sizeof(struct addon_plugin_reg));
		return POM_ERR;
	}
	memset(reg, 0, sizeof(struct addon_plugin_reg));

	reg->name = reg_info->name;
	reg->mod = reg_info->mod;

	reg->init = reg_info->init;
	reg->cleanup = reg_info->cleanup;
	reg->open = reg_info->open;
	reg->close = reg_info->close;
	reg->event_begin = reg_info->event_begin;
	reg->event_end = reg_info->event_end;

	reg->type = addon_plugin_type_event;

	reg->next = addon_plugin_head;
	if (reg->next)
		reg->next->prev = reg;
	addon_plugin_head = reg;

	mod_refcount_inc(reg->mod);
	
	return POM_OK;
}

int addon_plugin_pload_register(struct addon_plugin_pload_reg *reg_info) {

	struct addon_plugin_reg *reg = malloc(sizeof(struct addon_plugin_reg));
	if (!reg) {
		pom_oom(sizeof(struct addon_plugin_reg));
		return POM_ERR;
	}
	memset(reg, 0, sizeof(struct addon_plugin_reg));

	reg->name = reg_info->name;
	reg->mod = reg_info->mod;

	reg->init = reg_info->init;
	reg->cleanup = reg_info->cleanup;
	reg->open = reg_info->open;
	reg->close = reg_info->close;
	reg->pload_open = reg_info->pload_open;
	reg->pload_write = reg_info->pload_write;
	reg->pload_close = reg_info->pload_close;

	reg->pload_params = reg_info->pload_params;

	reg->type = addon_plugin_type_pload;
	for (; reg_info->pload_params[reg->pload_param_count].name; reg->pload_param_count++);

	reg->next = addon_plugin_head;
	if (reg->next)
		reg->next->prev = reg;
	addon_plugin_head = reg;

	mod_refcount_inc(reg->mod);
	
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

	free(tmp);

	return POM_OK;
}

void addon_plugin_set_priv(struct addon_plugin *a, void *priv) {
	a->priv = priv;
}

int addon_plugin_add_param(struct addon_plugin *a, char *name, char *defval, struct ptype *value) {

	if (ptype_parse_val(value, defval) != POM_OK)
		return POM_ERR;

	struct addon_param *p = malloc(sizeof(struct addon_param));
	if (!p) {
		pom_oom(sizeof(struct addon_param));
		return POM_ERR;
	}
	memset(p, 0, sizeof(struct addon_param));

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

int addon_plugin_pload_write(struct addon_plugin_reg *addon_reg, void *pload_instance_priv, void *data, size_t len) {

	return addon_reg->pload_write(pload_instance_priv, data, len);
}

int addon_plugin_pload_close(struct addon_plugin_reg *addon_reg, void *pload_instance_priv) {

	return addon_reg->pload_close(pload_instance_priv);
}
