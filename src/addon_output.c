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

#include <pom-ng/event.h>
#include "addon_event.h"

struct addon_output *addon_output_head = NULL;

// Called from lua to create a new output class
static int addon_output_new(lua_State *L) {

	luaL_checkstring(L, 1);

	// Create the new instance
	lua_newtable(L);

	// Assign the metatable
	luaL_getmetatable(L, ADDON_OUTPUT_METATABLE);
	lua_setmetatable(L, -2);

	// Set its name
	lua_pushliteral(L, "name");
	lua_pushvalue(L, 1);
	lua_settable(L, -3);

	// TODO make name read-only

	return 1;
}

// Called from lua to listen to a new event from an instance
static int addon_output_event_listen_start(lua_State *L) {
	
	// Args should be :
	// 1) self
	// 2) event name
	// 3) process_begin
	// 4) process_end
	
	// Find the event
	const char *evt_name = luaL_checkstring(L, 2);
	
	struct event_reg *evt = event_find(evt_name);
	if (!evt)
		luaL_error(L, "Event %s does not exists", evt_name);

	// Check which function we should register
	int (*process_begin) (struct event *evt, void *obj, struct proto_process_stack *stack, unsigned int stack_index) = NULL;
	int (*process_end) (struct event *evt, void *obj) = NULL;

	if (lua_isfunction(L, 3))
		process_begin = addon_event_process_begin;
	if (lua_isfunction(L, 4))
		process_end = addon_event_process_end;

	if (!process_begin && !process_end)
		luaL_error(L, "No processing function provided");

	// Get the output
	lua_pushliteral(L, "__priv");
	lua_gettable(L, 1);
	struct addon_instance_priv *p = lua_touserdata(L, -1);
	if (!p)
		luaL_error(L, "Error while finding the output pointer");

	if (event_listener_register(evt, p, process_begin, process_end) != POM_OK)
		luaL_error(L, "Error while listening to event %s", evt_name);

	// Add a table to self for the processing functions of this event
	lua_newtable(L);
	lua_pushlightuserdata(L, evt);
	lua_pushvalue(L, -2);
	lua_settable(L, 1);

	// Add the processing function
	if (process_begin) {
		lua_pushliteral(L, "begin");
		lua_pushvalue(L, 3);
		lua_settable(L, -3);
	}

	if (process_end) {
		lua_pushliteral(L, "end");
		lua_pushvalue(L, 4);
		lua_settable(L, -3);
	}

	pomlog(POMLOG_DEBUG "Output listening to event %s", evt_name);

	return 0;
}

// Called from lua to stop listening to a particular event
static int addon_output_event_listen_stop(lua_State *L) {
	// Args should be :
	// 1) self
	// 2) event name

	// Find the event
	const char *evt_name = luaL_checkstring(L, 2);

	struct event_reg *evt = event_find(evt_name);
	if (!evt)
		luaL_error(L, "Event %s does not exists", evt_name);

	// Get the output
	lua_pushliteral(L, "__priv");
	lua_gettable(L, 1);
	struct addon_instance_priv *p = lua_touserdata(L, -1);
	if (!p)
		luaL_error(L, "Error while finding the output pointer");
	
	if (event_listener_unregister(evt, p) != POM_OK)
		luaL_error(L, "Error while unregistering event listener");

	// Forget about listening to the event
	lua_pushlightuserdata(L, evt);
	lua_pushnil(L);
	lua_settable(L, 1);

	return 0;
}

// Garbage collector function for output instances
static int addon_output_gc(lua_State *L) {
	struct output_reg_info *output_reg = lua_touserdata(L, 1);
	if (output_reg)
		free(output_reg->name);
	return 0;
}

int addon_output_lua_register(lua_State *L) {
	struct luaL_Reg l[] = {
		{ "new", addon_output_new },
		{ "register", addon_output_register },
		{ 0 }
	};
	luaL_register(L, ADDON_POM_OUTPUT_LIB, l);

	struct luaL_Reg m[] = {
		{ "event_listen_start", addon_output_event_listen_start },
		{ "event_listen_stop", addon_output_event_listen_stop },
		{ 0 }
	};

	// Create the output metatable
	luaL_newmetatable(L, ADDON_OUTPUT_METATABLE);

	// Assign __index to itself
	lua_pushstring(L, "__index");
	lua_pushvalue(L, -2);
	lua_settable(L, -3);

	// Register the functions
	luaL_register(L, NULL, m);

	struct luaL_Reg m_reg[] = {
		{ "__gc", addon_output_gc },
		{ 0 }
	};
	
	// Create the output_reg metatable
	luaL_newmetatable(L, ADDON_OUTPUT_REG_METATABLE);
	luaL_register(L, NULL, m_reg);

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

	// Add the output_reg metatable
	luaL_getmetatable(L, ADDON_OUTPUT_REG_METATABLE);
	lua_setmetatable(L, -2);
	
	output_info->name = strdup(name);
	if (!output_info->name)
		addon_oom(L, strlen(name) + 1);

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

	lua_State *L = lua_newthread(addon->L);

	if (!L) {
		pomlog(POMLOG_ERR "Error while creating new lua state for output %s", o->info->reg_info->name);
		return POM_ERR;
	}

	// Create a new global table for this thread to avoid memory corruption
	lua_newtable(L);
	// Create a new metatable to 'inherit' the main thread global
	lua_newtable(L);
	lua_pushliteral(L, "__index");
	lua_pushvalue(L, LUA_GLOBALSINDEX);
	lua_settable(L, -3);
	// Set the metatable to the new global table
	lua_setmetatable(L, -2);
	// Replace the old table
	lua_replace(L, LUA_GLOBALSINDEX);


	// Create a new instance of the class
	lua_newtable(L);

	// Do the inheritence
	lua_newtable(L);
	lua_pushliteral(L, "__index");
	lua_pushlightuserdata(L, o->info->reg_info);
	lua_gettable(L, LUA_REGISTRYINDEX);
	lua_settable(L, -3);
	lua_setmetatable(L, -2);

	// Create the private data
	lua_pushliteral(L, "__priv");
	// TODO make __priv read-only
	struct addon_instance_priv *p = lua_newuserdata(L, sizeof(struct addon_instance_priv));
	memset(p, 0, sizeof(struct addon_instance_priv));
	o->priv = p;
	p->instance = o;
	p->L = L;
	lua_settable(L, -3);

	lua_pushlightuserdata(L, p);
	lua_pushvalue(L, -2);
	// Add the new instance in the registry
	lua_settable(L, LUA_REGISTRYINDEX);
	
	pomlog(POMLOG_DEBUG "Output %s created", o->name);

	return POM_OK;
}

int addon_output_cleanup(void *output_priv) {
	
	struct addon_instance_priv *p = output_priv;

	lua_pushlightuserdata(p->L, p);
	lua_pushnil(p->L);
	lua_settable(p->L, LUA_REGISTRYINDEX);

	return POM_OK;
}

int addon_output_open(void *output_priv) {

	struct addon_instance_priv *p = output_priv;
	if (addon_get_instance(p) != POM_OK)
		return POM_ERR;
	return addon_call(p->L, "open", 0);
}

int addon_output_close(void *output_priv) {

	struct addon_instance_priv *p = output_priv;
	if (addon_get_instance(p) != POM_OK)
		return POM_ERR;
	return addon_call(p->L, "close", 0);
}

