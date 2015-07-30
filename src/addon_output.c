/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2012-2015 Guy Martin <gmsoft@tuxicoman.be>
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
#include <pom-ng/analyzer.h>
#include "addon_event.h"
#include "addon_ptype.h"
#include "addon_pload.h"
#include "addon_plugin.h"

struct addon_output *addon_output_head = NULL;

// Called from lua to create a new output class
static int addon_output_new(lua_State *L) {

	// Args should be :
	// 1) name
	// 2) output description
	// 3) parameter table

	// Stack : name, params

	luaL_checkstring(L, 1);

	// Create a new addon class
	lua_newtable(L); // Stack : name, descr, params, class

	// Assign the metatable
	luaL_getmetatable(L, ADDON_OUTPUT_METATABLE); // Stack : name, descr, params, class, metatable
	lua_setmetatable(L, -2); // Stack : name, descr, params, class

	// Save the parameter table
	lua_pushvalue(L, -2); // Stack : name, descr, params, class, params
	lua_setfield(L, -2, "__params"); // Stack : name, descr, params, class
	lua_remove(L, -2); // Stack : name, descr, class

	// Save the description
	lua_pushvalue(L, -2); // Stack : name, descr, class, descr
	lua_setfield(L, -2, "__descr"); // Stack : name, descr, class
	lua_remove(L, -2); // Stack : name, class

	// Add the output to the outputs table
	lua_getfield(L, LUA_REGISTRYINDEX, ADDON_OUTPUTS_TABLE); // Stack : name, class, outputs
	if (lua_isnil(L, -1)) {
		lua_pop(L, 1); // Stack : name, class
		lua_newtable(L); // Stack : name, class, outputs
		lua_pushvalue(L, -1); // Stack : name,  class, outputs, outputs
		lua_setfield(L, LUA_REGISTRYINDEX, ADDON_OUTPUTS_TABLE); // Stack : name, class, outputs
	}
	lua_pushvalue(L, -3); // Stack : name, class, outputs, name
	lua_pushvalue(L, -3); // Stack : name, class, outputs, name, class
	lua_settable(L, -3); // Stack : name, class, outputs
	lua_pop(L, 1); // Stack : name, class
	lua_remove(L, 1); // Stack : class

	return 1;
}

// Helper function to get the output priv
static struct addon_instance_priv *addon_output_get_priv(lua_State *L, int t) {

	lua_getfield(L, t, "__priv");
	return luaL_checkudata(L, -1, ADDON_OUTPUT_PRIV_METATABLE);
}

// Called from lua to listen to a new event from an instance
static int addon_output_event_listen_start(lua_State *L) {
	
	// Args should be :
	// 1) self
	// 2) event name
	// 3) process_begin
	// 4) process_end
	// 5) filter if any
	
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

	struct filter_node *filter = NULL;
	if (!lua_isnil(L, 5)) {
		const char *filter_str = luaL_checkstring(L, 5);
		if (filter_event((char*)filter_str, evt, &filter) != POM_OK)
			luaL_error(L, "Error while parsing filter \"%s\"", filter_str);
	}

	// Get the output
	struct addon_instance_priv *p = addon_output_get_priv(L, 1);

	if (event_listener_register(evt, p, process_begin, process_end, filter) != POM_OK)
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
	struct addon_instance_priv *p = addon_output_get_priv(L, 1);
	
	if (event_listener_unregister(evt, p) != POM_OK)
		luaL_error(L, "Error while unregistering event listener");

	// Forget about listening to the event
	lua_pushlightuserdata(L, evt);
	lua_pushnil(L);
	lua_settable(L, 1);

	return 0;
}

// Called from C to open a pload
static int addon_output_pload_open(void *obj, void **priv, struct pload *pload) {

	struct addon_instance_priv *p = obj;

	// Lock the output
	pom_mutex_lock(&p->lock);

	lua_getfield(p->L, LUA_REGISTRYINDEX, ADDON_INSTANCE); // Stack : self

	struct addon_output_pload_priv *ppriv = malloc(sizeof(struct addon_output_pload_priv));
	if (!ppriv) {
		pom_mutex_unlock(&p->lock);
		pom_oom(sizeof(struct addon_output_pload_priv));
		return POM_ERR;
	}
	memset(ppriv, 0, sizeof(struct addon_output_pload_priv));

	*priv = ppriv;

	// Get the __pload_listener table
	lua_getfield(p->L, -1, "__pload_listener"); // Stack : self, __pload_listener

	// Get the open function
	lua_getfield(p->L, -1, "open"); // Stack : self, __pload_listener, open_func

	// Check if there is an open function
	if (lua_isnil(p->L, -1)) {
		pom_mutex_unlock(&p->lock);
		lua_pop(p->L, 3); // Stack : empty
		return POM_OK;
	}

	// Add self
	lua_pushvalue(p->L, -3); // Stack : self, __pload_listener, open_func, self

	// Create a new table for the pload priv and store it into __pload_listener
	lua_newtable(p->L); // Stack : self, __pload_listener, open_func, self, pload_priv_table

	// Add output_pload_data to it
	addon_pload_data_push(p->L); // Stack : self, __pload_listener, open_func, self, pload_priv_table, pload_data
	lua_setfield(p->L, -2, "__pload_data"); // Stack : self, __pload_listener, open_func, self, pload_priv_table

	// Add the new priv to the __pload_listener table
	lua_pushlightuserdata(p->L, ppriv); // Stack : self, __pload_listener, open_func, self, pload_priv_table, pload_priv
	lua_pushvalue(p->L, -2); // Stack : self, __pload_listener, open_func, self, pload_priv_table, pload_priv, pload_priv_table
	lua_settable(p->L, -6); // Stack : self, __pload_listener, open_func, self, pload_priv_table

	// Add the pload to the args
	addon_pload_push(p->L, pload, ppriv); // Stack : self, __pload_listener, open_func, self, pload_priv_table, pload


	// Call the open function
	addon_pcall(p->L, 3, 1); // Stack : self, __pload_listener, result

	int res = 0;
	if (!lua_isboolean(p->L, -1)) {
		pomlog(POMLOG_WARN "LUA coding error: pload open function result must be a boolean");
	} else {
		res = lua_toboolean(p->L, -1);
	}

	if (!res) { // The payload doesn't need to be processed, remove the payload_priv_table and the __pload_data
		lua_pushlightuserdata(p->L, ppriv); // Stack : self, __pload_listener, result, pload_priv
		lua_pushnil(p->L); // Stack : self, __pload_listener, result, pload_priv, nil
		lua_settable(p->L, -4); // Stack : self, __pload_listener, result
		lua_pushnil(p->L); // Stack : self, __pload_listener, result, nil
		lua_setfield(p->L, -3, "__pload_data"); // Stack : self, __pload_listener, result
	}

	// Remove leftovers
	lua_pop(p->L, 3); // Stack : empty
	pom_mutex_unlock(&p->lock);

	return POM_OK;
}

// Called from C to write a pload
static int addon_output_pload_write(void *output_priv, void *pload_instance_priv, void *data, size_t len) {

	struct addon_output_pload_priv *ppriv = pload_instance_priv;
	struct addon_instance_priv *p = output_priv;

	pom_mutex_lock(&p->lock);

	// First process all the plugins attached to this pload
	struct addon_output_pload_plugin *tmp;
	for (tmp = ppriv->plugins; tmp; tmp = tmp->next) {
		if (tmp->is_err)
			continue;

		if (addon_plugin_pload_write(tmp->addon_reg, ppriv->plugin_priv, tmp->pload_priv, data, len) != POM_OK) {
			addon_plugin_pload_close(tmp->addon_reg, ppriv->plugin_priv, tmp->pload_priv);
			tmp->is_err = 1;
		}
	}

	lua_getfield(p->L, LUA_REGISTRYINDEX, ADDON_INSTANCE); // Stack : self

	lua_getfield(p->L, -1, "__pload_listener"); // Stack : self, __pload_listener

	// Get the write function
	lua_getfield(p->L, -1, "write"); // Stack : self, __pload_listener, write_func
	
	// Check if there is a write function
	if (lua_isnil(p->L, -1)) {
		lua_pop(p->L, 3); // Stack : empty
		pom_mutex_unlock(&p->lock);
		return POM_OK;
	}

	// Setup args
	lua_pushvalue(p->L, -3); // Stack : self, __pload_listener, write_func, self
	lua_pushlightuserdata(p->L, pload_instance_priv); // Stack : self, __pload_listener, write_func, self, pload_priv
	lua_gettable(p->L, -4); // Stack : self, __pload_listener, write_func, self, pload_priv_table

	if (lua_isnil(p->L, -1)) {
		// There is no pload_priv_table, payload doesn't need to be processed
		lua_pop(p->L, 5); // Stack : empty
		pom_mutex_unlock(&p->lock);
		return POM_OK;
	}

	lua_getfield(p->L, -1, "__pload_data"); // Stack : self, __pload_listener, write_func, self, pload_priv_table, pload_data

	// Update the pload_data
	addon_pload_data_update(p->L, -1, data, len);
	pom_mutex_unlock(&p->lock);

	int res = addon_pcall(p->L, 3, 1); // Stack : self, __pload_listener, result

	int write_res = 0;

	if (res == POM_OK) {
		if (!lua_isboolean(p->L, -1)) {
			pomlog(POMLOG_WARN "LUA coding error: pload write function result must be a boolean");
		} else {
			write_res = lua_toboolean(p->L, -1);
		}
	}

	if (!write_res) {
		// Remove the pload_priv_table since it failed
		lua_pushlightuserdata(p->L, pload_instance_priv); // Stack : self, __pload_listener, result, pload_priv
		lua_pushnil(p->L); // Stack : self, __pload_listener, result, pload_priv, nil
		lua_settable(p->L, -4); // Stack : self, __pload_listener, result
	}

	lua_pop(p->L, 3); // Stack : empty

	pom_mutex_unlock(&p->lock);

	return POM_OK;
}

// Called from C to close a pload
static int addon_output_pload_close(void *output_priv, void *pload_instance_priv) {

	struct addon_output_pload_priv *ppriv = pload_instance_priv;
	struct addon_instance_priv *p = output_priv;
	int res = POM_OK;


	pom_mutex_lock(&p->lock);

	// Process all the plugins attached to this pload
	struct addon_output_pload_plugin *tmp;
	for (tmp = ppriv->plugins; tmp; tmp = tmp->next) {
		if (tmp->is_err)
			continue;
		addon_plugin_pload_close(tmp->addon_reg, ppriv->plugin_priv, tmp->pload_priv);
	}

	lua_getfield(p->L, LUA_REGISTRYINDEX, ADDON_INSTANCE); // Stack : self
	lua_getfield(p->L, -1, "__pload_listener"); // Stack : self, __pload_listener

	// Get the pload_priv_table
	lua_pushlightuserdata(p->L, pload_instance_priv); // Stack : self, __pload_listener, pload_priv
	lua_gettable(p->L, -2); // Stack : self, __pload_listener, pload_priv_table

	if (lua_isnil(p->L, -1)) {
		// There is no pload_priv_table, the payload doesn't need to be processed
		lua_pop(p->L, 3);
		goto cleanup;
	}

	// Remove the payload_priv_table from __pload_listener
	lua_pushlightuserdata(p->L, pload_instance_priv); // Stack : self, __pload_listener, pload_priv_table, pload_priv
	lua_pushnil(p->L); // Stack : self, __pload_listener, pload_priv_table, pload_priv, nil
	lua_settable(p->L, -4); // Stack : self, __pload_listener, pload_priv_table

	// Get the close function
	lua_getfield(p->L, -2,  "close"); // Stack : self, __pload_listener, pload_priv_table, close_func

	if (lua_isnil(p->L, -1)) {
		// There is no close function
		lua_pop(p->L, 4); // Stack : empty
		goto cleanup;
	}


	// Setup args
	lua_pushvalue(p->L, 1); // Stack : self, __pload_listener, pload_priv_table, close_func, self
	lua_pushvalue(p->L, -3); // Stack : self, __pload_listener, pload_priv_table, close_func, self, pload_priv_table

	res = addon_pcall(p->L, 2, 0); // Stack : self, __pload_listener, pload_priv_table

	lua_pop(p->L, 3); // Stack : empty

cleanup:

	pom_mutex_unlock(&p->lock);

	while (ppriv->plugins) {
		tmp = ppriv->plugins;
		ppriv->plugins = tmp->next;
		free(tmp);
	}

	free(ppriv);


	return res;
}

// Called from lua to start listening to files
static int addon_output_pload_listen_start(lua_State *L) {

	// Args should be :
	// 1) self
	// 2) open function
	// 3) write function
	// 4) close function
	// 5) filter if any

	// Push nill if additional functions are missing
	while (lua_gettop(L) < 4)
		lua_pushnil(L);

	// Stack : instance, read_func, write_func, close_func

	// Get the output
	struct addon_instance_priv *p = addon_output_get_priv(L, 1);

	if (!lua_isfunction(L, 2) && !lua_isfunction(L, 3) && !lua_isfunction(L, 4))
		luaL_error(L, "At least one function should be provided to pload_listen_start()");

	// Check if we are already listening or not
	lua_getfield(L, 1, "__pload_listener");
	if (!lua_isnil(L, -1))
		luaL_error(L, "The output is already listening for payloads");

	struct filter_node *filter = NULL;

	if (!lua_isnil(L, 5)) {
		const char *filter_str = luaL_checkstring(L, 5);
		if (filter_event((char*)filter_str, evt, &filter) != POM_OK)
			luaL_error(L, "Error while parsing filter \"%s\"", filter_str);
	}

	if (pload_listen_start(p, NULL, filter, addon_output_pload_open, addon_output_pload_write, addon_output_pload_close) != POM_OK)
		luaL_error(L, "Error while registering the payload listener");


	// Create table to track pload listener functions
	lua_pushliteral(L, "__pload_listener");
	lua_newtable(L);

	if (!lua_isnil(L, 2)) {
		lua_pushliteral(L, "open");
		lua_pushvalue(L, 2);
		lua_settable(L, -3);
	}

	if (!lua_isnil(L, 3)) {
		lua_pushliteral(L, "write");
		lua_pushvalue(L, 3);
		lua_settable(L, -3);
	}

	if (!lua_isnil(L, 4)) {
		lua_pushliteral(L, "close");
		lua_pushvalue(L, 4);
		lua_settable(L, -3);
	}

	lua_settable(L, 1);
	
	return 0;
}

// Called from lua to stop listening to a pload
static int addon_output_pload_listen_stop(lua_State *L) {
	// Args should be :
	// 1) self
	
	// Get the output
	struct addon_instance_priv *p = addon_output_get_priv(L, 1); // Stack : instance

	// Get the listening table
	lua_getfield(L, 1, "__pload_listener"); // Stack : instance, __pload_listener
	if (lua_isnil(L, 1))
		luaL_error(L, "The output is not listening for payloads");

	if (pload_listen_stop(p, NULL) != POM_OK)
		luaL_error(L, "Error while stopping payload listening");
	
	lua_pushnil(L); // Stack : instance, nil
	lua_setfield(L, 1, "__pload_listener"); // Stack : instance
	lua_pop(L, 1); // Stack : empty

	return 0;
}

// Called from lua to get a parameter value
static int addon_output_param_get(lua_State *L) {

	struct addon_instance_priv *p = addon_output_get_priv(L, 1);

	const char *name = luaL_checkstring(L, 2);

	struct addon_param *tmp;
	for (tmp = p->params; tmp && strcmp(tmp->name, name); tmp = tmp->next);
	
	if (!tmp)
		luaL_error(L, "No such parameter %s", name);

	addon_ptype_push(L, tmp->value);

	return 1;
}

// Garbage collector function for an output parameter
static int addon_output_priv_gc(lua_State *L) {
	struct addon_instance_priv *priv = luaL_checkudata(L, 1, ADDON_OUTPUT_PRIV_METATABLE);

	while (priv->params) {
		struct addon_param *tmp = priv->params;
		priv->params = tmp->next;
		free(tmp->name);
		ptype_cleanup(tmp->value);
		free(tmp);
	}

	pthread_mutex_destroy(&priv->lock);

	return 0;
}

// Garbage collector function for output class
static int addon_output_gc(lua_State *L) {
	struct output_reg_info *output_reg = luaL_checkudata(L, 1, ADDON_OUTPUT_REG_METATABLE);
	if (output_reg) {
		free(output_reg->name);
		free(output_reg->description);
	}
	return 0;
}

int addon_output_lua_register(lua_State *L) {

	// Register the output functions
	struct luaL_Reg l[] = {
		{ "new", addon_output_new },
		{ 0 }
	};
	addon_pomlib_register(L, "output", l);

	// Create the output instance metatable
	struct luaL_Reg m[] = {
		{ "event_listen_start", addon_output_event_listen_start },
		{ "event_listen_stop", addon_output_event_listen_stop },
		{ "pload_listen_start", addon_output_pload_listen_start },
		{ "pload_listen_stop", addon_output_pload_listen_stop },
		{ "param_get", addon_output_param_get },

		{ 0 }
	};

	luaL_newmetatable(L, ADDON_OUTPUT_METATABLE);
	// Assign __index to itself
	lua_pushstring(L, "__index");
	lua_pushvalue(L, -2);
	lua_settable(L, -3);
	luaL_register(L, NULL, m);


	// Create the output_reg metatable
	struct luaL_Reg m_reg[] = {
		{ "__gc", addon_output_gc },
		{ 0 }
	};
	luaL_newmetatable(L, ADDON_OUTPUT_REG_METATABLE);
	luaL_register(L, NULL, m_reg);

	
	// Ceate the output_priv metatable
	struct luaL_Reg m_priv[] = {
		{ "__gc", addon_output_priv_gc },
		{ 0 }
	};
	luaL_newmetatable(L, ADDON_OUTPUT_PRIV_METATABLE);
	luaL_register(L, NULL, m_priv);

	return POM_OK;
}


// Called from C to register all the outputs after the lua file was executed
int addon_output_register_all(struct addon *addon) {

	lua_getfield(addon->L, LUA_REGISTRYINDEX, ADDON_OUTPUTS_TABLE); // Stack : outputs

	lua_pushnil(addon->L); // Stack : outputs, nil
	while (lua_next(addon->L, -2)) { // Stack : outputs, name, output

		// Key is the name of the output
		const char *name = lua_tostring(addon->L, -2);
		
		pomlog(POMLOG_DEBUG "Registering addon output %s ...", name);

		lua_getfield(addon->L, -1, "__descr"); // Stack : outputs, name, output, __descr
		const char *descr = lua_tostring(addon->L, -1);
		lua_pop(addon->L, 1);

		struct output_reg_info *output_info = lua_newuserdata(addon->L, sizeof(struct output_reg_info)); // Stack : outputs, name, output, output_info
		memset(output_info, 0, sizeof(struct output_reg_info));

		// Add the output_reg metatable
		luaL_getmetatable(addon->L, ADDON_OUTPUT_REG_METATABLE); // Stack : outputs, name, output, output_info, metatable
		lua_setmetatable(addon->L, -2); // Stack : outputs, name, output, output_info
	
		output_info->name = strdup(name);
		if (!output_info->name)
			addon_oom(addon->L, strlen(name) + 1);

		output_info->description = strdup(descr);
		if (!output_info->description) {
			free(output_info->name);
			addon_oom(addon->L, strlen(descr) + 1);
		}

		output_info->mod = addon->mod;
		output_info->init = addon_output_init;
		output_info->open = addon_output_open;
		output_info->close = addon_output_close;
		output_info->cleanup = addon_output_cleanup;

		if (output_register(output_info) != POM_OK)
			luaL_error(addon->L, "Error while registering addon input %s", name);

		// Add the info to the class, we need to keep a copy of that so lua is a perfect location to store it
		lua_setfield(addon->L, -2, "__info"); // Stack : outputs, name, output
		lua_pop(addon->L, 1); // Stack : outputs, name

		pomlog(POMLOG_DEBUG "Registered addon output %s", name);
	}

	lua_pop(addon->L, 1); // Stack : empty

	return 0;
}

int addon_output_init(struct output *o) {

	struct addon *addon = o->info->reg_info->mod->priv;

	lua_State *L = addon_create_state(addon->filename); // Stack : empty

	if (!L) {
		pomlog(POMLOG_ERR "Error while creating new lua state for output %s", o->info->reg_info->name);
		return POM_ERR;
	}

	// Get the output from the outputs table
	lua_getfield(L, LUA_REGISTRYINDEX, ADDON_OUTPUTS_TABLE); // Stack : outputs
	lua_getfield(L, -1, o->info->reg_info->name); // Stack : outputs, output

	// Get rid of the outputs table
	lua_remove(L, -2); // Stack : output
	lua_pushnil(L); // Stack : output, nil
	lua_setfield(L, LUA_REGISTRYINDEX, ADDON_OUTPUTS_TABLE); // Stack : output

	// Add the output to the registry
	lua_pushvalue(L, -1); // Stack : output, output
	lua_setfield(L, LUA_REGISTRYINDEX, ADDON_INSTANCE); // Stack : output


	// Create the private data
	// TODO make __priv read-only
	struct addon_instance_priv *p = lua_newuserdata(L, sizeof(struct addon_instance_priv)); // Stack : output, priv
	if (!p) {
		pom_oom(sizeof(struct addon_instance_priv));
		return POM_ERR;
	}
	memset(p, 0, sizeof(struct addon_instance_priv));
	o->priv = p;
	p->instance = o;
	p->L = L;
	if (pthread_mutex_init(&p->lock, NULL)) {
		pomlog(POMLOG_ERR "Error while initializing mutex : %s", pom_strerror(errno));
		abort();
		return POM_ERR;
	}

	// Assign the output_priv metatable
	luaL_getmetatable(L, ADDON_OUTPUT_PRIV_METATABLE); // Stack : output, priv, metatable
	lua_setmetatable(L, -2); // Stack : output, priv
	// Add it to __priv
	lua_setfield(L, -2, "__priv"); // Stack : output

	// Fetch the parameters table 
	lua_getfield(L, -1, "__params"); // Stack : output, params

	// Parse each param from the class
	lua_pushnil(L); // Stack : output, params, nil
	while (lua_next(L, -2) != 0) { // Stack : output, params, key, param
		if (!lua_istable(L, -1)) {
			pomlog(POMLOG_ERR "Parameters should be described in tables");
			goto err;
		}

		// Fetch the name
		lua_pushinteger(L, 1); // Stack : output, params, key, param, 1
		lua_gettable(L, -2); // Stack : output, params, key, param, name
		if (!lua_isstring(L, -1)) {
			pomlog(POMLOG_ERR "Parameter name is not a string");
			goto err;
		}
		const char *name = luaL_checkstring(L, -1);
		lua_pop(L, 1); // Stack : output, params, key, param

		// Fetch the ptype type
		lua_pushinteger(L, 2); // Stack : output, params, key, param, 2
		lua_gettable(L, -2); // Stack : output, params, key, param, type
		if (!lua_isstring(L, -1)) {
			pomlog(POMLOG_ERR "Parameter type is not a string");
			goto err;
		}
		const char *type = lua_tostring(L, -1);
		lua_pop(L, 1); // Stack : output, params, key, param

		// Fetch the default value
		lua_pushinteger(L, 3); // Stack : output, params, key, param, 3
		lua_gettable(L, -2); // Stack : output, params, key, param, defval
		if (!lua_isstring(L, -1)) {
			pomlog(POMLOG_ERR "Parameter default value is not a string");
			goto err;
		}
		const char *defval = lua_tostring(L, -1);
		lua_pop(L, 1); // Stack : output, params, key, param

		// Fetch the description
		lua_pushinteger(L, 4); // Stack : output, params, key, param, 4
		lua_gettable(L, -2); // Stack : output, params, key, param, descr
		if (!lua_isstring(L, -1)) {
			pomlog(POMLOG_ERR "Parameter description is not a string");
			goto err;
		}
		const char *descr = lua_tostring(L, -1);
		lua_pop(L, 1); // Stack : output, params, key, param

		// Allocate it
		struct addon_param *param = malloc(sizeof(struct addon_param));
		if (!param) {
			pom_oom(sizeof(struct addon_param));
			goto err;
		}
		param->name = strdup(name);
		if (!param->name) {
			free(param);
			pom_oom(strlen(name) + 1);
			goto err;
		}
		param->value = ptype_alloc(type);
		if (!param->value) {
			free(param->name);
			free(param);
			goto err;
		}
		
		struct registry_param *reg_param = registry_new_param((char*)name, (char*)defval, param->value, (char*)descr, 0);
		if (output_add_param(o, reg_param) != POM_OK) {
			pomlog(POMLOG_ERR "Error while adding parameter to the output instance");
			if (reg_param)
				registry_cleanup_param(reg_param);
			free(param->name);
			ptype_cleanup(param->value);
			free(param);
			goto err;
		}

		param->next = p->params;
		p->params = param;


		// Pop the value (the param table)
		lua_pop(L, 1); // Stack : output, params, key
	}
	// At this point the stack is : output, params
	lua_pop(L, 2); // Stack : empty

	pomlog(POMLOG_DEBUG "Output %s created", o->name);
	return POM_OK;

err:
	lua_close(L);
	p->L = NULL;
	return POM_ERR;
}

int addon_output_cleanup(void *output_priv) {
	
	struct addon_instance_priv *p = output_priv;

	if (p->L)
		lua_close(p->L);

	return POM_OK;
}

int addon_output_open(void *output_priv) {

	struct addon_instance_priv *p = output_priv;

	pom_mutex_lock(&p->lock);

	lua_getfield(p->L, LUA_REGISTRYINDEX, ADDON_INSTANCE); // Stack : self

	lua_getfield(p->L, -1, "open"); // Stack : self, open_func

	lua_pushvalue(p->L, -2); // Stack : self, open_func, self

	int res = addon_pcall(p->L, 1, 0); // Stack : self
	
	lua_pop(p->L, 1); // Stack : empty

	pom_mutex_unlock(&p->lock);

	return res;
}

int addon_output_close(void *output_priv) {

	struct addon_instance_priv *p = output_priv;

	pom_mutex_lock(&p->lock);
	lua_getfield(p->L, LUA_REGISTRYINDEX, ADDON_INSTANCE); // Stack : self
	lua_getfield(p->L, -1, "close"); // Stack : self, close_func

	lua_pushvalue(p->L, -2); // Stack : self, close_func, self

	int res =  addon_pcall(p->L, 1, 0); // Stack : self
	
	lua_pop(p->L, 1); // Stack : empty
	pom_mutex_unlock(&p->lock);

	return res;
}

struct addon_output_pload_plugin *addon_output_pload_plugin_alloc(struct addon_plugin_reg *addon_reg) {
	struct addon_output_pload_plugin *plugin = malloc(sizeof(struct addon_output_pload_plugin));
	if (!plugin) {
		pom_oom(sizeof(struct addon_output_pload_plugin));
		return NULL;
	}
	memset(plugin, 0, sizeof(struct addon_output_pload_plugin));
	plugin->addon_reg = addon_reg;

	return plugin;
}
