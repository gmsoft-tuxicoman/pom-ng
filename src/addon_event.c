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
#include "addon_event.h"
#include "addon_ptype.h"

static int addon_event_data_item_iterator(lua_State *L) {

	struct data_item **d = lua_touserdata(L, lua_upvalueindex(1));

	if (!*d)
		return 0;

	lua_pushstring(L, (*d)->key);
	addon_ptype_push(L, (*d)->value);
	
	*d = (*d)->next;

	return 2;

}

static int addon_event_data_item_get_field(lua_State *L) {

	struct addon_event *e = luaL_checkudata(L, lua_upvalueindex(1), ADDON_EVENT_METATABLE);
	const char *key = luaL_checkstring(L, 2);
	int field_id = lua_tointeger(L, lua_upvalueindex(2));

	struct data_reg *data_reg = e->evt->reg->info->data_reg;

	if (field_id >= data_reg->data_count)
		luaL_error(L, "field_id %u bigger than data_count %u", field_id, data_reg->data_count);

	// Create an iterator if need
	if (!strcmp(key, "iter")) {
		struct data_item **d = lua_newuserdata(L, sizeof(struct data_item **));
		*d = e->evt->data[field_id].items;
		lua_pushcclosure(L, addon_event_data_item_iterator, 1);
		return 1;
	}

	struct data_item *item;
	for (item = e->evt->data[field_id].items; item && strcmp(item->key, key); item = item->next);
	if (!item)
		return 0;
	
	addon_ptype_push(L, item->value);

	return 1;

}

static int addon_event_data_push_item(lua_State *L, int item_id) {
	
	// Create the item table
	lua_newtable(L);

	// Create its metatable
	lua_newtable(L);

	// Add the lookup function
	lua_pushliteral(L, "__index");
	lua_pushvalue(L, lua_upvalueindex(1));
	lua_pushinteger(L, item_id);
	lua_pushcclosure(L, addon_event_data_item_get_field, 2);
	lua_settable(L, -3);

	// Set the metatable
	lua_setmetatable(L, -2);

	return 1;
}

static int addon_event_data_iterator(lua_State *L) {

	struct addon_event *e = luaL_checkudata(L, lua_upvalueindex(1), ADDON_EVENT_METATABLE);
	int id = lua_tointeger(L, lua_upvalueindex(2));

	struct data_reg *data_reg = e->evt->reg->info->data_reg;
	struct data *data = e->evt->data;
	
	if (id >= data_reg->data_count)
		return 0;

	lua_pushstring(L, data_reg->items[id].name);
	if (data_reg->items[id].flags & DATA_REG_FLAG_LIST) {
		addon_event_data_push_item(L, id);
	} else {
		addon_ptype_push(L, data[id].value);
	}

	id++;
	lua_pushinteger(L, id);
	lua_replace(L, lua_upvalueindex(2));

	return 2;
}

static int addon_event_data_get_field(lua_State *L) {
	
	struct addon_event *e = luaL_checkudata(L, lua_upvalueindex(1), ADDON_EVENT_METATABLE);
	const char *key = luaL_checkstring(L, 2);

	// Look for the field
	struct data_reg *data_reg = e->evt->reg->info->data_reg;
	struct data *data = e->evt->data;
	
	int i;
	for (i = 0; i < data_reg->data_count; i ++) {
		if (!strcmp(data_reg->items[i].name, key))
			break;
	}

	if (i >= data_reg->data_count) {
		// Not found
		lua_pushnil(L);
		return 1;
	}

	if (data_reg->items[i].flags & DATA_REG_FLAG_LIST) {
		addon_event_data_push_item(L, i);
		return 1;
	} else {
		addon_ptype_push(L, data[i].value);
		return 1;
	}

	return 0;
}

static int addon_event_get_field(lua_State *L) {

	struct addon_event *e = luaL_checkudata(L, 1, ADDON_EVENT_METATABLE);

	const char *key = luaL_checkstring(L, 2);
	if (!strcmp(key, "name")) {
		lua_pushstring(L, e->evt->reg->info->name);
	} else if (!strcmp(key, "data")) {
		// Create an empty table
		lua_newtable(L);

		// Push the iterator function
		lua_pushliteral(L, "iter");
		lua_pushvalue(L, 1);
		lua_pushinteger(L, 0);
		lua_pushcclosure(L, addon_event_data_iterator, 2);
		lua_settable(L, -3);

		// Add a new metatable
		lua_newtable(L);
		lua_pushliteral(L, "__index");
		lua_pushvalue(L, 1);
		lua_pushcclosure(L, addon_event_data_get_field, 1);
		lua_settable(L, -3);
		lua_setmetatable(L, -2);
	} else {
		lua_pushnil(L);
	}

	return 1;
}

int addon_event_lua_register(lua_State *L) {
	
	struct luaL_Reg m[] = {
		{ "__index", addon_event_get_field },
		{ 0 }
	};

	luaL_newmetatable(L, ADDON_EVENT_METATABLE);

	// Register the functions
	luaL_register(L, NULL, m);

	return POM_OK;
}

static int addon_event_add_event(lua_State *L, struct event *evt) {

	// Add a pointer to the event
	struct addon_event *e = lua_newuserdata(L, sizeof(struct addon_event));
	if (!e)
		return POM_ERR;
	e->evt = evt;
	
	// Add the metatable to this object
	luaL_getmetatable(L, ADDON_EVENT_METATABLE);
	lua_setmetatable(L, -2);

	return POM_OK;
}

int addon_event_process_begin(struct event *evt, void *obj, struct proto_process_stack *stack, unsigned int stack_index) {

	struct addon_instance_priv *p = obj;

	// Fetch the instance table
	if (addon_get_instance(p) != POM_OK) // Stack : self
		return POM_ERR;

	// Fetch the table associated with that event
	lua_pushlightuserdata(p->L, evt->reg);
	lua_gettable(p->L, -2); // Stack : self, evt_table
	if (!lua_istable(p->L, -1)) {
		pomlog(POMLOG_ERR "Listener not registered for event %s", evt->reg->info->name);
		return POM_ERR;
	}

	// Get the open function
	lua_pushliteral(p->L, "begin");
	lua_gettable(p->L, -2); // Stack : self, evt_table, open_func
	// Push self
	lua_pushvalue(p->L, -3); // Stack : self, evt_table, open_func, self
	// Push event
	if (addon_event_add_event(p->L, evt) != POM_OK) // Stack : self, evt_table, open_func, self, evt
		return POM_ERR;

	return addon_pcall(p->L, 2, 0);
}

int addon_event_process_end(struct event *evt, void *obj) {

	struct addon_instance_priv *p = obj;

	if (addon_get_instance(p) != POM_OK) // Stack : self
		return POM_ERR;

	// Fetch the table associated with that event
	lua_pushlightuserdata(p->L, evt->reg);
	lua_gettable(p->L, -2); // Stack : self, evt_table
	if (!lua_istable(p->L, -1)) {
		pomlog(POMLOG_ERR "Listener not registered for event %s", evt->reg->info->name);
		return POM_ERR;
	}

	// Get the open function
	lua_pushliteral(p->L, "end");
	lua_gettable(p->L, -2); // Stack : self, evt_table, close_func
	// Push self
	lua_pushvalue(p->L, -3); // Stack : self, evt_table, close_func, self
	// Push event
	if (addon_event_add_event(p->L, evt) != POM_OK) // Stack : self, evt_table, close_func, self, evt
		return POM_ERR;

	return addon_pcall(p->L, 2, 0);

}
