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
#include "addon_data.h"
#include "addon_ptype.h"

static int addon_data_item_iterator(lua_State *L) {

	struct data_item **d = lua_touserdata(L, lua_upvalueindex(1));

	if (!*d)
		return 0;

	lua_pushstring(L, (*d)->key);
	addon_ptype_push(L, (*d)->value);
	
	*d = (*d)->next;

	return 2;

}

static int addon_data_item_get_field(lua_State *L) {

	struct addon_data *d = lua_touserdata(L, lua_upvalueindex(1));
	const char *key = luaL_checkstring(L, 2);
	int field_id = lua_tointeger(L, lua_upvalueindex(2));

	struct data_reg *data_reg = d->reg;

	if (field_id >= data_reg->data_count)
		luaL_error(L, "field_id %u bigger than data_count %u", field_id, data_reg->data_count);

	// Create an iterator if need
	if (!strcmp(key, "iter")) {
		struct data_item **di = lua_newuserdata(L, sizeof(struct data_item *));
		*di = d->data[field_id].items;
		lua_pushcclosure(L, addon_data_item_iterator, 1);
		return 1;
	}

	struct data_item *item;
	for (item = d->data[field_id].items; item && strcmp(item->key, key); item = item->next);
	if (!item)
		return 0;
	
	addon_ptype_push(L, item->value);

	return 1;

}

static int addon_data_push_item(lua_State *L, int item_id) {
	
	// Create the item table
	lua_newtable(L);

	// Create its metatable
	lua_newtable(L);

	// Add the lookup function
	lua_pushliteral(L, "__index");
	lua_pushvalue(L, lua_upvalueindex(1));
	lua_pushinteger(L, item_id);
	lua_pushcclosure(L, addon_data_item_get_field, 2);
	lua_settable(L, -3);

	// Set the metatable
	lua_setmetatable(L, -2);

	return 1;
}

static int addon_data_iterator(lua_State *L) {

	struct addon_data *d = lua_touserdata(L, lua_upvalueindex(1));
	int id = lua_tointeger(L, lua_upvalueindex(2));

	struct data_reg *data_reg = d->reg;
	struct data *data = d->data;
	
	if (id >= data_reg->data_count)
		return 0;

	lua_pushstring(L, data_reg->items[id].name);
	if (data_reg->items[id].flags & DATA_REG_FLAG_LIST) {
		addon_data_push_item(L, id);
	} else {
		addon_ptype_push(L, data[id].value);
	}

	id++;
	lua_pushinteger(L, id);
	lua_replace(L, lua_upvalueindex(2));

	return 2;
}

static int addon_data_get_field(lua_State *L) {
	
	struct addon_data *d = lua_touserdata(L, lua_upvalueindex(1));
	const char *key = luaL_checkstring(L, 2);

	// Look for the field
	struct data_reg *data_reg = d->reg;
	struct data *data = d->data;
	
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
		addon_data_push_item(L, i);
		return 1;
	} else {
		addon_ptype_push(L, data[i].value);
		return 1;
	}

	return 0;
}

int addon_data_get_iterator(lua_State *L) {

	if (!lua_getmetatable(L, 1))
		luaL_error(L, "Expected addon.data");
	lua_pushliteral(L, "__metatable");
	lua_gettable(L, -2);
	const char *metatable = luaL_checkstring(L, -1);
	if (strcmp(metatable, "addon.data"))
		luaL_error(L, "Expected addon.data");

	lua_pushvalue(L, 1);
	lua_pushinteger(L, 0);
	lua_pushcclosure(L, addon_data_iterator, 2);

	return 1;
}

void addon_data_lua_register(lua_State *L) {

	struct luaL_Reg l[] = {
		{ "data_iterator", addon_data_get_iterator },
		{ 0 }
	};
	luaL_register(L, ADDON_POM_LIB, l);
}

void addon_data_push(lua_State *L, struct data *data, struct data_reg *data_reg) {

	struct addon_data *d = lua_newuserdata(L, sizeof(struct addon_data));
	memset(d, 0, sizeof(struct addon_data));

	d->data = data;
	d->reg = data_reg;

	lua_newtable(L);
	lua_pushliteral(L, "__index");
	lua_pushvalue(L, -3);
	lua_pushcclosure(L, addon_data_get_field, 1);
	lua_settable(L, -3);

	lua_pushliteral(L, "__metatable");
	lua_pushliteral(L, "addon.data");
	lua_settable(L, -3);

	lua_setmetatable(L, -2);

}

