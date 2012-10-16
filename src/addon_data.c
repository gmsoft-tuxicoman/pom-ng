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

static int addon_data_item_metatable(lua_State *L) {

	struct data_item **di = luaL_checkudata(L, 1, ADDON_DATA_ITEM_METATABLE);
	const char *key = luaL_checkstring(L, 2);

	struct data_item *item;
	for (item = *di; item && strcmp(item->key, key); item = item->next);
	if (!item)
		return 0;
	
	addon_ptype_push(L, item->value);

	return 1;

}

static int addon_data_push_item(lua_State *L, struct data_item *item) {
	
	struct data_item **di = lua_newuserdata(L, sizeof(struct data_item *));
	*di = item;

	luaL_getmetatable(L, ADDON_DATA_ITEM_METATABLE);
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
		addon_data_push_item(L, data[id].items);
	} else {
		if (data_is_set(data[id]))
			addon_ptype_push(L, data[id].value);
		else
			lua_pushnil(L);
	}

	id++;
	lua_pushinteger(L, id);
	lua_replace(L, lua_upvalueindex(2));

	return 2;
}

static int addon_data_metatable(lua_State *L) {
	
	struct addon_data *d = luaL_checkudata(L, 1, ADDON_DATA_METATABLE);
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
		addon_data_push_item(L, data[i].items);
		return 1;
	} else {
		if (data_is_set(data[i]))
			addon_ptype_push(L, data[i].value);
		else
			lua_pushnil(L);
		return 1;
	}

	return 0;
}

int addon_data_item_get_iterator(lua_State *L) {

	struct data_item **di = luaL_checkudata(L, 1, ADDON_DATA_ITEM_METATABLE);
	
	struct data_item **iter_di = lua_newuserdata(L, sizeof(struct data_item **));
	*iter_di = *di;
	lua_pushcclosure(L, addon_data_item_iterator, 1);

	return 1;
}

int addon_data_get_iterator(lua_State *L) {

	luaL_checkudata(L, 1, ADDON_DATA_METATABLE);

	lua_pushvalue(L, 1);
	lua_pushinteger(L, 0);
	lua_pushcclosure(L, addon_data_iterator, 2);

	return 1;
}

void addon_data_lua_register(lua_State *L) {

	luaL_newmetatable(L, ADDON_DATA_METATABLE);
	lua_pushliteral(L, "__index");
	lua_pushcfunction(L, addon_data_metatable);
	lua_settable(L, -3);

	luaL_newmetatable(L, ADDON_DATA_ITEM_METATABLE);
	lua_pushliteral(L, "__index");
	lua_pushcfunction(L, addon_data_item_metatable);
	lua_settable(L, -3);

	struct luaL_Reg l[] = {
		{ "data_iterator", addon_data_get_iterator },
		{ "data_item_iterator", addon_data_item_get_iterator },
		{ 0 }
	};
	addon_pomlib_register(L, l);
}

void addon_data_push(lua_State *L, struct data *data, struct data_reg *data_reg) {

	struct addon_data *d = lua_newuserdata(L, sizeof(struct addon_data));
	memset(d, 0, sizeof(struct addon_data));

	d->data = data;
	d->reg = data_reg;

	luaL_getmetatable(L, ADDON_DATA_METATABLE);
	lua_setmetatable(L, -2);
}

