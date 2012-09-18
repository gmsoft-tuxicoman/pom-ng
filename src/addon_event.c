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

static int addon_event_get_field(lua_State *L) {

	struct addon_event *e = lua_touserdata(L, 1);

	const char *key = luaL_checkstring(L, 2);
	if (!strcmp(key, "name")) {
		lua_pushstring(L, e->evt->reg->info->name);
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

	if (addon_get_instance(p) != POM_OK)
		return POM_ERR;

	// Fetch the table associated with that event
	lua_pushlightuserdata(p->L, evt->reg);
	lua_gettable(p->L, -2);
	if (!lua_istable(p->L, -1)) {
		pomlog(POMLOG_ERR "Listener not registered for event %s", evt->reg->info->name);
		return POM_ERR;
	}
	
	if (addon_event_add_event(p->L, evt) != POM_OK)
		return POM_ERR;

	return addon_call(p->L, "begin", 1);
}

int addon_event_process_end(struct event *evt, void *obj) {

	struct addon_instance_priv *p = obj;

	if (addon_get_instance(p) != POM_OK)
		return POM_ERR;

	// Fetch the table associated with that event
	lua_pushlightuserdata(p->L, evt->reg);
	lua_gettable(p->L, -2);
	if (!lua_istable(p->L, -1)) {
		pomlog(POMLOG_ERR "Listener not registered for event %s", evt->reg->info->name);
		return POM_ERR;
	}

	if (addon_event_add_event(p->L, evt) != POM_OK)
		return POM_ERR;

	return addon_call(p->L, "end", 1);

}
