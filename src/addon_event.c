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
#include <pom-ng/event.h>

int addon_event_lua_register(lua_State *L) {
	struct luaL_Reg l[] = {
		{ "event_find", addon_event_find },
		{ 0 }
	};

	luaL_register(L, "pom", l);

	return POM_OK;
}

int addon_event_find(lua_State *L) {

	const char *evt_name = luaL_checkstring(L, 1);

	if (event_find((char*)evt_name)) {
		lua_pushnumber(L, 1);
		return 1;
	}
	return 0;
}

