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

#include <pom-ng/ptype_bool.h>
#include <pom-ng/ptype_uint8.h>
#include <pom-ng/ptype_uint16.h>
#include <pom-ng/ptype_uint32.h>
#include <pom-ng/ptype_uint64.h>
#include <pom-ng/ptype_string.h>

static int addon_ptype_initialized = 0;
static struct ptype_reg *ptype_string = NULL, *ptype_bool = NULL, *ptype_uint8 = NULL, *ptype_uint16 = NULL, *ptype_uint32 = NULL, *ptype_uint64 = NULL;

static int addon_ptype_init() {
	ptype_string = ptype_get_type("string");
	ptype_bool = ptype_get_type("bool");
	ptype_uint8 = ptype_get_type("uint8");
	ptype_uint16 = ptype_get_type("uint16");
	ptype_uint32 = ptype_get_type("uint32");
	ptype_uint64 = ptype_get_type("uint64");

	addon_ptype_initialized = 1;

	if (!ptype_string || !ptype_bool || !ptype_uint8 || !ptype_uint16 || !ptype_uint32 || !ptype_uint64) {
		pomlog(POMLOG_ERR "Failed to initialize addon ptypes.");
		return POM_ERR;
	}

	return POM_OK;
}

int addon_ptype_push(lua_State *L, struct ptype *p) {

	if (!addon_ptype_initialized && addon_ptype_init() != POM_OK)
		abort();

	if (!p) {
		lua_pushnil(L);
	} else if (p->type == ptype_string) {
		const char *str = PTYPE_STRING_GETVAL(p);
		lua_pushstring(L, str);
	} else if (p->type == ptype_bool) {
		char *val = PTYPE_BOOL_GETVAL(p);
		lua_pushboolean(L, *val);
	} else if (p->type == ptype_uint8) {
		uint8_t *val = PTYPE_UINT8_GETVAL(p);
		lua_pushinteger(L, *val);
	} else if (p->type == ptype_uint16) {
		uint16_t *val = PTYPE_UINT16_GETVAL(p);
		lua_pushinteger(L, *val);
	} else if (p->type == ptype_uint32) {
		uint32_t *val = PTYPE_UINT32_GETVAL(p);
		lua_pushinteger(L, *val);
	} else if (p->type == ptype_uint64) {
		uint64_t *val = PTYPE_UINT64_GETVAL(p);
		lua_pushinteger(L, *val);
	} else {
		char *val = ptype_print_val_alloc(p);
		if (!val) {
			lua_pushnil(L);
		} else {
			lua_pushstring(L, val);
			free(val);
		}
	}

	return 1;
}
