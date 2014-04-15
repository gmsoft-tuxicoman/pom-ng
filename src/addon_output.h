/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2012-2014 Guy Martin <gmsoft@tuxicoman.be>
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


#ifndef __ADDON_OUTPUT_H__
#define __ADDON_OUTPUT_H__

#include "output.h"
#include "analyzer.h"

#define ADDON_OUTPUTS_TABLE		"outputs"
#define ADDON_OUTPUT_METATABLE		"addon.output"
#define ADDON_OUTPUT_PRIV_METATABLE	"addon.output_priv"
#define ADDON_OUTPUT_REG_METATABLE	"addon.output_reg"

struct addon_output {

	struct output_reg_info reg_info;

	struct addon_output *prev, *next;
};

struct addon_output_pload_plugin {

	struct addon_plugin_reg *addon_reg;
	void *pload_priv;

	int is_err;

	struct addon_output_pload_plugin *prev, *next;
};

struct addon_output_pload_priv {

	void *plugin_priv;

	// Used by pload plugins for this output
	struct addon_output_pload_plugin *plugins;

};

int addon_output_lua_register(lua_State *L);
int addon_output_register_all(struct addon *addon);

int addon_output_init(struct output *o);
int addon_output_cleanup(void *output_priv);
int addon_output_open(void *output_priv);
int addon_output_close(void *output_priv);

struct addon_output_pload_plugin *addon_output_pload_plugin_alloc(struct addon_plugin_reg *addon_reg);

#endif


