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

#ifndef __ADDON_PLUGIN_H__
#define __ADDON_PLUGIN_H__

#include <pom-ng/addon.h>

#define ADDON_PLUGIN_METATABLE		"addon.plugin"

enum addon_plugin_type {
	addon_plugin_type_event,
	addon_plugin_type_pload
};

struct addon_plugin_reg {

	char *name;
	struct mod_reg *mod;

	enum addon_plugin_type type;

	int (*init) (struct addon_plugin *p);
	int (*cleanup) (void *addon_priv);
	int (*open) (void *addon_priv);
	int (*close) (void *addon_priv);

	// For event plugins
	int (*event_begin) (struct event *evt, void *obj, struct proto_process_stack *stack, unsigned int stack_index);
	int (*event_end) (struct event *evt, void *obj);

	// For payload plugins
	int (*pload_open) (struct analyzer_pload_instance *pi, void *output_priv, struct ptype *params[]);
	int (*pload_write) (void *pload_instance_priv, void *data, size_t len);
	int (*pload_close) (void *pload_instance_priv);

	struct addon_pload_param_reg *pload_params;
	int pload_param_count;

	struct addon_plugin_reg *prev, *next;
};

struct addon_plugin {
	struct addon_plugin_reg *reg;
	struct addon_param *params;

	int open;

	void *priv;
};

int addon_plugin_lua_register(lua_State *L);

int addon_plugin_pload_write(struct addon_plugin_reg *addon_reg, void *pload_instance_priv, void *data, size_t len);
int addon_plugin_pload_close(struct addon_plugin_reg *addon_reg, void *pload_instance_priv);

#endif
