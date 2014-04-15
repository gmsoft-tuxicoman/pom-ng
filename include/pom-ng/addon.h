/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2012-2013 Guy Martin <gmsoft@tuxicoman.be>
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

#ifndef __POMNG_ADDON_H__
#define __POMNG_ADDON_H__

#include <pom-ng/event.h>
#include <pom-ng/pload.h>

struct addon_plugin;

struct addon_pload_param_reg {
	char *name;
	char *ptype_type;
	char *defval;
};

struct addon_plugin_event_reg {
	char *name;
	struct mod_reg *mod;

	int (*init) (struct addon_plugin *p);
	int (*cleanup) (void *addon_priv);
	int (*open) (void *addon_priv);
	int (*close) (void *addon_priv);

	int (*event_begin) (struct event *evt, void *obj, struct proto_process_stack *stack, unsigned int stack_index);
	int (*event_end) (struct event *evt, void *obj);
};

struct addon_plugin_pload_reg {
	char *name;
	struct mod_reg *mod;

	int (*init) (struct addon_plugin *p);
	int (*cleanup) (void *addon_priv);
	int (*open) (void *addon_priv);
	int (*close) (void *addon_priv);

	int (*pload_open) (void *addon_priv, void **priv, struct pload *pload, struct ptype *params[]);
	int (*pload_write) (void *addon_priv, void *pload_instance_priv, void *data, size_t len);
	int (*pload_close) (void *addon_priv, void *pload_instance_priv);

	struct addon_pload_param_reg *pload_params;
};

int addon_plugin_event_register(struct addon_plugin_event_reg *reg_info);
int addon_plugin_pload_register(struct addon_plugin_pload_reg *reg_info);
int addon_plugin_unregister(char *name);

void addon_plugin_set_priv(struct addon_plugin *a, void *priv);
int addon_plugin_add_param(struct addon_plugin *a, char *name, char *defval, struct ptype *value);


#endif
