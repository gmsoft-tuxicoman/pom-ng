/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2010 Guy Martin <gmsoft@tuxicoman.be>
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



#ifndef __POM_NG_REGISTRY_H__
#define __POM_NG_REGISTRY_H__

#include <pom-ng/ptype.h>

#define REGISTRY_PARAM_FLAG_CLEANUP_VAL	1
#define REGISTRY_PARAM_FLAG_IMMUTABLE	2

struct registry_param {
	char *name;
	char *default_value;
	struct ptype *value;
	char *description;
	unsigned int flags;

	void *check_priv;
	int (*set_pre_check) (void *priv, char *value);
	int (*set_post_check) (void *priv, struct ptype *value);

	struct registry_param *next, *prev;
};

struct registry_instance {
	char *name;
	struct registry_param *params;
	struct registry_function *funcs;
	void *priv;
	struct registry_instance *next, *prev;
	struct registry_class *parent;
};

struct registry_param* registry_new_param(char *name, char *default_value, struct ptype *value, char *description, int flags);
int registry_param_set_check_callbacks(struct registry_param *p, void *priv, int (*pre_check) (void *priv, char *value), int (*post_check) (void *priv, struct ptype* value));
int registry_instance_add_param(struct registry_instance *i, struct registry_param *p);
int registry_instance_add_function(struct registry_instance *i, char *name, int (*handler) (struct registry_instance *), char *description);

#endif
