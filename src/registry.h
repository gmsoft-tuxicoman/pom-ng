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



#ifndef __REGISTRY_H__
#define __REGISTRY_H__


#define REGISTRY_FLAG_CLEANUP_VAL	1

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

	struct registry_instance *next, *prev;
	struct registry_class *parent;
};

struct registry_class {
	char *name;

	struct registry_instance *instances;

	struct registry_param *global_params;

	struct registry_class *next, *prev;
};

int registry_init();
int registry_cleanup();
struct registry_class * registry_get_head();

struct registry_class* registry_add_class(char *name);
int registry_remove_class(struct registry_class *c);

struct registry_instance *registry_add_instance(struct registry_class *c, char *name);
int registry_remove_instance(struct registry_instance *i);

struct registry_param* registry_new_param(char *name, char *default_value, struct ptype *value, char *description, int flags);
int registry_param_set_check_callbacks(struct registry_param *p, void *priv, int (*pre_check) (void *priv, char *value), int (*post_check) (void *priv, struct ptype* value));
int registry_class_add_param(struct registry_class *c, struct registry_param *p);
int registry_instance_add_param(struct registry_instance *i, struct registry_param *p);
int registry_set_param_value(struct registry_param *p, char *value);

#endif
