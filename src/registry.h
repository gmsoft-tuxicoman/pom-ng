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

#define REGISTRY_ROOT "root"


#define REGISTRY_FLAG_CLEANUP_VAL	1

struct registry_param {
	char *name;
	char *default_value;
	struct ptype *value;
	char *description;
	unsigned int flags;

	struct registry_param *next, *prev;
	struct registry_node *parent;
};

struct registry_node {
	char *name;

	struct registry_node *branches;

	struct registry_param *params;

	struct registry_node *next, *prev;
	struct registry_node *parent;
};

int registry_init();
struct registry_node* registry_find_branch(char *path);
struct registry_param* registry_find_param(char *path);
int registry_add_branch(char *node, char *branch);
int registry_add_param(char* branch, char *param, char *default_value, struct ptype *value, char *description, int flags);
int registry_cleanup();

#endif
