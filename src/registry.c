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

#include "common.h"
#include "registry.h"
#include <pom-ng/ptype.h>

static struct registry_node *registry_root = NULL;

int registry_init() {


	registry_root = malloc(sizeof(struct registry_node));
	if (!registry_root)
		return POM_ERR;

	memset(registry_root, 0, sizeof(struct registry_node));
	
	registry_root->name = strdup("root");
	if (!registry_root->name) {
		free(registry_root);
		registry_root = NULL;
		return POM_ERR;
	}

	
	return POM_OK;
}

struct registry_node* registry_find_branch(char *path) {

	char *my_node = strdup(path);
	if (!my_node) {
		pom_oom(strlen(path));
		return NULL;
	}

	struct registry_node *n = registry_root, *nup = NULL;

	char *str, *token, *saveptr = NULL;
	for (str = my_node; ;str = NULL) {
		token = strtok_r(str, ".", &saveptr);
		if (!token)
			break;

		for (;n && strcmp(n->name, token); n = n->next);
		if (!n) {
			free(my_node);
			return NULL;
		}

		nup = n;
		n = n->branches;
	}
	free(my_node);

	return nup;

}

struct registry_param* registry_find_param(char *path) {

	char *my_path = strdup(path);
	if (!my_path) {
		pom_oom(strlen(path));
		return NULL;
	}
	
	char *param = strrchr(my_path, '.');
	if (!param) {
		free(my_path);
		return NULL;
	}

	*param = 0;
	param ++;

	struct registry_node *n = registry_find_branch(my_path);
	if (!n) {
		free(my_path);
		return NULL;
	}

	struct registry_param *p;
	for (p = n->params; p && strcmp(p->name, param); p = p->next);

	free(my_path);

	return p;
}


int registry_add_branch(char *parent, char *branch) {


	struct registry_node *n = registry_find_branch(parent);
	if (!n) {
		pomlog(POMLOG_WARN "Cannot add branch \"%s\". Parent %s not found" , branch, parent);
		return POM_ERR;
	}

	struct registry_node *b = malloc(sizeof(struct registry_node));
	if (!b) {
		pom_oom(sizeof(struct registry_node));
		return POM_ERR;
	}

	memset(b, 0, sizeof(struct registry_node));
	b->name = strdup(branch);
	if (!b->name) {
		pom_oom(strlen(branch));
		free(b);
		return POM_ERR;
	}
		
	b->next = n->branches;
	if (b->next)
		b->next->prev = b;
	
	n->branches = b;
	b->parent = n;

	pomlog(POMLOG_DEBUG "Added branch %s.%s", parent, branch);

	return POM_OK;
}

int registry_add_param(char* branch, char *param, char *default_value, struct ptype *value, char *description, int flags) {

	struct registry_node *n = registry_find_branch(branch);
	if (!n) {
		pomlog(POMLOG_WARN "Cannot add param \"%s\". Branch %s not found" , param, branch);
		return POM_ERR;
	}

	struct registry_param *p = malloc(sizeof(struct registry_param));
	if (!p) {
		pom_oom(sizeof(struct registry_param));
		return POM_ERR;
	}

	memset(p, 0, sizeof(struct registry_param));
	p->name = strdup(param);
	if (!p->name) {
		pom_oom(strlen(param));
		goto err_name;
	}

	p->default_value = strdup(default_value);
	if (!p->default_value) {
		pom_oom(strlen(default_value));
		goto err_defval;
	}

	p->description = strdup(description);
	if (!p->description) {
		pom_oom(strlen(description));
		goto err_description;
	}
	
	p->flags = flags;
	p->value = value;

	p->next = n->params;
	if (p->next)
		p->next->prev = p;

	n->params = p;
	p->parent = n;

	pomlog(POMLOG_DEBUG "Added parameter %s.%s", branch, param);

	return POM_OK;

err_description:
	free(p->default_value);
err_defval:
	free(p->name);
err_name:
	free(p);


	return POM_ERR;
}

int registry_remove_branch(struct registry_node *b) {

	// Destroy recursively
	while (b->branches) {
		struct registry_node *child = b->branches;
		b->branches = child->next;

		registry_remove_branch(child);
	}

	while (b->params) {
		struct registry_param *p = b->params;
		b->params = p->next;

		free(p->name);
		free(p->default_value);
		free(p->description);
		
		if (p->flags & REGISTRY_FLAG_CLEANUP_VAL)
			ptype_cleanup(p->value);

		free(p);
	}


	if (b->next)
		b->next->prev = b->prev;
	

	if (b->prev) {
		b->prev->next = b->next;
	} else {
		if (b->parent)
			b->parent->branches = b->next;
	}
	
	free(b->name);
	free(b);

	return POM_OK;
}

int registry_cleanup() {

	if (!registry_root)
		return POM_OK;

	registry_remove_branch(registry_root);

	registry_root = NULL;

	return POM_OK;
}

