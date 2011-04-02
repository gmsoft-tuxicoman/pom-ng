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

static pthread_mutex_t registry_class_lock = PTHREAD_MUTEX_INITIALIZER;
static struct registry_class *registry_head = NULL;

int registry_init() {

	return POM_OK;
}

int registry_cleanup() {

	while (registry_head) {
		if (registry_remove_class(registry_head) != POM_OK)
			return POM_ERR;
	}


	return POM_OK;
}

struct registry_class * registry_get_head() {
	return registry_head;
}

struct registry_class* registry_add_class(char *name) {

	if (!name)
		return NULL;

	pom_mutex_lock(&registry_class_lock);

	struct registry_class *c = registry_head;
	for (;c && strcmp(c->name, name); c = c->next);
	if (c) {
		pomlog(POMLOG_WARN "Cannot add class %s as it already exists", name);
		pom_mutex_unlock(&registry_class_lock);
		return NULL;
	}

	c = malloc(sizeof(struct registry_class));
	if (!c) {
		pom_oom(sizeof(struct registry_class));
		pom_mutex_unlock(&registry_class_lock);
		return NULL;
	}

	memset(c, 0, sizeof(struct registry_class));

	if (pthread_mutex_init(&c->lock, NULL)) {
		pomlog(POMLOG_ERR "Unable to initialize the class lock : %s", pom_strerror(errno));
		free(c);
		return NULL;
	}
	
	c->name = strdup(name);
	if (!c->name) {
		pom_mutex_unlock(&registry_class_lock);
		free(c);
		pom_oom(strlen(name));
		return NULL;
	}

	c->next = registry_head;
	if (c->next)
		registry_head->prev = c;
	registry_head = c;
	pom_mutex_unlock(&registry_class_lock);

	return c;
}

int registry_remove_class(struct registry_class *c) {

	if (!c)
		return POM_OK;

	pom_mutex_lock(&registry_class_lock);

	if (c->prev)
		c->prev->next = c->next;
	else
		registry_head = c->next;
	
	if (c->next)
		c->next->prev = c->prev;
	
	pom_mutex_unlock(&registry_class_lock);


	while (c->instances) {
		if (registry_remove_instance(c->instances) != POM_OK) {
			pomlog(POMLOG_WARN "Some error occured while removing an instance");
			break;
		}
	}

	while (c->global_params) {
		struct registry_param *p = c->global_params;
		c->global_params = p->next;

		free(p->name);
		free(p->default_value);
		free(p->description);

		pthread_mutex_destroy(&p->lock);
		
		if (p->flags & REGISTRY_FLAG_CLEANUP_VAL)
			ptype_cleanup(p->value);

		free(p);
	}

	pthread_mutex_destroy(&c->lock);

	free(c->name);

	free(c);

	return POM_OK;
}

struct registry_instance *registry_add_instance(struct registry_class *c, char *name) {

	if (!name || !c)
		return NULL;

	struct registry_instance *i = malloc(sizeof(struct registry_instance));
	if (!i) {
		pom_oom(sizeof(struct registry_instance));
		return NULL;
	}

	memset(i, 0, sizeof(struct registry_instance));

	if (pthread_mutex_init(&i->lock, NULL)) {
		free(i);
		pomlog(POMLOG_ERR "Error while initializing instance lock");
		return NULL;
	}
	
	i->name = strdup(name);
	if (!i->name) {
		free(i);
		pom_oom(strlen(name));
		return NULL;
	}



	pom_mutex_lock(&c->lock);

	i->parent = c;


	i->next = c->instances;
	if (i->next)
		i->next->prev = i;
	c->instances = i;

	pom_mutex_unlock(&c->lock);

	return i;

}

int registry_remove_instance(struct registry_instance *i) {

	if (!i)
		return POM_ERR;


	struct registry_class *c = i->parent;

	pom_mutex_lock(&c->lock);

	free(i->name);
	
	while (i->params) {
		struct registry_param *p = i->params;
		i->params = p->next;

		free(p->name);
		free(p->default_value);
		free(p->description);

		pthread_mutex_destroy(&p->lock);
		
		if (p->flags & REGISTRY_FLAG_CLEANUP_VAL)
			ptype_cleanup(p->value);

		free(p);
	}

	while (i->funcs) {
		struct registry_function *f = i->funcs;
		i->funcs = f->next;
		free(f->name);
		free(f->description);
		free(f);
	}

	if (i->prev)
		i->prev->next = i->next;
	else 
		c->instances = i->next;

	if (i->next)
		i->next->prev = i->prev;

	pom_mutex_unlock(&c->lock);

	pthread_mutex_destroy(&i->lock);

	free(i);

	return POM_OK;
}

struct registry_param* registry_new_param(char *name, char *default_value, struct ptype *value, char *description, int flags) {

	if (!name || !default_value || !value || !description)
		return NULL;

	struct registry_param *p = malloc(sizeof(struct registry_param));
	if (!p) {
		pom_oom(sizeof(struct registry_param));
		return NULL;
	}

	memset(p, 0, sizeof(struct registry_param));

	if (pthread_mutex_init(&p->lock, NULL)) {
		pomlog(POMLOG_ERR "Error while initializing the param lock : %s", pom_strerror(errno));
		goto err_name;
	}

	p->name = strdup(name);
	if (!p->name) {
		pom_oom(strlen(name));
		goto err_name;
	}

	p->default_value = strdup(default_value);
	if (!p->default_value) {
		pom_oom(strlen(default_value));
		goto err_defval;
	}

	if (ptype_parse_val(value, default_value) != POM_OK) {
		pomlog(POMLOG_ERR "Error whiel parsing default parameter \"%s\" of type \"%s\"", default_value, value->type);
		goto err_description;
	}

	p->description = strdup(description);
	if (!p->description) {
		pom_oom(strlen(description));
		goto err_description;
	}
	
	p->flags = flags;
	p->value = value;

	return p;

err_description:
	free(p->default_value);
err_defval:
	free(p->name);
err_name:
	free(p);


	return NULL;
}


int registry_param_set_check_callbacks(struct registry_param *p, void *priv, int (*pre_check) (void *priv, char *value), int (*post_check) (void *priv, struct ptype* value)) {
	
	p->check_priv = priv;
	p->set_pre_check = pre_check;
	p->set_post_check = post_check;

	return POM_OK;
}

int registry_class_add_param(struct registry_class *c, struct registry_param *p) {

	if (!c || !p)
		return POM_ERR;

	pom_mutex_lock(&c->lock);

	if (c->global_params) {
		// Add at the end
		struct registry_param *tmp = c->global_params;
		while (tmp->next)
			tmp = tmp->next;
		tmp->next = p;
		p->prev = tmp;
	} else {
		c->global_params = p;
		p->prev = NULL;
	}
	p->next = NULL;

	pom_mutex_unlock(&c->lock);

	return POM_OK;
}

int registry_instance_add_param(struct registry_instance *i, struct registry_param *p) {

	if (!i || !p)
		return POM_ERR;

	pom_mutex_lock(&i->lock);

	if (i->params) {
		// Add at the end
		struct registry_param *tmp = i->params;
		while (tmp->next)
			tmp = tmp->next;
		tmp->next = p;
		p->prev = tmp;
	} else {
		i->params = p;
		p->prev = NULL;
	}
	p->next = NULL;

	pom_mutex_unlock(&i->lock);

	return POM_OK;
}

int registry_instance_add_function(struct registry_instance *i, char *name, int (*handler) (struct registry_instance *), char *description) {

	if (!i || !name || !handler || !description)
		return POM_ERR;

	struct registry_function *f = malloc(sizeof(struct registry_function));
	if (!f) {
		pom_oom(sizeof(struct registry_function));
		return POM_ERR;
	}

	memset(f, 0, sizeof(struct registry_function));

	f->name = strdup(name);
	if (!f->name) {
		pom_oom(strlen(name));
		goto err;
	}

	f->description = strdup(description);
	if (!f->description) {
		pom_oom(strlen(description));
		goto err;
	}

	f->handler = handler;

	pom_mutex_lock(&i->lock);

	f->next = i->funcs;
	i->funcs = f;

	pom_mutex_unlock(&i->lock);

	return POM_OK;

err:
	if (f->name)
		free(name);
	if (f->description);
		free(f->description);
	
	free(f);

	return POM_ERR;
}

int registry_set_param_value(struct registry_param *p, char *value) {

	if (!p || !value)
		return POM_ERR;
	
	if (p->set_pre_check && p->set_pre_check(p->check_priv, value) != POM_OK) {
		return POM_ERR;
	}

	struct ptype *old_value = ptype_alloc_from(p->value);

	if (ptype_parse_val(p->value, value) != POM_OK) {
		ptype_cleanup(old_value);
		return POM_ERR;
	}

	if (p->set_post_check && p->set_post_check(p->check_priv, p->value) != POM_OK) {
		// Revert the old value
		ptype_copy(p->value, old_value);
		ptype_cleanup(old_value);
		return POM_ERR;
	}

	ptype_cleanup(old_value);
	
	return POM_OK;

}

struct registry_class *registry_find_class(char *cls) {


	pom_mutex_lock(&registry_class_lock);

	struct registry_class *res = registry_head;
	for (; res && strcmp(res->name, cls); res = res->next);

	pom_mutex_unlock(&registry_class_lock);

	return res;
}

struct registry_instance *registry_find_instance(char *cls, char *instance) {

	struct registry_instance *res = NULL;

	pom_mutex_lock(&registry_class_lock);
	struct registry_class *c = registry_head;

	for (; c && strcmp(c->name, cls); c = c->next);
	if (!c) {
		pom_mutex_unlock(&registry_class_lock);
		return NULL;
	}

	// Lock the class so the instance doesn't get removed
	pom_mutex_lock(&c->lock);

	pom_mutex_unlock(&registry_class_lock);
	
	for (res = c->instances; res && strcmp(res->name, instance); res = res->next);

	pom_mutex_unlock(&c->lock);

	return res;
}


