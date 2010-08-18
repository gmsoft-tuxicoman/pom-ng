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
#include "proto.h"
#include "main.h"
#include "mod.h"
#include "input_server.h"

static struct proto_reg *proto_head = NULL;

static struct proto_dependency *proto_dependency_head = NULL;
static pthread_mutex_t proto_dependency_list_lock = PTHREAD_MUTEX_INITIALIZER;


int proto_register(struct proto_reg_info *reg_info) {

	if (input_server_is_current_process()) {
		pomlog(POMLOG_DEBUG "Not loading protocol %s in the input process", reg_info->name);
		return POM_OK;
	}

	// Check if the protocol already exists
	struct proto_reg *proto;
	for (proto = proto_head; proto && strcmp(proto->info->name, reg_info->name); proto = proto->next);
	if (proto)
		return POM_ERR;

	proto = malloc(sizeof(struct proto_reg));
	if (!proto) {
		pom_oom(sizeof(struct proto_reg));
		return POM_ERR;
	}

	memset(proto, 0, sizeof(struct proto_reg));
	proto->info = reg_info;

	if (reg_info->init) {
		if (reg_info->init() == POM_ERR) {
			free(proto);
			pomlog(POMLOG_ERR "Error while registering proto %s", reg_info->name);
			return POM_ERR;
		}
	}


	mod_refcount_inc(reg_info->mod);

	proto->next = proto_head;
	if (proto->next)
		proto->next->prev = proto;
	proto_head = proto;

	// Update dependencies
	struct proto_dependency *dep;
	for (dep = proto_dependency_head; dep && strcmp(dep->name, reg_info->name); dep = dep->next);
	if (dep) {
		dep->proto = proto;
		proto->dep = dep;
	}

	pomlog(POMLOG_DEBUG "Proto %s registered", reg_info->name);

	return POM_OK;

}

int proto_process(struct proto_reg *proto, struct packet *p, struct proto_process_state *s) {

	if (!proto || !proto->info->process)
		return POM_ERR;
	return proto->info->process(p, s);
}

int proto_unregister(char *name) {

	struct proto_reg *proto;
	for (proto = proto_head; proto && strcmp(proto->info->name, name); proto = proto->next);
	if (!proto)
		return POM_OK;
	
	if (proto->info->cleanup && proto->info->cleanup()) {
		pomlog(POMLOG_ERR "Error while cleaning up the protocol %s", name);
		return POM_ERR;
	}

	if (proto->dep)
		proto->dep->proto = NULL;
	
	if (proto->next)
		proto->next->prev = proto->prev;
	if (proto->prev)
		proto->prev->next = proto->next;
	else
		proto_head = proto->next;

	mod_refcount_dec(proto->info->mod);

	free(proto);

	return POM_OK;
}

struct proto_dependency *proto_add_dependency(char *name) {


	pom_mutex_lock(&proto_dependency_list_lock);

	struct proto_dependency *dep = proto_dependency_head;

	for (; dep && strcmp(dep->name, name); dep = dep->next);
	if (!dep) {
		dep = malloc(sizeof(struct proto_dependency));
		if (!dep) {
			pom_mutex_unlock(&proto_dependency_list_lock);
			pom_oom(sizeof(struct proto_dependency));
			return NULL;
		}
		memset(dep, 0, sizeof(struct proto_dependency));
		dep->name = strdup(name);
		if (!dep->name) {
			pom_mutex_unlock(&proto_dependency_list_lock);
			pom_oom(strlen(name));
			free(dep);
			return NULL;

		}
		strcpy(dep->name, name);
		
		struct proto_reg *proto;
		for (proto = proto_head; proto && strcmp(proto->info->name, name); proto = proto->next);
		if (proto) {
			if (proto->dep) {
				pom_mutex_unlock(&proto_dependency_list_lock);
				pomlog(POMLOG_ERR "Internal error, the proto should have a dependency already");
				free(dep->name);
				free(dep);
				return NULL;
			}
			proto->dep = dep;
			dep->proto = proto;
		}

		dep->next = proto_dependency_head;
		if (dep->next)
			dep->next->prev = dep;
		proto_dependency_head = dep;
	}
	dep->refcount++;
	pom_mutex_unlock(&proto_dependency_list_lock);
	
	return dep;
}

int proto_remove_dependency(struct proto_dependency *dep) {

	if (!dep)
		return POM_ERR;

	pom_mutex_lock(&proto_dependency_list_lock);

	if (!dep->refcount)
		pomlog(POMLOG_WARN "Warning, depcount already at 0 for dependency %s", dep->name);
	else
		dep->refcount--;

	if (!dep->refcount) {
		if (dep->next)
			dep->next->prev = dep->prev;
		if (dep->prev)
			dep->prev->next = dep->next;
		else
			proto_dependency_head = dep->next;

		if (dep->proto)
			dep->proto->dep = NULL;
	
		free(dep->name);
		free(dep);
	}

	pom_mutex_unlock(&proto_dependency_list_lock);

	return POM_OK;
}

int proto_cleanup() {

	while (proto_head) {
		struct proto_reg *proto = proto_head;
		proto_head = proto->next;
		if (proto->info->cleanup && proto->info->cleanup() == POM_ERR)
			pomlog(POMLOG_WARN "Error while cleaning up protocol %s", proto->info->name);
		if (proto->dep)
			proto->dep->proto = NULL;
		mod_refcount_dec(proto->info->mod);
		free(proto);
	}

	pom_mutex_lock(&proto_dependency_list_lock);

	struct proto_dependency *dep = proto_dependency_head;
	while (dep) {
		if (dep->refcount) {
			pomlog(POMLOG_WARN "Cannot remove dep for %s, refcount is %u", dep->name, dep->refcount);
			dep = dep->next;
			continue;
		}

		struct proto_dependency *tmp = dep;
		dep = tmp->next;

		if (tmp->next)
			tmp->next->prev = tmp->prev;
		if (tmp->prev)
			tmp->prev->next = tmp->next;
		else
			proto_dependency_head = tmp->next;
	
		free(tmp);
	}

	pom_mutex_unlock(&proto_dependency_list_lock);

	return POM_OK;
}
