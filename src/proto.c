/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2010-2012 Guy Martin <gmsoft@tuxicoman.be>
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
#include "filter.h"

static struct proto *proto_head = NULL;

static pthread_mutex_t proto_list_lock = PTHREAD_MUTEX_INITIALIZER;

static struct registry_class *proto_registry_class = NULL;

int proto_init() {
	
	proto_registry_class = registry_add_class(PROTO_REGISTRY);
	if (!proto_registry_class)
		return POM_ERR;

	return POM_OK;
}

int proto_register(struct proto_reg_info *reg_info) {

	if (reg_info->api_ver != PROTO_API_VER) {
		pomlog(POMLOG_ERR "Cannot register proto as API version differ : expected %u got %u", PROTO_API_VER, reg_info->api_ver);
		return POM_ERR;
	}


	pom_mutex_lock(&proto_list_lock);

	// Check if the protocol already exists
	struct proto *proto;
	for (proto = proto_head; proto && strcmp(proto->info->name, reg_info->name); proto = proto->next);
	if (proto) {
		pom_mutex_unlock(&proto_list_lock);
		return POM_ERR;
	}

	// Allocate the protocol
	proto = malloc(sizeof(struct proto));
	if (!proto) {
		pom_mutex_unlock(&proto_list_lock);
		pom_oom(sizeof(struct proto));
		return POM_ERR;
	}

	memset(proto, 0, sizeof(struct proto));
	proto->info = reg_info;

	

	if (packet_info_pool_init(&proto->pkt_info_pool)) {
		pomlog(POMLOG_ERR "Error while initializing the pkt_info_pool");
		goto err_proto;
	}

	// Allocate the conntrack table
	if (reg_info->ct_info) {
		proto->ct = conntrack_tables_alloc(reg_info->ct_info->default_table_size, (reg_info->ct_info->rev_pkt_field_id == -1 ? 0 : 1));
		if (!proto->ct) {
			pomlog(POMLOG_ERR "Error while allocating conntrack tables");
			goto err_packet_info;
		}
	}

	proto->reg_instance = registry_add_instance(proto_registry_class, reg_info->name);
	if (!proto->reg_instance) {
		pomlog(POMLOG_ERR "Error while adding the registry instanc for protocol %s", reg_info->name);
		goto err_conntrack;
	}

	if (reg_info->init) {
		if (reg_info->init(proto, proto->reg_instance) == POM_ERR) {
			pomlog(POMLOG_ERR "Error while registering proto %s", reg_info->name);
			goto err_registry;
		}
	}



	mod_refcount_inc(reg_info->mod);

	proto->next = proto_head;
	if (proto->next)
		proto->next->prev = proto;
	proto_head = proto;

	pom_mutex_unlock(&proto_list_lock);

	pomlog(POMLOG_DEBUG "Proto %s registered", reg_info->name);

	return POM_OK;

err_registry:
	registry_remove_instance(proto->reg_instance);
err_conntrack:
	conntrack_tables_cleanup(proto->ct);
err_packet_info:
	packet_info_pool_cleanup(&proto->pkt_info_pool);
err_proto:
	free(proto);

	pom_mutex_unlock(&proto_list_lock);

	return POM_ERR;

}

int proto_process(struct packet *p, struct proto_process_stack *s, unsigned int stack_index) {

	if (!s)
		return PROTO_ERR;
	
	struct proto *proto = s[stack_index].proto;

	if (!proto || !proto->info->process)
		return PROTO_ERR;
	int result = proto->info->process(proto, p, s, stack_index);

	if (result == PROTO_OK && s[stack_index].plen) {
		
		// Process packet listeners

	}

	return result;
}

int proto_process_listeners(struct packet *p, struct proto_process_stack *s, unsigned int stack_index) {

	if (!s[stack_index].plen)
		return POM_OK;

	// Process packet listeners
	struct proto *proto = s[stack_index].proto;
	
	if (!proto)
		return POM_OK;

	struct proto_packet_listener *l;
	for (l = proto->packet_listeners; l; l = l->next) {
		if (l->filter && !filter_proto_match(s, l->filter))
			continue;
		if (l->process(l->object, p, s, stack_index) != POM_OK) {
			pomlog(POMLOG_WARN "Warning packet listener failed");
			// FIXME remove listener from the list ?
		}
	}

	// Process payload listeners
	if (s[stack_index + 1].plen) {
		for (l = proto->payload_listeners; l; l = l->next) {
			if (l->filter && !filter_proto_match(s, l->filter))
				continue;
			if (l->process(l->object, p, s, stack_index + 1) != POM_OK) {
				pomlog(POMLOG_WARN "Warning payload listener failed");
				// FIXME remove listener from the list ?
			}
		}
	}

	return POM_OK;
}

int proto_post_process(struct packet *p, struct proto_process_stack *s, unsigned int stack_index) {

	if (!s)
		return PROTO_ERR;
	
	struct proto *proto = s[stack_index].proto;

	if (!proto)
		return PROTO_ERR;
	
	if (proto->info->post_process)
		return proto->info->post_process(proto, p, s, stack_index);

	return POM_OK;
}

int proto_unregister(char *name) {

	pom_mutex_lock(&proto_list_lock);
	struct proto *proto;
	for (proto = proto_head; proto && strcmp(proto->info->name, name); proto = proto->next);
	if (!proto) {
		pom_mutex_unlock(&proto_list_lock);
		return POM_OK;
	}
	
	if (proto->info->cleanup && proto->info->cleanup(proto)) {
		pom_mutex_unlock(&proto_list_lock);
		pomlog(POMLOG_ERR "Error while cleaning up the protocol %s", name);
		return POM_ERR;
	}

	if (proto->reg_instance)
		registry_remove_instance(proto->reg_instance);

		conntrack_tables_cleanup(proto->ct);

	packet_info_pool_cleanup(&proto->pkt_info_pool);
	
	if (proto->next)
		proto->next->prev = proto->prev;
	if (proto->prev)
		proto->prev->next = proto->next;
	else
		proto_head = proto->next;

	mod_refcount_dec(proto->info->mod);

	free(proto);

	pom_mutex_unlock(&proto_list_lock);

	return POM_OK;
}

struct proto *proto_get(char *name) {
	
	struct proto *tmp;
	for (tmp = proto_head; tmp && strcmp(tmp->info->name, name); tmp = tmp->next);

	if (!tmp)
		pomlog(POMLOG_WARN "Proto %s not found !", name);

	return tmp;
}

int proto_empty_conntracks() {

	pom_mutex_lock(&proto_list_lock);
	struct proto *proto;
	for (proto = proto_head; proto; proto = proto->next) {
		conntrack_tables_empty(proto->ct);
	}
	pom_mutex_unlock(&proto_list_lock);

	return POM_OK;
}

int proto_cleanup() {

	pom_mutex_lock(&proto_list_lock);

	
	struct proto *proto;
	for (proto = proto_head; proto; proto = proto->next) {

		if (proto->info->cleanup && proto->info->cleanup(proto) == POM_ERR)
			pomlog(POMLOG_WARN "Error while cleaning up protocol %s", proto->info->name);
		conntrack_tables_cleanup(proto->ct);

		mod_refcount_dec(proto->info->mod);
		packet_info_pool_cleanup(&proto->pkt_info_pool);
	}

	while (proto_head) {
		proto = proto_head;
		proto_head = proto->next;
		free(proto);
	}

	pom_mutex_unlock(&proto_list_lock);

	if (proto_registry_class)
		registry_remove_class(proto_registry_class);
	proto_registry_class = NULL;

	return POM_OK;
}

struct proto_packet_listener *proto_packet_listener_register(struct proto *proto, unsigned int flags, void *object, int (*process) (void *object, struct packet *p, struct proto_process_stack *s, unsigned int stack_index)) {

	struct proto_packet_listener *l = malloc(sizeof(struct proto_packet_listener));
	if (!l) {
		pom_oom(sizeof(struct proto_packet_listener));
		return NULL;
	}
	memset(l, 0, sizeof(struct proto_packet_listener));

	l->flags = flags;
	l->process = process;
	l->proto = proto;
	l->object = object;

	if (l->flags & PROTO_PACKET_LISTENER_PLOAD_ONLY)
		l->next = proto->payload_listeners;
	else
		l->next = proto->packet_listeners;

	if (l->next)
		l->next->prev = l;

	if (l->flags & PROTO_PACKET_LISTENER_PLOAD_ONLY)
		proto->payload_listeners = l;
	else
		proto->packet_listeners = l;

	return l;
}

int proto_packet_listener_unregister(struct proto_packet_listener *l) {

	if (!l)
		return POM_ERR;

	if (l->next)
		l->next->prev = l->prev;

	if (l->prev) {
		l->prev->next = l->next;
	} else {
		if (l->flags & PROTO_PACKET_LISTENER_PLOAD_ONLY)
			l->proto->payload_listeners = l->next;
		else
			l->proto->packet_listeners = l->next;
	}

	free(l);

	return POM_OK;
}

void proto_packet_listener_set_filter(struct proto_packet_listener *l, struct filter_proto *f) {
	l->filter = f;
}
