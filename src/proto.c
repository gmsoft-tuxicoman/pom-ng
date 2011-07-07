/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2010-2011 Guy Martin <gmsoft@tuxicoman.be>
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
static pthread_mutex_t proto_list_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t proto_dependency_list_lock = PTHREAD_MUTEX_INITIALIZER;

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


	if (input_server_is_current_process()) {
		pomlog(POMLOG_DEBUG "Not loading protocol %s in the input process", reg_info->name);
		return POM_OK;
	}

	pom_mutex_lock(&proto_list_lock);

	// Check if the protocol already exists
	struct proto_reg *proto;
	for (proto = proto_head; proto && strcmp(proto->info->name, reg_info->name); proto = proto->next);
	if (proto) {
		pom_mutex_unlock(&proto_list_lock);
		return POM_ERR;
	}

	// Allocate the protocol
	proto = malloc(sizeof(struct proto_reg));
	if (!proto) {
		pom_mutex_unlock(&proto_list_lock);
		pom_oom(sizeof(struct proto_reg));
		return POM_ERR;
	}

	memset(proto, 0, sizeof(struct proto_reg));
	proto->info = reg_info;

	

	if (packet_info_pool_init(&proto->pkt_info_pool)) {
		pomlog(POMLOG_ERR "Error while initializing the pkt_info_pool");
		goto err_proto;
	}

	// Allocate the conntrack table
	if (reg_info->ct_info.default_table_size) {
		proto->ct = conntrack_tables_alloc(reg_info->ct_info.default_table_size, (reg_info->ct_info.rev_pkt_field_id == -1 ? 0 : 1));
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
		if (reg_info->init(proto->reg_instance) == POM_ERR) {
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

	pom_mutex_lock(&proto_dependency_list_lock);
	// Update dependencies
	struct proto_dependency *dep;
	for (dep = proto_dependency_head; dep && strcmp(dep->name, reg_info->name); dep = dep->next);
	if (dep) {
		dep->proto = proto;
		proto->dep = dep;
	}
	pom_mutex_unlock(&proto_dependency_list_lock);

	pomlog(POMLOG_DEBUG "Proto %s registered", reg_info->name);

	return POM_OK;

err_registry:
	registry_remove_instance(proto->reg_instance);
err_conntrack:
	conntrack_tables_free(proto->ct);
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
	
	struct proto_reg *proto = s[stack_index].proto;

	if (!proto || !proto->info->process)
		return PROTO_ERR;
	int result = proto->info->process(p, s, stack_index);

	if (result == PROTO_OK) {
		struct proto_packet_listener *l = proto->packet_listeners;
		while (l) {
			int listener_res = POM_OK;
			if (l->flags & PROTO_PACKET_LISTENER_PLOAD_ONLY) {
				if (s[stack_index + 1].plen)
					listener_res = l->process(l->object, p, s, stack_index + 1);

			} else {
				listener_res = l->process(l->object, p, s, stack_index);
			}
			if (listener_res != POM_OK) {
				pomlog(POMLOG_WARN "Warning listener failed");
				// FIXME remove listener from the list ?
			}

			l = l->next;
		}
	}

	return result;
}

int proto_unregister(char *name) {

	pom_mutex_lock(&proto_list_lock);
	struct proto_reg *proto;
	for (proto = proto_head; proto && strcmp(proto->info->name, name); proto = proto->next);
	if (!proto) {
		pom_mutex_unlock(&proto_list_lock);
		return POM_OK;
	}
	
	if (proto->info->cleanup && proto->info->cleanup()) {
		pom_mutex_unlock(&proto_list_lock);
		pomlog(POMLOG_ERR "Error while cleaning up the protocol %s", name);
		return POM_ERR;
	}

	if (proto->reg_instance)
		registry_remove_instance(proto->reg_instance);

	if (proto->dep)
		proto->dep->proto = NULL;

	conntrack_tables_free(proto->ct);

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

void proto_dependency_refcount_inc(struct proto_dependency *proto_dep) {
	
	pom_mutex_lock(&proto_dependency_list_lock);
	proto_dep->refcount++;
	pom_mutex_unlock(&proto_dependency_list_lock);

}

int proto_remove_dependency(struct proto_dependency *dep) {

	if (!dep)
		return POM_ERR;

	pom_mutex_lock(&proto_dependency_list_lock);

	if (!dep->refcount)
		pomlog(POMLOG_WARN "Warning, refcount already at 0 for dependency %s", dep->name);
	else
		dep->refcount--;
/*
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
*/
	pom_mutex_unlock(&proto_dependency_list_lock);

	return POM_OK;
}

int proto_cleanup() {

	pom_mutex_lock(&proto_list_lock);

	
	struct proto_reg *proto = proto_head;
	int forced = 0;
	while (proto_head) {
		if (!forced && proto->dep && proto->dep->refcount) {
			proto = proto->next;
			if (!proto) {
				pomlog(POMLOG_ERR "Some proto are still in use, forcing cleanup anyway");
				forced = 1;
				proto = proto_head;
			}
			continue;
		}

		if (forced && proto->dep->refcount)
			pomlog(POMLOG_WARN "Proto %s still has a refcount of %u", proto->dep->name, proto->dep->refcount);
			
		if (proto->info->cleanup && proto->info->cleanup() == POM_ERR)
			pomlog(POMLOG_WARN "Error while cleaning up protocol %s", proto->info->name);
		conntrack_tables_free(proto->ct);

		mod_refcount_dec(proto->info->mod);
		packet_info_pool_cleanup(&proto->pkt_info_pool);

		struct proto_reg *tmp = proto;
		if (!proto->prev) {
			proto_head = proto_head->next;
			if (proto_head)
				proto_head->prev = NULL;
		} else {
			proto->prev->next = proto->next;
		}
		
		if (proto->next)
			proto->next->prev = proto->prev;
		free(tmp);

		proto = proto_head;
	}
	pom_mutex_unlock(&proto_list_lock);

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
	
		free(tmp->name);
		free(tmp);
	}

	pom_mutex_unlock(&proto_dependency_list_lock);

	if (proto_registry_class)
		registry_remove_class(proto_registry_class);
	proto_registry_class = NULL;

	return POM_OK;
}


struct proto_event *proto_event_alloc(struct proto_reg *proto, unsigned int evt_id) {

	struct proto_event *evt = malloc(sizeof(struct proto_event));
	if (!evt) {
		pom_oom(sizeof(struct proto_event));
		return NULL;
	}
	memset(evt, 0, sizeof(struct proto_event));

	struct proto_event_reg *evt_reg = &proto->info->events[evt_id];
	evt->evt_reg = evt_reg;

	struct proto_event_data *data = malloc(sizeof(struct proto_event_data) * evt_reg->data_count);
	if (!data) {
		pom_oom(sizeof(struct proto_event_data) * evt_reg->data_count);
		free(evt);
		return NULL;
	}
	memset(data, 0, sizeof(struct proto_event_data) * evt_reg->data_count);
	
	int i;
	for (i = 0; i < evt_reg->data_count; i++) {
		// Allocate a ptype for each non list items
		if (!(evt_reg->data[i].flags & PROTO_EVENT_DATA_FLAG_LIST)) {
			data[i].value = ptype_alloc_from(evt_reg->data[i].value_template);
			if (!data[i].value)
				goto err;
		}
	}
	evt->data = data;
	evt->proto = proto;

	return evt;
err:

	for (i = 0; i < evt_reg->data_count; i++) {
		if (data[i].value)
			ptype_cleanup(data[i].value);
	}

	free(data);
	free(evt);

	return NULL;
}

struct ptype *proto_event_data_item_add(struct proto_event *evt, unsigned int data_id, char *key) {

	struct proto_event_data_item *itm = malloc(sizeof(struct proto_event_data_item));
	if (!itm) {
		pom_oom(sizeof(struct proto_event_data_item));
		return NULL;
	}
	memset(itm, 0, sizeof(struct proto_event_data_item));
	
	itm->key = key;

	itm->value = ptype_alloc_from(evt->evt_reg->data[data_id].value_template);
	if (!itm->value) {
		free(itm);
		return NULL;
	}

	itm->next = evt->data[data_id].items;
	evt->data[data_id].items = itm;
	return itm->value;
}

int proto_event_process(struct proto_event *evt, struct proto_process_stack *stack, unsigned int stack_index) {

	if (evt->flags & PROTO_EVENT_FLAG_PROCESSED) {
		pomlog(POMLOG_ERR "Internal error, proto event already processed");
		return POM_ERR;
	}

	struct proto_event_analyzer_list *lst = evt->proto->event_analyzers;
	for (; lst; lst = lst->next) {
		if (lst->analyzer_reg->process(lst->analyzer_reg->analyzer, evt, stack, stack_index) != POM_OK) {
			pomlog(POMLOG_WARN "An analyzer returned an error when processing event %s", evt->evt_reg->name);
			// FIXME : remove the analyzer from the list ?
		}
	}

	evt->flags |= PROTO_EVENT_FLAG_PROCESSED;

	return POM_OK;
}

int proto_event_reset(struct proto_event *evt, struct conntrack_entry *ce) {

	struct proto_event_analyzer_list *lst = evt->proto->event_analyzers;
	for (; lst; lst = lst->next) {
		if (lst->analyzer_reg->expire) {
			if (lst->analyzer_reg->expire(lst->analyzer_reg->analyzer, evt, ce) != POM_OK) {
				pomlog(POMLOG_WARN "An analyzer returned an error when processing event %s", evt->evt_reg->name);
				// FIXME : remove the analyzer from the list ?
			}
		}
	}

	int i;
	for (i = 0; i < evt->evt_reg->data_count; i++) {
		if (evt->evt_reg->data[i].flags & PROTO_EVENT_DATA_FLAG_LIST) {
			struct proto_event_data_item *itm = evt->data[i].items;
			while (itm) {
				struct proto_event_data_item *next = itm->next;
				free(itm->key);
				ptype_cleanup(itm->value);
				free(itm);
				itm = next;
			}
			evt->data[i].items = NULL;

		} else {
			evt->data[i].set = 0;
		}

	}

	evt->flags &= ~PROTO_EVENT_FLAG_PROCESSED;

	return POM_OK;
}


int proto_event_cleanup(struct proto_event *evt) {

	int i;
	for (i = 0; i < evt->evt_reg->data_count; i++) {
		if (evt->evt_reg->data[i].flags & PROTO_EVENT_DATA_FLAG_LIST) {
			struct proto_event_data_item *itm = evt->data[i].items;
			while (itm) {
				struct proto_event_data_item *next = itm->next;
				free(itm->key);
				ptype_cleanup(itm->value);
				free(itm);
				itm = next;
			}

		} else {
			ptype_cleanup(evt->data[i].value);
		}

	}

	free(evt->data);
	free(evt);
	return POM_OK;
}


int proto_event_analyzer_register(struct proto_reg *proto, struct proto_event_analyzer_reg *analyzer_reg) {

	struct proto_event_analyzer_list *lst = malloc(sizeof(struct proto_event_analyzer_list));
	if (!lst) {
		pom_oom(sizeof(struct proto_event_analyzer_list));
		return POM_ERR;
	}
	memset(lst, 0, sizeof(struct proto_event_analyzer_list));

	lst->analyzer_reg = analyzer_reg;
	lst->next = proto->event_analyzers;
	if (lst->next)
		lst->next->prev = lst;
	proto->event_analyzers = lst;

	return POM_OK;
}

int proto_event_analyzer_unregister(struct proto_reg *proto, struct analyzer_reg *analyzer) {

	struct proto_event_analyzer_list *lst = proto->event_analyzers;
	for (; lst && lst->analyzer_reg->analyzer != analyzer; lst = lst->next);

	if (!lst) {
		pomlog(POMLOG_ERR "Cannot unregister event analyzer from proto %s, analyzer not found", proto->info->name);
		return POM_ERR;
	}

	if (lst->next)
		lst->next->prev = lst->prev;

	if (lst->prev)
		lst->prev->next = lst->next;
	else
		proto->event_analyzers = lst->next;

	free(lst);

	return POM_OK;
}


struct proto_packet_listener *proto_packet_listener_register(struct proto_reg *proto, unsigned int flags, void *object, int (*process) (void *object, struct packet *p, struct proto_process_stack *s, unsigned int stack_index)) {

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

	l->next = proto->packet_listeners;
	if (l->next)
		l->next->prev = l;
	
	proto->packet_listeners = l;

	return l;
}

int proto_packet_listener_unregister(struct proto_packet_listener *l) {

	if (!l)
		return POM_ERR;

	if (l->next)
		l->next->prev = l->prev;

	if (l->prev)
		l->prev->next = l->next;
	else
		l->proto->packet_listeners = l->next;

	free(l);

	return POM_OK;
}
