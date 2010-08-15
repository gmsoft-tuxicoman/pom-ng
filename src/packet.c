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
#include "packet.h"
#include "main.h"

#include <pom-ng/ptype.h>

static struct packet_info_owner *packet_info_owner_list = NULL;
pthread_mutex_t packet_info_owner_list_lock = PTHREAD_MUTEX_INITIALIZER;

struct packet_info_owner *packet_register_info_owner(char *owner, struct packet_info_reg *info) {

	int i;
	for (i = 0; i < PACKET_INFO_MAX && info[i].name; i++) {
		if (!info[i].value_template) {
			pomlog(POMLOG_ERR "Info value template not provided for new owner");
			return NULL;
		}
	}

	struct packet_info_owner *o = malloc(sizeof(struct packet_info_owner));
	if (!o) {
		pom_oom(sizeof(struct packet_info_owner));
		return NULL;
	}
	memset(o, 0, sizeof(struct packet_info_owner));
	if (pthread_mutex_init(&o->lock, NULL)) {
		pomlog(POMLOG_ERR "Error while initializing packet_info_owner lock : %s", pom_strerror(errno));
		free(o);
		return NULL;
	}

	o->name = owner;
	memcpy(&o->info, info, sizeof(struct packet_info_reg) * (PACKET_INFO_MAX + 1));

	pom_mutex_lock(&packet_info_owner_list_lock);
	o->next = packet_info_owner_list;
	if (o->next)
		o->next->prev = o;
	packet_info_owner_list = o;
	pom_mutex_unlock(&packet_info_owner_list_lock);

	return o;
}

int packet_unregister_info_owner(struct packet_info_owner *owner) {

	if (!owner)
		return POM_ERR;

	pom_mutex_lock(&owner->lock);
	
	if (owner->refcount) {
		pomlog(POMLOG_ERR "Cannot unregister packet info owner %s as it's still being used", owner->name);
		pom_mutex_unlock(&owner->lock);
		return POM_ERR;
	}
	int i;
	for (i = 0; i < PACKET_INFO_MAX && owner->info[i].name; i++) {
		if (owner->info[i].value_template)
			ptype_cleanup(owner->info[i].value_template);
	}

	pom_mutex_lock(&packet_info_owner_list_lock);
	pom_mutex_unlock(&owner->lock);

	if (owner->next)
		owner->next->prev = owner->prev;
	if (owner->prev)
		owner->prev->next = owner->next;
	else
		packet_info_owner_list = owner->next;
	pom_mutex_unlock(&packet_info_owner_list_lock);

	pthread_mutex_destroy(&owner->lock);
	free(owner);

	return POM_OK;
}

struct packet_info_list *packet_add_infos(struct packet *p, struct packet_info_owner *owner) {

	pom_mutex_lock(&owner->lock);

	unsigned int info_count;
	for (info_count = 0; owner->info[info_count].name; info_count++);
	if (!info_count) {
		pomlog(POMLOG_ERR "Cannot add infos, owner has no info");
		goto err;
	}

	struct packet_info_list *infos = malloc(sizeof(struct packet_info_list));
	if (!infos) {
		pom_oom(sizeof(struct packet_info_list));
		goto err;
	}
	memset(infos, 0, sizeof(struct packet_info_list));

	infos->values = malloc(sizeof(struct packet_info_val) * (info_count + 1));
	if (!infos->values) {
		pom_oom(sizeof(struct packet_info_val) * (info_count + 1));
		free(infos);
		goto err;
	}
	memset(infos->values, 0, sizeof(struct packet_info_val) * (info_count + 1));

	int i;
	for (i = 0; i < info_count; i++) {
		infos->values[i].reg = &owner->info[i];
		infos->values[i].value = ptype_alloc_from(infos->values[i].reg->value_template);
		if (!infos->values[i].value) {
			pom_oom(sizeof(struct ptype));
			free(infos->values);
			free(infos);
			goto err;
		}
	}

	infos->owner = owner;

	infos->prev = p->info_tail;
	if (infos->prev)
		infos->prev->next = infos;
	else
		p->info_head = infos;
	p->info_tail = infos;
	
	owner->refcount++;
	pom_mutex_unlock(&owner->lock);

	return infos;

err:
	pom_mutex_unlock(&owner->lock);
	return NULL;

}

int packet_drop_infos(struct packet *p) {

	if (!p)
		return POM_ERR;

	while (p->info_head) {
		struct packet_info_list *infos = p->info_head;
		p->info_head = infos->next;

		pom_mutex_lock(&infos->owner->lock);


		int i;
		for (i = 0; i < PACKET_INFO_MAX; i++) {
			if (!infos->values[i].value)
				break;
			ptype_cleanup(infos->values[i].value);

		}
		free(infos->values);

		if (!infos->owner->refcount)
			pomlog(POMLOG_WARN "Warning, cannot decrement packet_info_owner refcount as it's already 0");

		infos->owner->refcount--;
		pom_mutex_unlock(&infos->owner->lock);

		free(infos);
	}
	p->info_tail = NULL;

	return POM_OK;
}

int packet_info_cleanup() {

	pom_mutex_lock(&packet_info_owner_list_lock);

	while (packet_info_owner_list) {
		struct packet_info_owner *o = packet_info_owner_list;
		packet_info_owner_list = o->next;
		int i;
		for (i = 0; i < PACKET_INFO_MAX && o->info[i].name; i++) {
			if (o->info[i].value_template)
				ptype_cleanup(o->info[i].value_template);
		}

		free(o);
	}

	pom_mutex_unlock(&packet_info_owner_list_lock);

	return POM_OK;
}
