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
static unsigned int packet_info_owner_count = 0;
int packet_register_info_owner(char *owner, struct packet_info_reg *info) {

	int i;
	for (i = 0; i < PACKET_INFO_MAX && info[i].name; i++) {
		if (!(info[i].flags & PACKET_INFO_FLAG_OPTIONAL) && !info[i].value_template) {
			pomlog(POMLOG_ERR "Non optional value template not provided");
			return POM_ERR;
		}
	}

	packet_info_owner_list = realloc(packet_info_owner_list, sizeof(struct packet_info_owner) * (packet_info_owner_count + 1));
	if (!packet_info_owner_list) {
		pom_oom(sizeof(struct packet_info_owner) * (packet_info_owner_count + 1));
		packet_info_owner_count = 0;
		halt("Packet info owner table was lost");
		return POM_ERR;
	}

	struct packet_info_owner *o = &packet_info_owner_list[packet_info_owner_count];
	memset(o, 0, sizeof(struct packet_info_owner));
	packet_info_owner_count++;
	o->name = owner;
	memcpy(&o->info, info, sizeof(struct packet_info_reg) * (PACKET_INFO_MAX + 1));

	return packet_info_owner_count - 1;
}

int packet_unregister_info_owner(unsigned int owner) {


	return POM_ERR;
}

struct packet_info_list *packet_add_infos(struct packet *p, unsigned int owner) {


	if (owner >= packet_info_owner_count || !packet_info_owner_list[owner].name) {
		pomlog(POMLOG_ERR "Cannot add owner, invalid owner id %u", owner);
		return NULL;
	}

	unsigned int info_count;
	for (info_count = 0; packet_info_owner_list[owner].info[info_count].name; info_count++);
	if (!info_count) {
		pomlog(POMLOG_ERR "Cannot add infos, owner has no info");
		return NULL;
	}

	struct packet_info_list *infos = malloc(sizeof(struct packet_info_list));
	if (!infos) {
		pom_oom(sizeof(struct packet_info_list));
		return NULL;
	}
	memset(infos, 0, sizeof(struct packet_info_list));

	infos->values = malloc(sizeof(struct packet_info_val) * (info_count + 1));
	if (!infos->values) {
		pom_oom(sizeof(struct packet_info_val) * (info_count + 1));
		free(infos);
		return NULL;
	}
	memset(infos->values, 0, sizeof(struct packet_info_val) * (info_count + 1));

	int i;
	for (i = 0; i < info_count; i++) {
		infos->values[i].reg = &packet_info_owner_list[owner].info[i];
		if (!(infos->values[i].reg->flags & PACKET_INFO_FLAG_OPTIONAL)) {
			infos->values[i].value = ptype_alloc_from(infos->values[i].reg->value_template);
			if (!infos->values[i].value) {
				pom_oom(sizeof(struct ptype));
				free(infos->values);
				free(infos);
				return NULL;
			}
		}
	}

	infos->owner = owner;

	infos->prev = p->info_tail;
	if (infos->prev)
		infos->prev->next = infos;
	else
		p->info_head = infos;
	p->info_tail = infos;

	return infos;
}

int packet_drop_infos(struct packet *p) {

	while (p->info_head) {
		struct packet_info_list *infos = p->info_head;
		p->info_head = infos->next;

		int i;
		for (i = 0; i < PACKET_INFO_MAX; i++) {
			if (!infos->values[i].value)
				break;
			ptype_cleanup(infos->values[i].value);

		}
		free(infos->values);
		free(infos);

	}
	p->info_tail = NULL;

	return POM_OK;
}

int packet_info_cleanup() {

	int j;
	for (j = 0; j < packet_info_owner_count; j++) {
		struct packet_info_owner *o = &packet_info_owner_list[j];
		int i;
		for (i = 0; i < PACKET_INFO_MAX && o->info[i].name; i++) {
			if (o->info[i].value_template)
				ptype_cleanup(o->info[i].value_template);
		}


	}

	if (packet_info_owner_count) {
		free(packet_info_owner_list);
		packet_info_owner_list = NULL;
		packet_info_owner_count = 0;
	}

	return POM_OK;
}
