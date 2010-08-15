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
#include "core.h"
#include "input.h"
#include "packet.h"
#include "input_client.h"


struct core_thread* core_spawn_thread(struct input_client_entry *i) {
	
	struct core_thread *t = malloc(sizeof(struct core_thread));
	if (!t) {
		pom_oom(sizeof(struct core_thread));
		return NULL;
	}
	memset(t, 0, sizeof(struct core_thread));

	t->pkt = malloc(sizeof(struct packet));
	if (!t->pkt) {
		free(t);
		pom_oom(sizeof(struct packet));
		return NULL;
	}
	memset(t->pkt, 0, sizeof(struct packet));

	t->input = i;

	if (pthread_create(&t->thread, NULL, core_process_thread, (void*)t)) {
		pomlog(POMLOG_ERR "Error while creating a new processing thread : %s", pom_strerror(errno));
		free(t->pkt);
		free(t);
		return NULL;
	}

	return t;
}


void *core_process_thread(void *thread) {

	struct core_thread *t = thread;

	pomlog(POMLOG_INFO "New thread created for input %u", t->input->id);

	while (1) {

		if (input_client_get_packet(t->input, t->pkt) == POM_ERR) {
			pomlog(POMLOG_ERR "Error while reading packet");
			return NULL;
		}

		if (!t->pkt->len) {
			// EOF
			packet_drop_infos(t->pkt);
			return NULL;
		}

		if (core_process_packet(t->pkt, t->input->datalink_dep->proto) == POM_ERR) {
			packet_drop_infos(t->pkt);
			return NULL;
		}

		// Dump the packet info
		struct packet_info_list *info = t->pkt->info_head;
		while (info) {
			printf("%s{", info->owner->name);
			int i;
			for (i = 0; i < PACKET_INFO_MAX && info->values[i].value; i++) {
				char buff[256];
				ptype_print_val(info->values[i].value, buff, sizeof(buff) - 1);
				printf("%s : %s; ", info->values[i].reg->name, buff);
			}
			printf("} ");

			info = info->next;

		}
		printf("\n");

		// Cleanup the info which were added
		packet_drop_infos(t->pkt);
	}

	return NULL;
}

int core_destroy_thread(struct core_thread *t) {

	if (input_client_wait_for_empty_buff(t->input) == POM_ERR)
		return POM_ERR;

	if (pthread_join(t->thread, NULL)) {
		pomlog(POMLOG_ERR "Error while joining a processing thread : %s", pom_strerror(errno));
		return POM_ERR;
	}
	if (t->pkt->buff)
		free(t->pkt->buff);
	free(t->pkt);
	free(t);

	return POM_OK;
}

int core_process_packet(struct packet *p, struct proto_reg *datalink) {

	struct proto_process_state s;
	memset(&s, 0, sizeof(struct proto_process_state));
	s.pload = p->buff;
	s.plen = p->len;
	s.next_proto = datalink;

	while (s.next_proto) {
		if (proto_process(s.next_proto, p, &s) == POM_ERR) {
			pomlog(POMLOG_ERR "Error while processing packet");
			return POM_ERR;
		}
	}

	return POM_OK;
}
