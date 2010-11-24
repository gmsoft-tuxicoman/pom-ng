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
#include "packet.h"
#include "conntrack.h"


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
			//packet_drop_infos(t->pkt);
			return NULL;
		}

		if (core_process_packet(t->pkt, t->input->datalink_dep->proto) == POM_ERR) {
			//packet_drop_infos(t->pkt);
			return NULL;
		}

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

	struct proto_process_stack s[CORE_PROTO_STACK_MAX];

	memset(s, 0, sizeof(struct proto_process_stack) * CORE_PROTO_STACK_MAX);
	s[0].pload = p->buff;
	s[0].plen = p->len;
	s[0].proto = datalink;

	int i;
	for (i = 0; i < CORE_PROTO_STACK_MAX - 1 && s[i].proto; i++) {
		
		s[i].pkt_info = packet_info_pool_get(s[i].proto);

		if (proto_parse(p, s, i) == POM_ERR) {
			pomlog(POMLOG_ERR "Error while parsing packet");
			return POM_ERR;
		}
		if (!s[i].proto) // Packet was invalid, stop here
			break;

		if ((s[i + 1].pload > s[i].pload + s[i].plen) || // Check if next payload is further than the end of current paylod
			(s[i + 1].pload < s[i].pload) || // Check if next payload is before the start of the current payload
			(s[i + 1].pload + s[i + 1].plen > s[i].pload + s[i].plen) || // Check if the end of the next payload is after the end of the current payload
			(s[i + 1].pload + s[i + 1].plen < s[i + 1].pload)) { // Check for integer overflow
			// Invalid packet
			pomlog(POMLOG_INFO "Invalid parsing detected for proto %s", s[i].proto->info->name);
		}

		if (s[i].ct_field_fwd) {
			struct conntrack_entry *parent = NULL;
			if (i > 1)
				parent = s[i - 1].ce;
			s[i].ce = conntrack_get(s[i].proto->ct, s[i].ct_field_fwd, s[i].ct_field_rev, parent);
			if (!s[i].ce) 
				pomlog(POMLOG_WARN "Warning : could not get conntrack for proto %s", s[i].proto->info->name);
		}

	}


	// Packet parsed at this point
	

	// Dump packet info
	for (i = 0; i < CORE_PROTO_STACK_MAX - 1 && s[i].proto; i++) {
		printf("%s{", s[i].proto->info->name);
		int j;
		for (j = 0; s[i].proto->info->pkt_fields[j].name; j++) {
			char buff[256];
			ptype_print_val(s[i].pkt_info->fields_value[j], buff, sizeof(buff) - 1);
			printf("%s : %s; ", s[i].proto->info->pkt_fields[j].name, buff);
		}

		printf("} ");
	}
	printf("\n");

	// Cleanup pkt_info

	for (i = 0; i < CORE_PROTO_STACK_MAX - 1 && s[i].proto; i++)
		packet_info_pool_release(&s[i].proto->pkt_info_pool, s[i].pkt_info);

	return POM_OK;
}
