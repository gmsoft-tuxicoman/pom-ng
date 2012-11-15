/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2012 Guy Martin <gmsoft@tuxicoman.be>
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

#ifndef __ANALYZER_DNS_H__
#define __ANALYZER_DNS_H__


struct analyzer_dns_query {

	struct ptype *src_ip, *dst_ip;
	uint16_t src_port, dst_port;
	uint16_t id, type, cls;
	char *name;
	struct timer *t;
	struct proto *l4_proto;

	struct analyzer_dns_query *prev, *next;

};

struct analyzer_dns_priv {
	
	struct analyzer_dns_query *entry_head, *entry_tail;
	struct event_reg *evt_record;
	struct ptype *p_anti_spoof;
	struct ptype *p_qtimeout;

	struct proto *proto_dns;
	struct proto_packet_listener *dns_packet_listener;

	pthread_mutex_t lock;
};

struct analyzer_dns_question {

	char *qname;
	uint16_t qtype;
	uint16_t qclass;
};

struct analyzer_dns_rr {

	char *name;
	uint16_t type;
	uint16_t cls;
	uint32_t ttl;
	uint16_t rdlen;
	void * rdata;

};

#define ANALYZER_DNS_EVT_RECORD_DATA_COUNT 5

enum {
	analyzer_dns_record_name,
	analyzer_dns_record_ttl,
	analyzer_dns_record_type,
	analyzer_dns_record_class,
	analyzer_dns_record_values,
};

struct mod_reg_info *analyzer_dns_reg_info();
static int analyzer_dns_mod_register(struct mod_reg *mod);
static int analyzer_dns_mod_unregister();
static int analyzer_dns_init(struct analyzer *analyzer);
static int analyzer_dns_cleanup(struct analyzer *analyzer);
static int analyzer_dns_event_listeners_notify(void *obj, struct event_reg *evt_reg, int has_listeners);
static int analyzer_dns_proto_packet_process(void *object, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index);


#endif
