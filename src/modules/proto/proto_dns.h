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

#ifndef __PROTO_DNS_H__
#define __PROTO_DNS_H__

#define PROTO_DNS_FIELD_NUM 6

enum proto_dns_fields {
	proto_dns_field_id = 0,
	proto_dns_field_response,
	proto_dns_field_rcode,
	proto_dns_field_qdcount,
	proto_dns_field_ancount,
	proto_dns_field_nscount,
	proto_dns_field_arcount
};

struct dns_header {

	uint16_t id;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint16_t rd:1;
	uint16_t tc:1;
	uint16_t aa:1;
	uint16_t opcode:4;
	uint16_t qr:1;

	uint16_t rcode:4;
	uint16_t z:3;
	uint16_t ra:1;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint16_t qr:1;
	uint16_t opcode:4;
	uint16_t aa:1;
	uint16_t tc:1;
	uint16_t rd:1;

	uint16_t ra:1;
	uint16_t z:3;
	uint16_t rcode:4;
#else
# error "Please fix <endian.h>"
#endif
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
};


struct proto_dns_priv {
	struct event_reg *evt_record;
};


struct proto_dns_question {

	char *qname;
	uint16_t qtype;
	uint16_t qclass;
};

struct proto_dns_rr {

	char *name;
	uint16_t type;
	uint16_t cls;
	uint32_t ttl;
	uint16_t rdlen;
	void * rdata;

};

#define PROTO_DNS_EVT_RECORD_DATA_COUNT 5

enum {
	proto_dns_record_name,
	proto_dns_record_ttl,
	proto_dns_record_type,
	proto_dns_record_class,
	proto_dns_record_values,
};

struct mod_reg_info* proto_dns_reg_info();
static int proto_dns_mod_register(struct mod_reg *mod);
static int proto_dns_init(struct proto *proto, struct registry_instance *ri);
static int proto_dns_cleanup(struct proto *proto);
static int proto_dns_process(struct proto *proto, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index);
static int proto_dns_mod_unregister();

#endif
