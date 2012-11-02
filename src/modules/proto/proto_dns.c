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


#include <pom-ng/ptype.h>
#include <pom-ng/proto.h>
#include <pom-ng/event.h>
#include <pom-ng/ptype_bool.h>
#include <pom-ng/ptype_ipv4.h>
#include <pom-ng/ptype_ipv6.h>
#include <pom-ng/ptype_string.h>
#include <pom-ng/ptype_uint8.h>
#include <pom-ng/ptype_uint16.h>
#include <pom-ng/ptype_uint32.h>

#include <arpa/inet.h>
#include <arpa/nameser.h>

#include "proto_dns.h"

#include <string.h>

struct mod_reg_info* proto_dns_reg_info() {

	static struct mod_reg_info reg_info = { 0 };
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = proto_dns_mod_register;
	reg_info.unregister_func = proto_dns_mod_unregister;
	reg_info.dependencies = "ptype_bool, ptype_ipv4, ptype_ipv6, ptype_string, ptype_uint8, ptype_uint16, ptype_uint32";

	return &reg_info;
}

static int proto_dns_mod_register(struct mod_reg *mod) {

	static struct proto_pkt_field fields[PROTO_DNS_FIELD_NUM + 1] = { { 0 } };
	fields[0].name = "id";
	fields[0].value_type = ptype_get_type("uint16");
	fields[0].description = "ID";
	fields[1].name = "response";
	fields[1].value_type = ptype_get_type("bool");
	fields[1].description = "Query or response";
	fields[2].name = "rcode";
	fields[2].value_type = ptype_get_type("uint8");
	fields[2].description = "Response code";
	fields[3].name = "qdcount";
	fields[3].value_type = ptype_get_type("uint16");
	fields[3].description = "Question count";
	fields[4].name = "ancount";
	fields[4].value_type = ptype_get_type("uint16");
	fields[4].description = "Answer count";
	fields[5].name = "nscount";
	fields[5].value_type = ptype_get_type("uint16");
	fields[5].description = "Name server count";
	fields[6].name = "arcount";
	fields[6].value_type = ptype_get_type("uint16");
	fields[6].description = "Additional records count";


	static struct proto_reg_info proto_dns = { 0 };
	proto_dns.name = "dns";
	proto_dns.api_ver = PROTO_API_VER;
	proto_dns.mod = mod;
	proto_dns.pkt_fields = fields;

	// No contrack here
	
	proto_dns.init = proto_dns_init;
	proto_dns.process = proto_dns_process;
	proto_dns.cleanup = proto_dns_cleanup;

	if (proto_register(&proto_dns) == POM_OK)
		return POM_OK;

	return POM_ERR;

}

static int proto_dns_init(struct proto *proto, struct registry_instance *ri) {

	struct proto_dns_priv *priv = malloc(sizeof(struct proto_dns_priv));
	if (!priv) {
		pom_oom(sizeof(struct proto_dns_priv));
		return POM_ERR;
	}
	memset(priv, 0, sizeof(struct proto_dns_priv));
	proto->priv = priv;

	static struct data_item_reg evt_dns_record_data_items[PROTO_DNS_EVT_RECORD_DATA_COUNT] = { { 0 } };
	evt_dns_record_data_items[proto_dns_record_name].name = "name";
	evt_dns_record_data_items[proto_dns_record_name].value_type = ptype_get_type("string");
	evt_dns_record_data_items[proto_dns_record_ttl].name = "ttl";
	evt_dns_record_data_items[proto_dns_record_ttl].value_type = ptype_get_type("uint32");
	evt_dns_record_data_items[proto_dns_record_type].name = "type";
	evt_dns_record_data_items[proto_dns_record_type].value_type = ptype_get_type("uint16");
	evt_dns_record_data_items[proto_dns_record_class].name = "class";
	evt_dns_record_data_items[proto_dns_record_class].value_type = ptype_get_type("uint16");
	evt_dns_record_data_items[proto_dns_record_values].name = "values";
	evt_dns_record_data_items[proto_dns_record_values].flags = DATA_REG_FLAG_LIST;

	static struct data_reg evt_dns_record_data = {
		.items = evt_dns_record_data_items,
		.data_count = PROTO_DNS_EVT_RECORD_DATA_COUNT
	};

	static struct event_reg_info proto_dns_evt_record = { 0 };
	proto_dns_evt_record.source_name = "proto_dns";
	proto_dns_evt_record.source_obj = proto;
	proto_dns_evt_record.name = "dns_record";
	proto_dns_evt_record.description = "DNS record";
	proto_dns_evt_record.data_reg = &evt_dns_record_data;

	priv->evt_record = event_register(&proto_dns_evt_record);
	if (!priv->evt_record)
		return POM_ERR;

	return POM_OK;
}

static int proto_dns_cleanup(struct proto *proto) {

	if (proto->priv) {
		struct proto_dns_priv *priv = proto->priv;
		if (priv->evt_record)
			event_unregister(priv->evt_record);

		free(priv);
	}

	return POM_OK;
}

static uint16_t proto_dns_get_uint16(void *data) {
	uint8_t *src = data;
	return (src[0] << 8 | src[1]);
}

static uint32_t proto_dns_get_uint32(void *data) {
	uint8_t *src = data;
	return (src[0] << 24 | src[1] << 16 | src[2] << 8 | src[3]);
}

static int proto_dns_parse_name(void *msg, void **data, size_t *data_len, char **name) {
	
	size_t label_len = 0;

	char *msg_end = *data + *data_len;
	size_t msg_len = (*data - msg) + *data_len;

	// Calculate the length
	char *data_tmp = *data;
	unsigned char len = *data_tmp;
	while (len) {

		// Check if it's a pointer or a normal label
		if (len > 63) {
			if ((len & 0xC0) != 0xC0) {
				pomlog(POMLOG_DEBUG "Invalid label length : 0x%X", len);
				return PROTO_INVALID;
			}
			// We have a pointer
			uint16_t offset = ((data_tmp[0] & 0x3f) << 8) | data_tmp[1];
			if (offset > msg_len) {
				pomlog(POMLOG_DEBUG "Offset too big : %u > %zu", offset, msg_len);
				return PROTO_INVALID;
			}
			data_tmp = msg + offset;
			len = *data_tmp;

			if (len > 63) {
				pomlog(POMLOG_DEBUG "Label pointer points to a pointer");
				return PROTO_INVALID;
			}

		}

		len++;

		if (data_tmp + len > msg_end) {
			pomlog(POMLOG_DEBUG "Label length too big");
			return PROTO_INVALID;
		}

		label_len += len;
		data_tmp += len;
		
		len = *data_tmp;
	}

	// Allocate the buffer and copy the value
	*name = malloc(label_len);
	if (!*name) {
		pom_oom(label_len);
		return PROTO_ERR;
	}

	char *name_cur = *name;
	
	data_tmp = *data;
	len = *data_tmp;
	while (len) {
	
		if (len > 63) {
			uint16_t offset = ((data_tmp[0] & 0x3f) << 8) | data_tmp[1];
			data_tmp = msg + offset;
			len = *data_tmp;

			// Prevent updating the current position
			if (data_len) {
				*data += 2;
				*data_len -= 2;
				data_len = NULL;
			}

		}

		data_tmp++;
		memcpy(name_cur, data_tmp, len);

		if (data_len) {
			*data += len + 1;
			*data_len -= len + 1;
		}

		data_tmp += len;
		name_cur += len;
		*name_cur = '.';
		name_cur++;


		len = *data_tmp;
	}

	*(name_cur - 1) = 0;

	// Point right after the end
	if (data_len) {
		*data += 1;
		*data_len -= 1;
	}

	return PROTO_OK;
}

static int proto_dns_parse_question(void **data, size_t *data_len, struct proto_dns_question *q) {

	int res = proto_dns_parse_name(NULL, data, data_len, &q->qname);
	if (res != PROTO_OK)
		return res;
	if (*data_len < (sizeof(uint16_t) * 2)) {
		free(q->qname);
		return PROTO_INVALID;
	}

	*data_len -= sizeof(uint16_t) * 2;

	q->qtype = proto_dns_get_uint16(*data);
	*data += sizeof(uint16_t);

	q->qclass = proto_dns_get_uint16(*data);
	*data += sizeof(uint16_t);

	return PROTO_OK;

}

static int proto_dns_parse_rr(void *msg, void **data, size_t *data_len, struct proto_dns_rr *rr) {

	int res = proto_dns_parse_name(msg, data, data_len, &rr->name);
	if (res != PROTO_OK)
		return res;

	if (*data_len < 10) {
		pomlog(POMLOG_DEBUG "Data length too short to parse RR");
		free(rr->name);
		return PROTO_INVALID;
	}

	rr->type = proto_dns_get_uint16(*data);
	*data += sizeof(uint16_t);

	rr->cls = proto_dns_get_uint16(*data);
	*data += sizeof(uint16_t);

	rr->ttl = proto_dns_get_uint32(*data);
	*data += sizeof(uint32_t);

	rr->rdlen = proto_dns_get_uint16(*data);
	*data += sizeof(uint16_t);

	rr->rdata = *data;
	*data_len -= 10;

	return PROTO_OK;
}

static int proto_dns_process(struct proto *proto, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct proto_dns_priv *priv = proto->priv;

	struct proto_process_stack *s = &stack[stack_index];

	if (s->plen < sizeof(struct dns_header))
		return PROTO_INVALID;

	struct dns_header *dhdr = s->pload;

	uint16_t qdcount = 0, ancount = 0, nscount = 0, arcount = 0;
	qdcount = ntohs(dhdr->qdcount);
	ancount = ntohs(dhdr->ancount);
	nscount = ntohs(dhdr->nscount);
	arcount = ntohs(dhdr->arcount);

	PTYPE_UINT16_SETVAL(s->pkt_info->fields_value[proto_dns_field_id], ntohs(dhdr->id));
	PTYPE_BOOL_SETVAL(s->pkt_info->fields_value[proto_dns_field_response], dhdr->qr);
	PTYPE_UINT8_SETVAL(s->pkt_info->fields_value[proto_dns_field_rcode], dhdr->rcode);
	PTYPE_UINT16_SETVAL(s->pkt_info->fields_value[proto_dns_field_qdcount], qdcount);
	PTYPE_UINT16_SETVAL(s->pkt_info->fields_value[proto_dns_field_ancount], ancount);
	PTYPE_UINT16_SETVAL(s->pkt_info->fields_value[proto_dns_field_nscount], nscount);
	PTYPE_UINT16_SETVAL(s->pkt_info->fields_value[proto_dns_field_arcount], arcount);


	if (qdcount != 1) {
		pomlog(POMLOG_DEBUG "Invalid DNS packet with qdcount != 1 : %u", qdcount);
		return PROTO_INVALID;
	}

	// Nothing left to do if it's a query or if it's a failed reply
	if (!dhdr->qr || dhdr->rcode)
		return PROTO_OK;

	if (!event_has_listener(priv->evt_record))
		return PROTO_OK;

	void *data_start = s->pload + sizeof(struct dns_header);
	size_t data_remaining = s->plen - sizeof(struct dns_header); 

	// Parse the question section
	struct proto_dns_question question = { 0 };
	int res = PROTO_OK;
	res = proto_dns_parse_question(&data_start, &data_remaining, &question);

	if (res != PROTO_OK)
		return res;
	
	pomlog(POMLOG_DEBUG "Got question \"%s\", type : %u, class : %u", question.qname, question.qtype, question.qclass);

	free(question.qname);

	uint32_t rr_count = ancount + nscount + arcount;

	unsigned int i;
	for (i = 0; i < rr_count; i++) {
		struct proto_dns_rr rr = { 0 };
		res = proto_dns_parse_rr(s->pload, &data_start, &data_remaining, &rr);
		if (res != POM_OK)
			return res;

		if (rr.rdlen > data_remaining) {
			free(rr.name);
			pomlog(POMLOG_DEBUG "RDLENGTH > remaining data : %u > %zu", rr.rdlen, data_remaining);
			return PROTO_INVALID;
		}

		pomlog(POMLOG_DEBUG "Got RR for %s, type %u", rr.name, rr.type);

		int process_event = 0;

		struct event *evt_record = event_alloc(priv->evt_record);
		if (!evt_record) {
			free(rr.name);
			return PROTO_ERR;
		}

		PTYPE_STRING_SETVAL_P(evt_record->data[proto_dns_record_name].value, rr.name);
		data_set(evt_record->data[proto_dns_record_name]);
		PTYPE_UINT32_SETVAL(evt_record->data[proto_dns_record_ttl].value, rr.ttl);
		data_set(evt_record->data[proto_dns_record_ttl]);
		PTYPE_UINT16_SETVAL(evt_record->data[proto_dns_record_type].value, rr.type);
		data_set(evt_record->data[proto_dns_record_type]);
		PTYPE_UINT16_SETVAL(evt_record->data[proto_dns_record_class].value, rr.cls);
		data_set(evt_record->data[proto_dns_record_class]);


		switch (rr.type) {
			case ns_t_a: {
				if (rr.rdlen < sizeof(uint32_t)) {
					event_cleanup(evt_record);
					pomlog(POMLOG_DEBUG "RDLEN too small to contain ipv4");
					return PROTO_INVALID;
				}

				struct ptype_ipv4_val ipv4 = { { 0 } };
				memcpy(&ipv4.addr.s_addr, data_start, sizeof(uint32_t));
				struct ptype *ipv4_val = ptype_alloc("ipv4");
				if (!ipv4_val)
					break;
				PTYPE_IPV4_SETADDR(ipv4_val, ipv4);
				if (data_item_add_ptype(evt_record->data, proto_dns_record_values, strdup("a"), ipv4_val) != POM_OK) {
					ptype_cleanup(ipv4_val);
					break;
				}
				process_event = 1;
				break;
			}

			case ns_t_aaaa: {
				if (rr.rdlen < sizeof(struct in6_addr)) {
					event_cleanup(evt_record);
					pomlog(POMLOG_DEBUG "RDLEN too small to contain ipv6");
					return PROTO_INVALID;
				}

				struct ptype_ipv6_val ipv6 = { { { { 0 } } } };
				memcpy(&ipv6, data_start, sizeof(struct in6_addr));
				struct ptype *ipv6_val = ptype_alloc("ipv6");
				if (!ipv6_val)
					break;
				PTYPE_IPV6_SETADDR(ipv6_val, ipv6);
				if (data_item_add_ptype(evt_record->data, proto_dns_record_values, strdup("aaaa"), ipv6_val) != POM_OK) {
					ptype_cleanup(ipv6_val);
					break;
				}
				process_event = 1;
				break;
			}

			case ns_t_cname: {
				char *cname = NULL;
				void *tmp_data_start = data_start;
				size_t tmp_data_remaining = data_remaining;
				res = proto_dns_parse_name(s->pload, &tmp_data_start, &tmp_data_remaining, &cname);
				if (res != POM_OK) {
					pomlog(POMLOG_DEBUG "Could not parse CNAME");
					event_cleanup(evt_record);
					return res;
				}

				struct ptype *val = ptype_alloc("string");
				if (!val) {
					free(cname);
					break;
				}
				PTYPE_STRING_SETVAL_P(val, cname);
				if (data_item_add_ptype(evt_record->data, proto_dns_record_values, strdup("cname"), val) != POM_OK) {
					ptype_cleanup(val);
					break;
				}
				process_event = 1;
				break;
			}

			case ns_t_ptr: {
				char *ptr = NULL;
				void *tmp_data_start = data_start;
				size_t tmp_data_remaining = data_remaining;
				res = proto_dns_parse_name(s->pload, &tmp_data_start, &tmp_data_remaining, &ptr);
				if (res != POM_OK) {
					pomlog(POMLOG_DEBUG "Could not parse PTR");
					event_cleanup(evt_record);
					return res;
				}

				struct ptype *val = ptype_alloc("string");
				if (!val) {
					free(ptr);
					break;
				}
				PTYPE_STRING_SETVAL_P(val, ptr);
				if (data_item_add_ptype(evt_record->data, proto_dns_record_values, strdup("ptr"), val) != POM_OK) {
					ptype_cleanup(val);
					break;
				}
				process_event = 1;
				break;
			}

			case ns_t_mx: {

				if (rr.rdlen < 2 * sizeof(uint16_t)) {
					pomlog(POMLOG_DEBUG "RDLEN too short to contain valid MX data");
					event_cleanup(evt_record);
					return PROTO_INVALID;
				}
				
				struct ptype *pref_val = ptype_alloc("uint16");
				if (!pref_val)
					break;
				uint16_t pref = proto_dns_get_uint16(data_start);
				PTYPE_UINT16_SETVAL(pref_val, pref);

				if (data_item_add_ptype(evt_record->data, proto_dns_record_values, strdup("mx_pref"), pref_val) != POM_OK) {
					ptype_cleanup(pref_val);
					break;
				}

				char *mx = NULL;
				void *tmp_data_start = data_start + sizeof(uint16_t);
				size_t tmp_data_remaining = data_remaining - sizeof(uint16_t);
				res = proto_dns_parse_name(s->pload, &tmp_data_start, &tmp_data_remaining, &mx);
				if (res != POM_OK) {
					pomlog(POMLOG_DEBUG "Could not parse MX");
					event_cleanup(evt_record);
					return res;
				}

				struct ptype *val = ptype_alloc("string");
				if (!val) {
					free(mx);
					break;
				}
				PTYPE_STRING_SETVAL_P(val, mx);
				if (data_item_add_ptype(evt_record->data, proto_dns_record_values, strdup("ptr"), val) != POM_OK) {
					ptype_cleanup(val);
					break;
				}
				process_event = 1;
				break;
			}

		}

		data_start += rr.rdlen;
		data_remaining -= rr.rdlen;

		if (!process_event) {
			event_cleanup(evt_record);
			continue;
		}

		if (event_process(evt_record, stack, stack_index) != POM_OK)
			return PROTO_ERR;

	}

	return PROTO_OK;
}

static int proto_dns_mod_unregister() {

	return proto_unregister("dns");
}
