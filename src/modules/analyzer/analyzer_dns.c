/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2012-2013 Guy Martin <gmsoft@tuxicoman.be>
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

#include <pom-ng/event.h>
#include <pom-ng/analyzer.h>
#include <pom-ng/ptype_ipv4.h>
#include <pom-ng/ptype_ipv6.h>
#include <pom-ng/ptype_string.h>
#include <pom-ng/ptype_bool.h>
#include <pom-ng/ptype_uint8.h>
#include <pom-ng/ptype_uint16.h>
#include <pom-ng/ptype_uint32.h>
#include <pom-ng/proto_dns.h>
#include <pom-ng/timer.h>

#include "analyzer_dns.h"

#include <arpa/nameser.h>


#if 0
#define debug_dns(x ...) pomlog(POMLOG_DEBUG x)
#else
#define debug_dns(x ...)
#endif

struct mod_reg_info *analyzer_dns_reg_info() {

	static struct mod_reg_info reg_info = { 0 };
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = analyzer_dns_mod_register;
	reg_info.unregister_func = analyzer_dns_mod_unregister;
	reg_info.dependencies = "proto_dns, ptype_uint16, ptype_uint32, ptype_string";

	return &reg_info;
}

static int analyzer_dns_mod_register(struct mod_reg *mod) {
	
	static struct analyzer_reg analyzer_dns = { 0 };
	analyzer_dns.name = "dns";
	analyzer_dns.api_ver = ANALYZER_API_VER;
	analyzer_dns.mod = mod;
	analyzer_dns.init = analyzer_dns_init;
	analyzer_dns.cleanup = analyzer_dns_cleanup;

	return analyzer_register(&analyzer_dns);

}

static int analyzer_dns_mod_unregister() {

	return analyzer_unregister("dns");
}

static int analyzer_dns_init(struct analyzer *analyzer) {

	struct analyzer_dns_priv *priv = malloc(sizeof(struct analyzer_dns_priv));
	if (!priv) {
		pom_oom(sizeof(struct analyzer_dns_priv));
		return POM_ERR;
	}
	memset(priv, 0, sizeof(struct analyzer_dns_priv));

	analyzer->priv = priv;

	if (pthread_mutex_init(&priv->lock, NULL)) {
		pomlog(POMLOG_ERR "Error while initializing query lock : %s", pom_strerror(errno));
		free(priv);
		return POM_ERR;
	}

	static struct data_item_reg evt_dns_record_data_items[ANALYZER_DNS_EVT_RECORD_DATA_COUNT] = { { 0 } };
	evt_dns_record_data_items[analyzer_dns_record_name].name = "name";
	evt_dns_record_data_items[analyzer_dns_record_name].value_type = ptype_get_type("string");
	evt_dns_record_data_items[analyzer_dns_record_ttl].name = "ttl";
	evt_dns_record_data_items[analyzer_dns_record_ttl].value_type = ptype_get_type("uint32");
	evt_dns_record_data_items[analyzer_dns_record_type].name = "type";
	evt_dns_record_data_items[analyzer_dns_record_type].value_type = ptype_get_type("uint16");
	evt_dns_record_data_items[analyzer_dns_record_class].name = "class";
	evt_dns_record_data_items[analyzer_dns_record_class].value_type = ptype_get_type("uint16");
	evt_dns_record_data_items[analyzer_dns_record_values].name = "values";
	evt_dns_record_data_items[analyzer_dns_record_values].flags = DATA_REG_FLAG_LIST;

	static struct data_reg evt_dns_record_data = {
		.items = evt_dns_record_data_items,
		.data_count = ANALYZER_DNS_EVT_RECORD_DATA_COUNT
	};

	static struct event_reg_info analyzer_dns_evt_record = { 0 };
	analyzer_dns_evt_record.source_name = "analyzer_dns";
	analyzer_dns_evt_record.source_obj = priv;
	analyzer_dns_evt_record.name = "dns_record";
	analyzer_dns_evt_record.description = "DNS record";
	analyzer_dns_evt_record.data_reg = &evt_dns_record_data;
	analyzer_dns_evt_record.listeners_notify = analyzer_dns_event_listeners_notify;

	struct registry_param *p = NULL;

	priv->proto_dns = proto_get("dns");
	if (!priv->proto_dns)
		goto err;

	priv->evt_record = event_register(&analyzer_dns_evt_record);
	if (!priv->evt_record)
		goto err;

	priv->p_anti_spoof = ptype_alloc("bool");
	if (!priv->p_anti_spoof)
		goto err;

	priv->p_qtimeout = ptype_alloc("uint32");
	if (!priv->p_qtimeout)
		goto err;

	p = registry_new_param("anti_spoof", "no", priv->p_anti_spoof, "Prevent spoofing by accepting only replies that match a query", 0);
	if (registry_instance_add_param(analyzer->reg_instance, p) != POM_OK)
		goto err;

	p = registry_new_param("q_timeout", "10", priv->p_qtimeout, "Query timeout for anti spoofing protection", 0);
	if (registry_instance_add_param(analyzer->reg_instance, p) != POM_OK)
		goto err;

	p = NULL;


	return POM_OK;

err:
	if (p)
		registry_cleanup_param(p);

	analyzer_dns_cleanup(analyzer);
	return POM_ERR;

}

static int analyzer_dns_cleanup(struct analyzer *analyzer) {

	struct analyzer_dns_priv *priv = analyzer->priv;

	if (priv) {
		pthread_mutex_destroy(&priv->lock);

		while (priv->entry_head) {
			struct analyzer_dns_query *tmp = priv->entry_head;
			priv->entry_head = tmp->next;

			free(tmp->name);
			ptype_cleanup(tmp->src_ip);
			ptype_cleanup(tmp->dst_ip);
			timer_cleanup(tmp->t);
			free(tmp);
		}

		if (priv->evt_record)
			event_unregister(priv->evt_record);
		if (priv->p_anti_spoof)
			ptype_cleanup(priv->p_anti_spoof);
		if (priv->p_qtimeout)
			ptype_cleanup(priv->p_qtimeout);
		free(priv);
	}
	
	return POM_OK;
}

static int analyzer_dns_event_listeners_notify(void *obj, struct event_reg *evt_reg, int has_listeners) {

	struct analyzer_dns_priv *priv = obj;

	if (has_listeners) {
		priv->dns_packet_listener = proto_packet_listener_register(priv->proto_dns, PROTO_PACKET_LISTENER_PLOAD_ONLY, priv, analyzer_dns_proto_packet_process);
		if (!priv->dns_packet_listener)
			return POM_ERR;
	} else {
		if (proto_packet_listener_unregister(priv->dns_packet_listener) != POM_OK)
			return POM_ERR;
	}
	

	return POM_OK;
}

static uint16_t analyzer_dns_get_uint16(void *data) {
	uint8_t *src = data;
	return (src[0] << 8 | src[1]);
}

static uint32_t analyzer_dns_get_uint32(void *data) {
	uint8_t *src = data;
	return (src[0] << 24 | src[1] << 16 | src[2] << 8 | src[3]);
}

static int analyzer_dns_parse_name(void *msg, void **data, size_t *data_len, char **name) {
	
	size_t label_len = 0;

	unsigned char *msg_end = *data + *data_len;
	size_t msg_len = (*data - msg) + *data_len;

	// Calculate the length
	unsigned char *data_tmp = *data;
	unsigned char len = *data_tmp;
	while (len) {

		// Check if it's a pointer or a normal label
		if (len > 63) {
			if (!msg) // Pointers are not allowed for the first record
				return POM_ERR;
			if ((len & 0xC0) != 0xC0) {
				debug_dns("Invalid label length : 0x%X", len);
				return POM_ERR;
			}
			// We have a pointer
			uint16_t offset = ((data_tmp[0] & 0x3f) << 8) | data_tmp[1];
			if (offset > msg_len) {
				debug_dns("Offset too big : %u > %zu", offset, msg_len);
				return POM_ERR;
			}
			data_tmp = msg + offset;
			len = *data_tmp;

			if (len > 63) {
				debug_dns("Label pointer points to a pointer");
				return POM_ERR;
			}

		}

		len++;

		if (data_tmp + len > msg_end) {
			debug_dns("Label length too big");
			return POM_ERR;
		}

		label_len += len;
		data_tmp += len;
		
		len = *data_tmp;
	}

	// Allocate the buffer and copy the value
	*name = malloc(label_len);
	if (!*name) {
		pom_oom(label_len);
		return POM_ERR;
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

	return POM_OK;
}

static int analyzer_dns_parse_question(void **data, size_t *data_len, struct analyzer_dns_question *q) {

	int res = analyzer_dns_parse_name(NULL, data, data_len, &q->qname);
	if (res != POM_OK)
		return res;
	if (*data_len < (sizeof(uint16_t) * 2)) {
		free(q->qname);
		return POM_ERR;
	}

	*data_len -= sizeof(uint16_t) * 2;

	q->qtype = analyzer_dns_get_uint16(*data);
	*data += sizeof(uint16_t);

	q->qclass = analyzer_dns_get_uint16(*data);
	*data += sizeof(uint16_t);

	return POM_OK;

}

static int analyzer_dns_parse_rr(void *msg, void **data, size_t *data_len, struct analyzer_dns_rr *rr) {

	int res = analyzer_dns_parse_name(msg, data, data_len, &rr->name);
	if (res != POM_OK)
		return res;

	if (*data_len < 10) {
		debug_dns("Data length too short to parse RR");
		free(rr->name);
		return POM_ERR;
	}

	rr->type = analyzer_dns_get_uint16(*data);
	*data += sizeof(uint16_t);

	rr->cls = analyzer_dns_get_uint16(*data);
	*data += sizeof(uint16_t);

	rr->ttl = analyzer_dns_get_uint32(*data);
	*data += sizeof(uint32_t);

	rr->rdlen = analyzer_dns_get_uint16(*data);
	*data += sizeof(uint16_t);

	rr->rdata = *data;
	*data_len -= 10;

	return POM_OK;
}


static int analyzer_dns_query_timeout(void *obj, ptime now) {

	struct analyzer_dns_priv *priv = obj;

	pom_mutex_lock(&priv->lock);

	if (!priv->entry_tail) {
		pomlog(POMLOG_WARN "DNS query timeout fired but no queries in the list");
		pom_mutex_unlock(&priv->lock);
		return POM_OK;
	}

	struct analyzer_dns_query *tmp = priv->entry_tail;

	if (tmp->prev)
		tmp->prev->next = NULL;
	else
		priv->entry_head = NULL;

	priv->entry_tail = tmp->prev;

	timer_cleanup(tmp->t);
	pom_mutex_unlock(&priv->lock);

	ptype_cleanup(tmp->src_ip);
	ptype_cleanup(tmp->dst_ip);
	free(tmp->name);
	free(tmp);

	return POM_OK;
}

static int analyzer_dns_proto_packet_process(void *object, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {


	struct analyzer_dns_priv *priv = object;
	if (!event_has_listener(priv->evt_record))
		return POM_OK;

	struct proto_process_stack *s = &stack[stack_index];
	struct proto_process_stack *s_dns = &stack[stack_index - 1];

	// Nothing left to do if it's a query or a failed response and anti_spoof is not enabled
	uint8_t rcode = *PTYPE_UINT8_GETVAL(s_dns->pkt_info->fields_value[proto_dns_field_rcode]);
	char is_response = *PTYPE_BOOL_GETVAL(s_dns->pkt_info->fields_value[proto_dns_field_response]);
	char anti_spoof = *PTYPE_BOOL_GETVAL(priv->p_anti_spoof);

	// No need to analyze queries if anti_spoof is not enabled
	// Same goes for failed replies, we only process them to remove queries from the queue
	if ((!is_response || rcode) && !anti_spoof)
		return POM_OK;

	void *data_start = s->pload;
	size_t data_remaining = s->plen; 

	if (stack_index < 3) {
		pomlog(POMLOG_DEBUG "Stack_index is supposed to be at least 3 for dns payloads");
		return POM_ERR;
	}


	struct ptype *sport = NULL, *dport = NULL;
	struct ptype *src = NULL, *dst = NULL;


	struct proto_process_stack *s_l4 = &stack[stack_index - 2];
	struct proto_process_stack *s_l3 = &stack[stack_index - 3];

	unsigned int i;
	for (i = 0; !sport || !dport; i++) {
		struct proto_reg_info *l4_info = proto_get_info(s_l4->proto);
		char *name = l4_info->pkt_fields[i].name;
		if (!name)
			break;
		if (!sport && !strcmp(name, "sport"))
			sport = s_l4->pkt_info->fields_value[i];
		else if (!dport && !strcmp(name, "dport"))
			dport = s_l4->pkt_info->fields_value[i];
	}

	if (!sport || !dport) {
		pomlog(POMLOG_DEBUG "Unable to find source or destination port");
		return POM_ERR;
	}

	for (i = 0; !src || !dst; i++) {
		struct proto_reg_info *l3_info = proto_get_info(s_l3->proto);
		char *name = l3_info->pkt_fields[i].name;
		if (!name)
			break;
		if (!src && !strcmp(name, "src"))
			src = s_l3->pkt_info->fields_value[i];
		else if (!dst && !strcmp(name, "dst"))
			dst = s_l3->pkt_info->fields_value[i];
	}
	if (!src || !dst) {
		pomlog(POMLOG_DEBUG "Unable to find source or destination addresse");
		return POM_ERR;
	}



	// Parse the question section
	struct analyzer_dns_question question = { 0 };
	if (analyzer_dns_parse_question(&data_start, &data_remaining, &question) != POM_OK)
		return POM_OK;

	debug_dns("Got question \"%s\", type : %u, class : %u", question.qname, question.qtype, question.qclass);

	if (anti_spoof) {
		if (!is_response) {
			// New DNS query, add it to the list
			struct analyzer_dns_query *q = malloc(sizeof(struct analyzer_dns_query));
			if (!q) {
				pom_oom(sizeof(struct analyzer_dns_query));
				return POM_ERR;
			}
			memset(q, 0, sizeof(struct analyzer_dns_query));
			q->t = timer_alloc(priv, analyzer_dns_query_timeout);
			if (!q->t) {
				free(q);
				return POM_ERR;
			}

			q->src_ip = ptype_alloc_from(src);
			if (!q->src_ip) {
				timer_cleanup(q->t);
				free(q);
				return POM_ERR;
			}
			q->dst_ip = ptype_alloc_from(dst);
			if (!q->dst_ip) {
				timer_cleanup(q->t);
				ptype_cleanup(q->src_ip);
				free(q);
				return POM_ERR;
			}

			// TODO check that the port is correctly 16bit wide ?
			q->src_port = *PTYPE_UINT16_GETVAL(sport);
			q->dst_port = *PTYPE_UINT16_GETVAL(dport);

			q->l4_proto = s_l4->proto;
			q->id = *PTYPE_UINT16_GETVAL(s_dns->pkt_info->fields_value[proto_dns_field_id]);
			q->type = question.qtype;
			q->cls = question.qclass;
			q->name = question.qname;

			timer_queue_now(q->t, *PTYPE_UINT32_GETVAL(priv->p_qtimeout), p->ts);
			pom_mutex_lock(&priv->lock);
			q->next = priv->entry_head;
			if (q->next)
				q->next->prev = q;
			else 
				priv->entry_tail = q;
			priv->entry_head = q;
			
			pom_mutex_unlock(&priv->lock);

			// Nothing else to do for queries
			return POM_OK;
		} else {
			// Check for the response

			pom_mutex_lock(&priv->lock);
			struct analyzer_dns_query *tmp;
			for (tmp = priv->entry_tail; tmp; tmp = tmp->prev) {
				if (
					tmp->l4_proto == s_l4->proto &&
					tmp->id == *PTYPE_UINT16_GETVAL(s_dns->pkt_info->fields_value[proto_dns_field_id]) &&
					tmp->type == question.qtype &&
					tmp->cls == question.qclass &&
					tmp->dst_port == *PTYPE_UINT16_GETVAL(sport) &&
					tmp->src_port == *PTYPE_UINT16_GETVAL(dport) &&
					ptype_compare_val(PTYPE_OP_EQ, tmp->src_ip, dst) &&
					ptype_compare_val(PTYPE_OP_EQ, tmp->dst_ip, src) &&
					!strcmp(tmp->name, question.qname)
					)
					break;
			}
			
			if (!tmp) {
				pom_mutex_unlock(&priv->lock);
				debug_dns("Ignoring response for \"%s\" as it might be spoofed", question.qname);
				free(question.qname);
				return POM_OK;
			}
			
			timer_cleanup(tmp->t);

			if (tmp->prev)
				tmp->prev->next = tmp->next;
			else
				priv->entry_head = tmp->next;

			if (tmp->next)
				tmp->next->prev = tmp->prev;
			else
				priv->entry_tail = tmp->prev;

			pom_mutex_unlock(&priv->lock);

			ptype_cleanup(tmp->src_ip);
			ptype_cleanup(tmp->dst_ip);
			free(tmp->name);
			free(tmp);
		}
	}

	free(question.qname);

	if (rcode) // No need for further processing
		return POM_OK;

	uint16_t *ancount, *nscount, *arcount;
	ancount = PTYPE_UINT16_GETVAL(s_dns->pkt_info->fields_value[proto_dns_field_ancount]);
	nscount = PTYPE_UINT16_GETVAL(s_dns->pkt_info->fields_value[proto_dns_field_nscount]);
	arcount = PTYPE_UINT16_GETVAL(s_dns->pkt_info->fields_value[proto_dns_field_arcount]);

	uint32_t rr_count = *ancount + *nscount + *arcount;

	for (i = 0; i < rr_count; i++) {
		struct analyzer_dns_rr rr = { 0 };
		if (analyzer_dns_parse_rr(s_dns->pload, &data_start, &data_remaining, &rr) != POM_OK)
			return POM_OK;

		if (rr.rdlen > data_remaining) {
			free(rr.name);
			debug_dns("RDLENGTH > remaining data : %u > %zu", rr.rdlen, data_remaining);
			return POM_OK;
		}

		debug_dns("Got RR for %s, type %u", rr.name, rr.type);

		int process_event = 0;

		struct event *evt_record = event_alloc(priv->evt_record);
		if (!evt_record) {
			free(rr.name);
			return POM_OK;
		}
		
		struct data *evt_data = event_get_data(evt_record);
		PTYPE_STRING_SETVAL_P(evt_data[analyzer_dns_record_name].value, rr.name);
		data_set(evt_data[analyzer_dns_record_name]);
		PTYPE_UINT32_SETVAL(evt_data[analyzer_dns_record_ttl].value, rr.ttl);
		data_set(evt_data[analyzer_dns_record_ttl]);
		PTYPE_UINT16_SETVAL(evt_data[analyzer_dns_record_type].value, rr.type);
		data_set(evt_data[analyzer_dns_record_type]);
		PTYPE_UINT16_SETVAL(evt_data[analyzer_dns_record_class].value, rr.cls);
		data_set(evt_data[analyzer_dns_record_class]);


		switch (rr.type) {
			case ns_t_a: {
				if (rr.rdlen < sizeof(uint32_t)) {
					event_cleanup(evt_record);
					debug_dns("RDLEN too small to contain ipv4");
					return POM_OK;
				}

				struct ptype_ipv4_val ipv4 = { { 0 } };
				memcpy(&ipv4.addr.s_addr, data_start, sizeof(uint32_t));
				struct ptype *ipv4_val = ptype_alloc("ipv4");
				if (!ipv4_val)
					break;
				PTYPE_IPV4_SETADDR(ipv4_val, ipv4);
				if (data_item_add_ptype(evt_data, analyzer_dns_record_values, strdup("a"), ipv4_val) != POM_OK) {
					ptype_cleanup(ipv4_val);
					break;
				}
				process_event = 1;
				break;
			}

			case ns_t_aaaa: {
				if (rr.rdlen < sizeof(struct in6_addr)) {
					event_cleanup(evt_record);
					debug_dns("RDLEN too small to contain ipv6");
					return POM_OK;
				}

				struct ptype_ipv6_val ipv6 = { { { { 0 } } } };
				memcpy(&ipv6, data_start, sizeof(struct in6_addr));
				struct ptype *ipv6_val = ptype_alloc("ipv6");
				if (!ipv6_val)
					break;
				PTYPE_IPV6_SETADDR(ipv6_val, ipv6);
				if (data_item_add_ptype(evt_data, analyzer_dns_record_values, strdup("aaaa"), ipv6_val) != POM_OK) {
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
				if (analyzer_dns_parse_name(s_dns->pload, &tmp_data_start, &tmp_data_remaining, &cname) != POM_OK) {
					debug_dns("Could not parse CNAME");
					event_cleanup(evt_record);
					return POM_OK;
				}

				struct ptype *val = ptype_alloc("string");
				if (!val) {
					free(cname);
					break;
				}
				PTYPE_STRING_SETVAL_P(val, cname);
				if (data_item_add_ptype(evt_data, analyzer_dns_record_values, strdup("cname"), val) != POM_OK) {
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
				if (analyzer_dns_parse_name(s_dns->pload, &tmp_data_start, &tmp_data_remaining, &ptr) != POM_OK) {
					debug_dns("Could not parse PTR");
					event_cleanup(evt_record);
					return POM_OK;
				}

				struct ptype *val = ptype_alloc("string");
				if (!val) {
					free(ptr);
					break;
				}
				PTYPE_STRING_SETVAL_P(val, ptr);
				if (data_item_add_ptype(evt_data, analyzer_dns_record_values, strdup("ptr"), val) != POM_OK) {
					ptype_cleanup(val);
					break;
				}
				process_event = 1;
				break;
			}

			case ns_t_mx: {

				if (rr.rdlen < 2 * sizeof(uint16_t)) {
					debug_dns("RDLEN too short to contain valid MX data");
					event_cleanup(evt_record);
					return POM_OK;
				}
				
				struct ptype *pref_val = ptype_alloc("uint16");
				if (!pref_val)
					break;
				uint16_t pref = analyzer_dns_get_uint16(data_start);
				PTYPE_UINT16_SETVAL(pref_val, pref);

				if (data_item_add_ptype(evt_data, analyzer_dns_record_values, strdup("mx_pref"), pref_val) != POM_OK) {
					ptype_cleanup(pref_val);
					break;
				}

				char *mx = NULL;
				void *tmp_data_start = data_start + sizeof(uint16_t);
				size_t tmp_data_remaining = data_remaining - sizeof(uint16_t);
				if (analyzer_dns_parse_name(s_dns->pload, &tmp_data_start, &tmp_data_remaining, &mx) != POM_OK) {
					debug_dns("Could not parse MX");
					event_cleanup(evt_record);
					return POM_OK;
				}

				struct ptype *val = ptype_alloc("string");
				if (!val) {
					free(mx);
					break;
				}
				PTYPE_STRING_SETVAL_P(val, mx);
				if (data_item_add_ptype(evt_data, analyzer_dns_record_values, strdup("ptr"), val) != POM_OK) {
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

		if (event_process(evt_record, stack, stack_index, p->ts) != POM_OK)
			return POM_ERR;

	}

	return POM_OK;
}
