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

#include <pom-ng/ptype_ipv4.h>
#include <pom-ng/ptype_mac.h>
#include <pom-ng/ptype_string.h>
#include <pom-ng/proto_arp.h>
#include <pom-ng/input.h>

#include "analyzer_arp.h"

struct mod_reg_info *analyzer_arp_reg_info() {

	static struct mod_reg_info reg_info = { 0 };
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = analyzer_arp_mod_register;
	reg_info.unregister_func = analyzer_arp_mod_unregister;
	reg_info.dependencies = "proto_arp, ptype_ipv4, ptype_mac, ptype_string";

	return &reg_info;
}

static int analyzer_arp_mod_register(struct mod_reg *mod) {
	
	static struct analyzer_reg analyzer_arp = { 0 };
	analyzer_arp.name = "arp";
	analyzer_arp.api_ver = ANALYZER_API_VER;
	analyzer_arp.mod = mod;
	analyzer_arp.init = analyzer_arp_init;
	analyzer_arp.cleanup = analyzer_arp_cleanup;

	return analyzer_register(&analyzer_arp);

}

static int analyzer_arp_mod_unregister() {

	return analyzer_unregister("arp");
}

static int analyzer_arp_init(struct analyzer *analyzer) {

	struct analyzer_arp_priv *priv = malloc(sizeof(struct analyzer_arp_priv));
	if (!priv) {
		pom_oom(sizeof(struct analyzer_arp_priv));
		return POM_ERR;
	}
	memset(priv, 0, sizeof(struct analyzer_arp_priv));

	analyzer->priv = priv;

	if (pthread_mutex_init(&priv->lock, NULL)) {
		pomlog(POMLOG_ERR "Error while initializing table lock : %s", pom_strerror(errno));
		free(priv);
		return POM_ERR;
	}


	static struct data_item_reg evt_new_sta_data_items[ANALYZER_ARP_EVT_NEW_STA_DATA_COUNT] = { { 0 } };

	evt_new_sta_data_items[analyzer_arp_new_sta_mac_addr].name = "mac_addr";
	evt_new_sta_data_items[analyzer_arp_new_sta_mac_addr].value_type = ptype_get_type("mac");
	evt_new_sta_data_items[analyzer_arp_new_sta_ip_addr].name = "ip_addr";
	evt_new_sta_data_items[analyzer_arp_new_sta_ip_addr].value_type = ptype_get_type("ipv4");
	evt_new_sta_data_items[analyzer_arp_new_sta_input].name = "input";
	evt_new_sta_data_items[analyzer_arp_new_sta_input].value_type = ptype_get_type("string");


	static struct data_reg evt_new_sta_data = {
		.items = evt_new_sta_data_items,
		.data_count = ANALYZER_ARP_EVT_NEW_STA_DATA_COUNT
	};

	static struct event_reg_info analyzer_arp_evt_new_sta = { 0 };
	analyzer_arp_evt_new_sta.source_name = "analyzer_arp";
	analyzer_arp_evt_new_sta.source_obj = analyzer;
	analyzer_arp_evt_new_sta.name = "arp_new_sta";
	analyzer_arp_evt_new_sta.description = "New station found";
	analyzer_arp_evt_new_sta.data_reg = &evt_new_sta_data;
	analyzer_arp_evt_new_sta.listeners_notify = analyzer_arp_event_listeners_notify;

	priv->evt_new_sta = event_register(&analyzer_arp_evt_new_sta);
	if (!priv->evt_new_sta)
		goto err;

	static struct data_item_reg evt_sta_changed_data_items[ANALYZER_ARP_EVT_STA_CHANGED_DATA_COUNT] = { { 0 } };

	evt_sta_changed_data_items[analyzer_arp_sta_changed_old_mac_addr].name = "old_mac_addr";
	evt_sta_changed_data_items[analyzer_arp_sta_changed_old_mac_addr].value_type = ptype_get_type("mac");
	evt_sta_changed_data_items[analyzer_arp_sta_changed_new_mac_addr].name = "new_mac_addr";
	evt_sta_changed_data_items[analyzer_arp_sta_changed_new_mac_addr].value_type = ptype_get_type("mac");
	evt_sta_changed_data_items[analyzer_arp_sta_changed_ip_addr].name = "ip_addr";
	evt_sta_changed_data_items[analyzer_arp_sta_changed_ip_addr].value_type = ptype_get_type("ipv4");
	evt_sta_changed_data_items[analyzer_arp_sta_changed_input].name = "input";
	evt_sta_changed_data_items[analyzer_arp_sta_changed_input].value_type = ptype_get_type("string");

	static struct data_reg evt_sta_changed_data = {
		.items = evt_sta_changed_data_items,
		.data_count = ANALYZER_ARP_EVT_STA_CHANGED_DATA_COUNT
	};

	static struct event_reg_info analyzer_arp_evt_sta_changed = { 0 };
	analyzer_arp_evt_sta_changed.source_name = "analyzer_arp";
	analyzer_arp_evt_sta_changed.source_obj = analyzer;
	analyzer_arp_evt_sta_changed.name = "arp_sta_changed";
	analyzer_arp_evt_sta_changed.description = "Station MAC address changed";
	analyzer_arp_evt_sta_changed.data_reg = &evt_sta_changed_data;
	analyzer_arp_evt_sta_changed.listeners_notify = analyzer_arp_event_listeners_notify;

	priv->evt_sta_changed = event_register(&analyzer_arp_evt_sta_changed);
	if (!priv->evt_sta_changed)
		goto err;

	return POM_OK;

err:
	analyzer_arp_cleanup(analyzer);

	return POM_ERR;
}

static int analyzer_arp_cleanup(struct analyzer *analyzer) {

	struct analyzer_arp_priv *priv = analyzer->priv;

	pthread_mutex_destroy(&priv->lock);

	if (priv->evt_new_sta)
		event_unregister(priv->evt_new_sta);
	
	if (priv->evt_sta_changed)
		event_unregister(priv->evt_sta_changed);

	int i;
	for (i = 0; i < ANALYZER_ARP_HOST_TABLE_SIZE; i++) {
		while (priv->hosts[i]) {
			struct analyzer_arp_host *tmp = priv->hosts[i];
			priv->hosts[i] = tmp->next;
			free(tmp);
		}
	}


	free(priv);

	return POM_OK;
}

static int analyzer_arp_event_listeners_notify(void *obj, struct event_reg *evt_reg, int has_listeners) {
	
	struct analyzer *analyzer = obj;
	struct analyzer_arp_priv *priv = analyzer->priv;

	if (has_listeners) {

		// Check if we are already listening
		if (priv->pkt_listener)
			return POM_OK;

		priv->pkt_listener = proto_packet_listener_register(proto_get("arp"), 0, obj, analyzer_arp_pkt_process);
		if (!priv->pkt_listener)
			return POM_ERR;
	} else {

		// Check if there is still an event being listened
		if (event_has_listener(priv->evt_new_sta) || event_has_listener(priv->evt_sta_changed))
			return POM_OK;

		if (proto_packet_listener_unregister(priv->pkt_listener) != POM_OK)
			return POM_ERR;
		priv->pkt_listener = NULL;
	}

	return POM_OK;
}

static int analyzer_arp_pkt_process(void *obj, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct analyzer *analyzer = obj;
	struct analyzer_arp_priv *priv = analyzer->priv;

	struct proto_process_stack *s = &stack[stack_index];

	struct in_addr arp_ip = PTYPE_IPV4_GETADDR(s->pkt_info->fields_value[proto_arp_field_sender_proto_addr]);

	// Discard bogon 0.0.0.0
	if (!arp_ip.s_addr)
		return POM_OK;

	// Find that IP in the table
	uint32_t id = arp_ip.s_addr & ANALYZER_ARP_HOST_MASK;
	char *arp_mac = PTYPE_MAC_GETADDR(s->pkt_info->fields_value[proto_arp_field_sender_hw_addr]);

	pom_mutex_lock(&priv->lock);

	struct analyzer_arp_host *host;
	for (host = priv->hosts[id]; host; host = host->next) {
		if (host->ip.s_addr == arp_ip.s_addr)
			break;
	}

	if (!host) {
		// Host not found !
		host = malloc(sizeof(struct analyzer_arp_host));
		if (!host) {
			pom_mutex_unlock(&priv->lock);
			pom_oom(sizeof(struct analyzer_arp_host));
			return POM_ERR;
		}
		memset(host, 0, sizeof(struct analyzer_arp_host));

		host->ip.s_addr = arp_ip.s_addr;
		memcpy(host->mac, arp_mac, sizeof(host->mac));

		host->next = priv->hosts[id];
		if (host->next)
			host->next->prev = host;

		priv->hosts[id] = host;
		pom_mutex_unlock(&priv->lock);

		// Announce the new station
	
		if (event_has_listener(priv->evt_new_sta)) {
			struct event *evt = event_alloc(priv->evt_new_sta);
			if (!evt)
				return POM_ERR;

			struct data *evt_data = evt->data;
			ptype_copy(evt_data[analyzer_arp_new_sta_mac_addr].value, s->pkt_info->fields_value[proto_arp_field_sender_hw_addr]);
			ptype_copy(evt_data[analyzer_arp_new_sta_ip_addr].value, s->pkt_info->fields_value[proto_arp_field_sender_proto_addr]);
			PTYPE_STRING_SETVAL(evt_data[analyzer_arp_new_sta_input].value, p->input->name);
			if (event_process(evt, stack, stack_index) != POM_OK)
				return POM_ERR;
		}
		
		// Nothing else to do
		return POM_OK;
	}

	// Host was found, check mac
	if (memcmp(host->mac, arp_mac, sizeof(host->mac))) {
		if (event_has_listener(priv->evt_sta_changed)) {
			struct event *evt = event_alloc(priv->evt_sta_changed);
			if (!evt) {
				pom_mutex_unlock(&priv->lock);
				return POM_ERR;
			}

			struct data *evt_data = evt->data;
			PTYPE_MAC_SETADDR(evt_data[analyzer_arp_sta_changed_old_mac_addr].value, host->mac);
			ptype_copy(evt_data[analyzer_arp_sta_changed_new_mac_addr].value, s->pkt_info->fields_value[proto_arp_field_sender_hw_addr]);
			ptype_copy(evt_data[analyzer_arp_sta_changed_ip_addr].value, s->pkt_info->fields_value[proto_arp_field_sender_proto_addr]);
			PTYPE_STRING_SETVAL(evt_data[analyzer_arp_sta_changed_input].value, p->input->name);

			if (event_process(evt, stack, stack_index) != POM_OK) {
				pom_mutex_unlock(&priv->lock);
				return POM_ERR;
			}
		}
		memcpy(host->mac, arp_mac, sizeof(host->mac));
	}
	


	pom_mutex_unlock(&priv->lock);
	return POM_OK;
}
