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

#include <pom-ng/ptype_mac.h>
#include <pom-ng/ptype_string.h>
#include <pom-ng/ptype_timestamp.h>
#include <pom-ng/ptype_uint8.h>
#include <pom-ng/input.h>
#include <pom-ng/proto_docsis.h>
#include <docsis.h>
#include <arpa/inet.h>

#include "analyzer_docsis.h"

struct mod_reg_info *analyzer_docsis_reg_info() {

	static struct mod_reg_info reg_info = { 0 };
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = analyzer_docsis_mod_register;
	reg_info.unregister_func = analyzer_docsis_mod_unregister;
	reg_info.dependencies = "proto_docsis, ptype_mac, ptype_string, ptype_timestamp, ptype_uint8";

	return &reg_info;
}

static int analyzer_docsis_mod_register(struct mod_reg *mod) {
	
	static struct analyzer_reg analyzer_docsis = { 0 };
	analyzer_docsis.name = "docsis";
	analyzer_docsis.api_ver = ANALYZER_API_VER;
	analyzer_docsis.mod = mod;
	analyzer_docsis.init = analyzer_docsis_init;
	analyzer_docsis.cleanup = analyzer_docsis_cleanup;

	return analyzer_register(&analyzer_docsis);

}

static int analyzer_docsis_mod_unregister() {

	return analyzer_unregister("docsis");
}

static int analyzer_docsis_init(struct analyzer *analyzer) {

	struct analyzer_docsis_priv *priv = malloc(sizeof(struct analyzer_docsis_priv));
	if (!priv) {
		pom_oom(sizeof(struct analyzer_docsis_priv));
		return POM_ERR;
	}
	memset(priv, 0, sizeof(struct analyzer_docsis_priv));

	analyzer->priv = priv;

	if (pthread_mutex_init(&priv->lock, NULL)) {
		pomlog(POMLOG_ERR "Error while initializing table lock : %s", pom_strerror(errno));
		free(priv);
		return POM_ERR;
	}


	static struct data_item_reg evt_new_cm_data_items[ANALYZER_DOCSIS_EVT_NEW_CM_DATA_COUNT] = { { 0 } };
	evt_new_cm_data_items[analyzer_docsis_new_cm_mac].name = "mac";
	evt_new_cm_data_items[analyzer_docsis_new_cm_mac].value_type = ptype_get_type("mac");
	evt_new_cm_data_items[analyzer_docsis_new_cm_input].name = "input";
	evt_new_cm_data_items[analyzer_docsis_new_cm_input].value_type = ptype_get_type("string");
	evt_new_cm_data_items[analyzer_docsis_new_cm_time].name = "time";
	evt_new_cm_data_items[analyzer_docsis_new_cm_time].value_type = ptype_get_type("timestamp");


	static struct data_reg evt_new_cm_data = {
		.items = evt_new_cm_data_items,
		.data_count = ANALYZER_DOCSIS_EVT_NEW_CM_DATA_COUNT
	};

	static struct event_reg_info analyzer_docsis_evt_new_cm = { 0 };
	analyzer_docsis_evt_new_cm.source_name = "analyzer_docsis";
	analyzer_docsis_evt_new_cm.source_obj = analyzer;
	analyzer_docsis_evt_new_cm.name = "docsis_new_cm";
	analyzer_docsis_evt_new_cm.description = "New cable modem found";
	analyzer_docsis_evt_new_cm.data_reg = &evt_new_cm_data;
	analyzer_docsis_evt_new_cm.listeners_notify = analyzer_docsis_event_listeners_notify;

	priv->evt_new_cm = event_register(&analyzer_docsis_evt_new_cm);
	if (!priv->evt_new_cm)
		goto err;

	static struct data_item_reg evt_cm_timeout_data_items[ANALYZER_DOCSIS_EVT_CM_TIMEOUT_DATA_COUNT] = { { 0 } };
	evt_cm_timeout_data_items[analyzer_docsis_cm_timeout_mac].name = "mac";
	evt_cm_timeout_data_items[analyzer_docsis_cm_timeout_mac].value_type = ptype_get_type("mac");
	evt_cm_timeout_data_items[analyzer_docsis_cm_timeout_time].name = "time";
	evt_cm_timeout_data_items[analyzer_docsis_cm_timeout_time].value_type = ptype_get_type("timestamp");

	static struct data_reg evt_cm_timeout_data = {
		.items = evt_cm_timeout_data_items,
		.data_count = ANALYZER_DOCSIS_EVT_CM_TIMEOUT_DATA_COUNT
	};

	static struct event_reg_info analyzer_docsis_evt_cm_timeout = { 0 };
	analyzer_docsis_evt_cm_timeout.source_name = "analyer_docsis";
	analyzer_docsis_evt_cm_timeout.source_obj = analyzer;
	analyzer_docsis_evt_cm_timeout.name = "docsis_cm_timeout";
	analyzer_docsis_evt_cm_timeout.description = "Cable modem timed out (disconnected)";
	analyzer_docsis_evt_cm_timeout.data_reg = &evt_cm_timeout_data;
	analyzer_docsis_evt_cm_timeout.listeners_notify = analyzer_docsis_event_listeners_notify;

	priv->evt_cm_timeout = event_register(&analyzer_docsis_evt_cm_timeout);
	if (!priv->evt_cm_timeout)
		goto err;
	return POM_OK;

err:
	analyzer_docsis_cleanup(analyzer);

	return POM_ERR;
}

static int analyzer_docsis_cleanup(struct analyzer *analyzer) {

	struct analyzer_docsis_priv *priv = analyzer->priv;

	pthread_mutex_destroy(&priv->lock);

	if (priv->evt_new_cm)
		event_unregister(priv->evt_new_cm);

	if (priv->filter)
		filter_proto_cleanup(priv->filter);
	
	int i;
	for (i = 0; i < ANALYZER_DOCSIS_CM_TABLE_SIZE; i++) {
		while (priv->cms[i]) {
			struct analyzer_docsis_cm *tmp = priv->cms[i];
			priv->cms[i] = tmp->next;
			free(tmp);
		}
	}

	free(priv);

	return POM_OK;
}

static int analyzer_docsis_event_listeners_notify(void *obj, struct event_reg *evt_reg, int has_listeners) {
	
	struct analyzer *analyzer = obj;
	struct analyzer_docsis_priv *priv = analyzer->priv;

	if (has_listeners) {

		// Check if we are already listening
		if (priv->pkt_listener)
			return POM_OK;

		if (!priv->filter) {
			priv->filter = filter_proto_build("docsis_mgmt", "type", PTYPE_OP_GT, "3");
			if (!priv->filter) {
				pomlog(POMLOG_ERR "Error while building filter");
				return POM_ERR;
			}
		}

		priv->pkt_listener = proto_packet_listener_register(proto_get("docsis_mgmt"), 0, obj, analyzer_docsis_pkt_process);
		if (!priv->pkt_listener)
			return POM_ERR;

		// Filter out useless broadcast docsis_mgmt packets
		proto_packet_listener_set_filter(priv->pkt_listener, priv->filter);

	} else {

		// Check if there is still an event being listened
		if (event_has_listener(priv->evt_new_cm) || event_has_listener(priv->evt_cm_timeout))
			return POM_OK;

		if (proto_packet_listener_unregister(priv->pkt_listener) != POM_OK)
			return POM_ERR;
		priv->pkt_listener = NULL;
	}

	return POM_OK;
}

static int analyzer_docsis_pkt_process(void *obj, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct analyzer *analyzer = obj;
	struct analyzer_docsis_priv *priv = analyzer->priv;

	struct proto_process_stack *s = &stack[stack_index];

	uint8_t *type = PTYPE_UINT8_GETVAL(s->pkt_info->fields_value[proto_docsis_mgmt_field_type]);

	char *mac_dst = PTYPE_MAC_GETADDR(s->pkt_info->fields_value[proto_docsis_mgmt_field_daddr]);

	switch (*type) {

		case MMT_RNG_RSP:
			break;

		case MMT_UCD2:
		case MMT_UCD3: // No useful info in UCD

		case MMT_MDD: // We don't care about MDD so far
			return POM_OK;

		default:
			pomlog(POMLOG_DEBUG "Unhandled DOCSIS MGMT message type %u for destination mac %02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX", *type, mac_dst[0], mac_dst[1], mac_dst[2], mac_dst[3], mac_dst[4], mac_dst[5]);
			return POM_OK;
	}

	// Use the last bits for the modem ID
	uint16_t id = ntohs(*(uint16_t*) (mac_dst + 4)) & ANALYZER_DOCSIS_CM_MASK;

	pom_mutex_lock(&priv->lock);

	struct analyzer_docsis_cm *cm;
	for (cm = priv->cms[id]; cm; cm = cm->next) {
		if (!memcmp(cm->mac, mac_dst, sizeof(cm->mac)))
			break;
	}

	if (!cm) {
		// Cable modem not found !
		cm = malloc(sizeof(struct analyzer_docsis_cm));
		if (!cm) {
			pom_oom(sizeof(struct analyzer_docsis_cm));
			return POM_ERR;
		}
		memset(cm, 0, sizeof(struct analyzer_docsis_cm));

		cm->t = timer_alloc(cm, analyzer_docsis_cm_timeout);
		if (!cm->t) {
			free(cm);
			return POM_ERR;
		}
	
		cm->analyzer = analyzer;
		memcpy(cm->mac, mac_dst, sizeof(cm->mac));

		cm->next = priv->cms[id];
		if (cm->next)
			cm->next->prev = cm;

		priv->cms[id] = cm;

		timer_queue(cm->t, ANALYZER_DOCSIS_CM_TIMEOUT);

		pom_mutex_unlock(&priv->lock);

		// Announce the new CM
		if (event_has_listener(priv->evt_new_cm)) {
			struct event *evt = event_alloc(priv->evt_new_cm);
			if (!evt)
				return POM_ERR;

			struct data *evt_data = evt->data;
			PTYPE_MAC_SETADDR(evt_data[analyzer_docsis_new_cm_mac].value, mac_dst);
			PTYPE_STRING_SETVAL(evt_data[analyzer_docsis_new_cm_input].value, p->input->name);
			PTYPE_TIMESTAMP_SETVAL(evt_data[analyzer_docsis_new_cm_time].value, p->ts);

			if (event_process(evt, stack, stack_index) != POM_OK)
				return POM_ERR;
		}
	} else {
		timer_queue(cm->t, ANALYZER_DOCSIS_CM_TIMEOUT);
		pom_mutex_unlock(&priv->lock);
	}

	return POM_OK;
}

static int analyzer_docsis_cm_timeout(void *cable_modem, struct timeval *now) {

	struct analyzer_docsis_cm *cm = cable_modem;
	struct analyzer_docsis_priv *priv = cm->analyzer->priv;

	pom_mutex_lock(&priv->lock);

	if (event_has_listener(priv->evt_cm_timeout)) {
		struct event *evt = event_alloc(priv->evt_cm_timeout);
		if (!evt) {
			pom_mutex_unlock(&priv->lock);
			return POM_ERR;
		}
		struct data *evt_data = evt->data;
		PTYPE_MAC_SETADDR(evt_data[analyzer_docsis_cm_timeout_mac].value, cm->mac);
		PTYPE_TIMESTAMP_SETVAL(evt_data[analyzer_docsis_cm_timeout_time].value, *now);

		if (event_process(evt, NULL, 0) != POM_OK) {
			pom_mutex_unlock(&priv->lock);
			return POM_ERR;
		}
	}

	// Use the last bits for the modem ID
	uint16_t id = ntohs(*(uint16_t*) (cm->mac + 4)) & ANALYZER_DOCSIS_CM_MASK;

	// Remove the CM from the list
	if (cm->prev)
		cm->prev->next = cm->next;
	else
		priv->cms[id] = cm->next;

	if (cm->next)
		cm->next->prev = cm->prev;

	timer_cleanup(cm->t);
	free(cm);

	pom_mutex_unlock(&priv->lock);

	return POM_OK;
}
