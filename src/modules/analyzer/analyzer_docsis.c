/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2012-2015 Guy Martin <gmsoft@tuxicoman.be>
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
#include <pom-ng/event.h>
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

	static struct data_item_reg evt_cm_new_data_items[ANALYZER_DOCSIS_EVT_CM_NEW_DATA_COUNT] = { { 0 } };
	evt_cm_new_data_items[analyzer_docsis_cm_new_mac].name = "mac",
	evt_cm_new_data_items[analyzer_docsis_cm_new_mac].value_type = ptype_get_type("mac");
	evt_cm_new_data_items[analyzer_docsis_cm_new_input].name = "input",
	evt_cm_new_data_items[analyzer_docsis_cm_new_input].value_type = ptype_get_type("string");

	static struct data_reg evt_cm_new_data = {
		.items = evt_cm_new_data_items,
		.data_count = ANALYZER_DOCSIS_EVT_CM_NEW_DATA_COUNT
	};

	static struct event_reg_info analyzer_docsis_evt_cm_new = { 0 };
	analyzer_docsis_evt_cm_new.source_name = "analyzer_docsis";
	analyzer_docsis_evt_cm_new.source_obj = analyzer;
	analyzer_docsis_evt_cm_new.name = "docsis_cm_new";
	analyzer_docsis_evt_cm_new.description = "New cable modem found";
	analyzer_docsis_evt_cm_new.data_reg = &evt_cm_new_data;
	analyzer_docsis_evt_cm_new.listeners_notify = analyzer_docsis_event_listeners_notify;

	priv->evt_cm_new = event_register(&analyzer_docsis_evt_cm_new);
	if (!priv->evt_cm_new)
		goto err;

	static struct data_item_reg evt_cm_reg_status_data_items[ANALYZER_DOCSIS_EVT_CM_REG_STATUS_DATA_COUNT] = { { 0 } };
	evt_cm_reg_status_data_items[analyzer_docsis_cm_reg_status_old].name = "old_status",
	evt_cm_reg_status_data_items[analyzer_docsis_cm_reg_status_old].value_type = ptype_get_type("uint8");
	evt_cm_reg_status_data_items[analyzer_docsis_cm_reg_status_new].name = "new_status",
	evt_cm_reg_status_data_items[analyzer_docsis_cm_reg_status_new].value_type = ptype_get_type("uint8");
	evt_cm_reg_status_data_items[analyzer_docsis_cm_reg_status_mac].name = "mac";
	evt_cm_reg_status_data_items[analyzer_docsis_cm_reg_status_mac].value_type = ptype_get_type("mac");
	evt_cm_reg_status_data_items[analyzer_docsis_cm_reg_status_timeout].name = "timeout",
	evt_cm_reg_status_data_items[analyzer_docsis_cm_reg_status_timeout].value_type = ptype_get_type("uint8");

	static struct data_reg evt_cm_reg_status_data = {
		.items = evt_cm_reg_status_data_items,
		.data_count = ANALYZER_DOCSIS_EVT_CM_REG_STATUS_DATA_COUNT
	};

	static struct event_reg_info analyzer_docsis_evt_cm_reg_status = { 0 };
	analyzer_docsis_evt_cm_reg_status.source_name = "analyzer_docsis";
	analyzer_docsis_evt_cm_reg_status.source_obj = analyzer;
	analyzer_docsis_evt_cm_reg_status.name = "docsis_cm_reg_status";
	analyzer_docsis_evt_cm_reg_status.description = "Cable modem registration status changed";
	analyzer_docsis_evt_cm_reg_status.data_reg = &evt_cm_reg_status_data;
	analyzer_docsis_evt_cm_reg_status.listeners_notify = analyzer_docsis_event_listeners_notify;

	priv->evt_cm_reg_status = event_register(&analyzer_docsis_evt_cm_reg_status);
	if (!priv->evt_cm_reg_status)
		goto err;

	return POM_OK;

err:
	analyzer_docsis_cleanup(analyzer);

	return POM_ERR;
}

static int analyzer_docsis_cleanup(struct analyzer *analyzer) {

	struct analyzer_docsis_priv *priv = analyzer->priv;

	pthread_mutex_destroy(&priv->lock);

	if (priv->evt_cm_new)
		event_unregister(priv->evt_cm_new);

	if (priv->evt_cm_reg_status)
		event_unregister(priv->evt_cm_reg_status);

	if (priv->filter)
		filter_cleanup(priv->filter);
	
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
			priv->filter = packet_filter_compile("docsis_mgmt.type > 3");
			if (!priv->filter) {
				pomlog(POMLOG_ERR "Error while building filter");
				return POM_ERR;
			}
		}

		priv->pkt_listener = proto_packet_listener_register(proto_get("docsis_mgmt"), 0, obj, analyzer_docsis_pkt_process, priv->filter);
		if (!priv->pkt_listener)
			return POM_ERR;

	} else {
		
		if (event_has_listener(priv->evt_cm_new) || event_has_listener(priv->evt_cm_reg_status))
			return POM_OK;

		if (proto_packet_listener_unregister(priv->pkt_listener) != POM_OK)
			return POM_ERR;
		priv->pkt_listener = NULL;
	}

	return POM_OK;
}

static int analyzer_docsis_reg_status_update(struct analyzer_docsis_priv *priv, struct analyzer_docsis_cm *cm, enum docsis_mmt_rng_status new_status, ptime ts, struct proto_process_stack *stack, unsigned int stack_index) {

	if (cm->ranging_status == new_status)
		return POM_OK;

	if (event_has_listener(priv->evt_cm_reg_status)) {
		struct event *evt = event_alloc(priv->evt_cm_reg_status);
		if (!evt) {
			pom_mutex_unlock(&priv->lock);
			return POM_ERR;
		}

		struct data *evt_data = event_get_data(evt);
		PTYPE_UINT8_SETVAL(evt_data[analyzer_docsis_cm_reg_status_old].value, cm->ranging_status);
		data_set(evt_data[analyzer_docsis_cm_reg_status_old]);
		PTYPE_UINT8_SETVAL(evt_data[analyzer_docsis_cm_reg_status_new].value, new_status);
		data_set(evt_data[analyzer_docsis_cm_reg_status_new]);
		PTYPE_MAC_SETADDR(evt_data[analyzer_docsis_cm_reg_status_mac].value, cm->mac);
		data_set(evt_data[analyzer_docsis_cm_reg_status_mac]);
		PTYPE_UINT8_SETVAL(evt_data[analyzer_docsis_cm_reg_status_timeout].value, T4_TIMEOUT * cm->t4_multiplier);
		data_set(evt_data[analyzer_docsis_cm_reg_status_timeout]);

		if (event_process(evt, stack, stack_index, ts) != POM_OK) {
			pom_mutex_unlock(&priv->lock);
			return POM_ERR;
		}
	}

	cm->ranging_status = new_status;

	return POM_OK;
}

static int analyzer_docsis_pkt_parse_rng_rsp(struct analyzer_docsis_priv *priv, struct analyzer_docsis_cm *cm, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct proto_process_stack *s = &stack[stack_index + 1];
	void *pload = s->pload + 3;
	uint32_t len = s->plen - 3;

	int res = POM_OK;

	while (len > sizeof(struct docsis_tlv)) {
		struct docsis_tlv *tlv = pload;
		void *data = pload + sizeof(struct docsis_tlv);
		if (tlv->len > len) {
			pomlog(POMLOG_DEBUG "TLV len greater than remaining payload len : %u > %u", tlv->len, len);
			break;
		}


		switch (tlv->type) {

			case RNG_RSP_RANGING_STATUS:
				if (tlv->len != 1)
					goto err_tlv_len;

				enum docsis_mmt_rng_status new_status = *(char*)data;
				if (new_status > docsis_mmt_rng_status_success) {
					pomlog(POMLOG_DEBUG "Invalid ranging status %u", new_status);
					return POM_ERR;
				}

				res = analyzer_docsis_reg_status_update(priv, cm, new_status, p->ts, stack, stack_index);

				break;

			case RNG_RSP_T4_TIMEOUT_MULTIPLIER:
				if (tlv->len != 1)
					goto err_tlv_len;
				cm->t4_multiplier = *(char*)data;
				break;
		}

		len -= tlv->len + sizeof(struct docsis_tlv);
		pload += tlv->len + sizeof(struct docsis_tlv);
	}

	return res;

err_tlv_len:
	pomlog(POMLOG_DEBUG "Invalid TLV data len");
	return POM_ERR;

}

static int analyzer_docsis_pkt_process(void *obj, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct analyzer *analyzer = obj;
	struct analyzer_docsis_priv *priv = analyzer->priv;

	struct proto_process_stack *s = &stack[stack_index];

	uint8_t *type = PTYPE_UINT8_GETVAL(s->pkt_info->fields_value[proto_docsis_mgmt_field_type]);

	char *mac_dst = PTYPE_MAC_GETADDR(s->pkt_info->fields_value[proto_docsis_mgmt_field_dst]);

	// FIXME : improve this filtering at the source
	// Filter some useless messages we don't care about
	
	if (*type == MMT_UCD2 || *type == MMT_UCD3 || *type == MMT_MDD)
		return POM_OK;

	if (*type != MMT_RNG_RSP) {
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
			pom_mutex_unlock(&priv->lock);
			pom_oom(sizeof(struct analyzer_docsis_cm));
			return POM_ERR;
		}
		memset(cm, 0, sizeof(struct analyzer_docsis_cm));

		cm->t = timer_alloc(cm, analyzer_docsis_cm_timeout);
		if (!cm->t) {
			pom_mutex_unlock(&priv->lock);
			free(cm);
			return POM_ERR;
		}
	
		cm->analyzer = analyzer;
		memcpy(cm->mac, mac_dst, sizeof(cm->mac));
		cm->t4_multiplier = 1;

		cm->next = priv->cms[id];
		if (cm->next)
			cm->next->prev = cm;

		priv->cms[id] = cm;

		// Announce the new CM
		if (event_has_listener(priv->evt_cm_new)) {
			struct event *evt = event_alloc(priv->evt_cm_new);
			if (!evt) {
				pom_mutex_unlock(&priv->lock);
				return POM_ERR;
			}

			struct data *evt_data = event_get_data(evt);
			PTYPE_MAC_SETADDR(evt_data[analyzer_docsis_cm_new_mac].value, cm->mac);
			data_set(evt_data[analyzer_docsis_cm_new_mac]);
			PTYPE_STRING_SETVAL(evt_data[analyzer_docsis_cm_new_input].value, p->input->name);
			data_set(evt_data[analyzer_docsis_cm_new_input]);

			if (event_process(evt, stack, stack_index, p->ts) != POM_OK) {
				pom_mutex_unlock(&priv->lock);
				return POM_ERR;
			}
		}
	}


	switch (*type) {

		case MMT_RNG_RSP:
			analyzer_docsis_pkt_parse_rng_rsp(priv, cm, p, stack, stack_index);
			break;

		// FIXME If ranging_status is 0 and we receive another msg, probably it's actually registered
		// and we need to call analyzer_docsis_reg_status_update();

	}

	timer_queue_now(cm->t, T4_TIMEOUT * cm->t4_multiplier, p->ts);

	pom_mutex_unlock(&priv->lock);

	return POM_OK;
}

static int analyzer_docsis_cm_timeout(void *cable_modem, ptime now) {

	struct analyzer_docsis_cm *cm = cable_modem;
	struct analyzer_docsis_priv *priv = cm->analyzer->priv;

	pom_mutex_lock(&priv->lock);
	analyzer_docsis_reg_status_update(priv, cm, docsis_mmt_rng_status_unknown, now, NULL, 0);
	pom_mutex_unlock(&priv->lock);

	return POM_OK;
}
