/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2015 Guy Martin <gmsoft@tuxicoman.be>
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

#include "analyzer_rtp.h"

#include <pom-ng/pload.h>
#include <pom-ng/ptype_string.h>
#include <pom-ng/ptype_uint16.h>
#include <pom-ng/proto_rtp.h>
#include <pom-ng/telephony.h>


#if 0
#define debug_rtp(x ...) pomlog(POMLOG_DEBUG x)
#else
#define debug_rtp(x ...)
#endif

struct mod_reg_info* analyzer_rtp_reg_info() {

	static struct mod_reg_info reg_info;
	memset(&reg_info, 0, sizeof(struct mod_reg_info));
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = analyzer_rtp_mod_register;
	reg_info.unregister_func = analyzer_rtp_mod_unregister;
	reg_info.dependencies = "proto_rtp, ptype_string, ptype_uint16, ptype_uint32";

	return &reg_info;
}

static int analyzer_rtp_mod_register(struct mod_reg *mod) {

	static struct analyzer_reg analyzer_rtp;
	memset(&analyzer_rtp, 0, sizeof(struct analyzer_reg));
	analyzer_rtp.name = "rtp";
	analyzer_rtp.mod = mod;
	analyzer_rtp.init = analyzer_rtp_init;
	analyzer_rtp.cleanup = analyzer_rtp_cleanup;

	return analyzer_register(&analyzer_rtp);

}

static int analyzer_rtp_mod_unregister() {

	return analyzer_unregister("rtp");
}

static int analyzer_rtp_init(struct analyzer *analyzer) {

	struct analyzer_rtp_priv *priv = malloc(sizeof(struct analyzer_rtp_priv));
	if (!priv) {
		pom_oom(sizeof(struct analyzer_rtp_priv));
		return POM_ERR;
	}
	memset(priv, 0, sizeof(struct analyzer_rtp_priv));
	analyzer->priv = priv;

	priv->proto_rtp = proto_get("rtp");
	if (!priv->proto_rtp)
		goto err;

	static struct data_item_reg evt_rtp_stream_data_items[ANALYZER_RTP_STREAM_DATA_COUNT] = { { 0 } };

	evt_rtp_stream_data_items[analyzer_rtp_stream_src_addr].name = "src_addr";
	evt_rtp_stream_data_items[analyzer_rtp_stream_src_addr].flags = DATA_REG_FLAG_NO_ALLOC;

	evt_rtp_stream_data_items[analyzer_rtp_stream_dst_addr].name = "dst_addr";
	evt_rtp_stream_data_items[analyzer_rtp_stream_dst_addr].flags = DATA_REG_FLAG_NO_ALLOC;

	evt_rtp_stream_data_items[analyzer_rtp_stream_src_port].name = "src_port";
	evt_rtp_stream_data_items[analyzer_rtp_stream_src_port].value_type = ptype_get_type("uint16");

	evt_rtp_stream_data_items[analyzer_rtp_stream_dst_port].name = "dst_port";
	evt_rtp_stream_data_items[analyzer_rtp_stream_dst_port].value_type = ptype_get_type("uint16");

	evt_rtp_stream_data_items[analyzer_rtp_stream_sess_proto].name = "sess_proto";
	evt_rtp_stream_data_items[analyzer_rtp_stream_sess_proto].value_type = ptype_get_type("string");

	evt_rtp_stream_data_items[analyzer_rtp_stream_call_id].name = "call_id";
	evt_rtp_stream_data_items[analyzer_rtp_stream_call_id].value_type = ptype_get_type("string");

	evt_rtp_stream_data_items[analyzer_rtp_stream_ssrc].name = "ssrc";
	evt_rtp_stream_data_items[analyzer_rtp_stream_ssrc].value_type = ptype_get_type("uint32");

	static struct data_reg evt_rtp_stream_data = {
		.items = evt_rtp_stream_data_items,
		.data_count = ANALYZER_RTP_STREAM_DATA_COUNT
	};

	static struct event_reg_info analyzer_rtp_evt_stream = { 0 };
	analyzer_rtp_evt_stream.source_name = "analyzer_rtp";
	analyzer_rtp_evt_stream.source_obj = analyzer;
	analyzer_rtp_evt_stream.name = "rtp_stream";
	analyzer_rtp_evt_stream.description = "RTP stream in a single direction";
	analyzer_rtp_evt_stream.data_reg = &evt_rtp_stream_data;
	analyzer_rtp_evt_stream.flags = EVENT_REG_FLAG_PAYLOAD;
	analyzer_rtp_evt_stream.listeners_notify = analyzer_rtp_event_listeners_notify;
	analyzer_rtp_evt_stream.cleanup = analyzer_rtp_stream_event_cleanup;
	
	priv->evt_rtp_stream = event_register(&analyzer_rtp_evt_stream);
	if (!priv->evt_rtp_stream)
		goto err;

	return POM_OK;

err:
	analyzer_rtp_cleanup(analyzer);
	return POM_ERR;
}


static int analyzer_rtp_cleanup(struct analyzer *analyzer) {

	struct analyzer_rtp_priv *priv = analyzer->priv;

	if (priv->evt_rtp_stream)
		event_unregister(priv->evt_rtp_stream);

	free(priv);
	return POM_OK;
}


static int analyzer_rtp_event_listeners_notify(void *obj, struct event_reg *evt_reg, int has_listeners) {

	struct analyzer *analyzer = obj;
	struct analyzer_rtp_priv *priv = analyzer->priv;

	if (has_listeners) {
		priv->rtp_listener = proto_packet_listener_register(priv->proto_rtp, PROTO_PACKET_LISTENER_PLOAD_ONLY, analyzer, analyzer_rtp_pload_process, NULL);
		if (!priv->rtp_listener)
			return POM_ERR;
	} else {
		if (!priv->rtp_listener || proto_packet_listener_unregister(priv->rtp_listener) != POM_OK)
			return POM_ERR;
	}

	return POM_OK;
}


static int analyzer_rtp_pload_process(void *obj, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct analyzer *analyzer = obj;
	struct analyzer_rtp_priv *priv = analyzer->priv;

	struct proto_process_stack *pload_stack = &stack[stack_index];
	struct proto_process_stack *s = &stack[stack_index - 1];

	if (!s->ce)
		return POM_ERR;

	struct analyzer_rtp_ce_priv *cp = conntrack_get_priv(s->ce, obj);
	if (!cp) {
		cp = malloc(sizeof(struct analyzer_rtp_ce_priv));
		if (!cp) {
			pom_oom(sizeof(struct analyzer_rtp_ce_priv));
			return POM_ERR;
		}
		memset(cp, 0, sizeof(struct analyzer_rtp_ce_priv));

		if (conntrack_add_priv(s->ce, obj, cp, analyzer_rtp_ce_cleanup) != POM_OK)
			return POM_ERR;
	}

	int dir = s->direction;

	if (!cp->evt[dir]) {
		cp->evt[dir] = event_alloc(priv->evt_rtp_stream);
		if (!cp->evt[dir])
			return POM_ERR;

		struct data *evt_data = event_get_data(cp->evt[dir]);
		ptype_copy(evt_data[analyzer_rtp_stream_ssrc].value, s->pkt_info->fields_value[proto_rtp_field_ssrc]);
		data_set(evt_data[analyzer_rtp_stream_ssrc]);

		// For now we always assume RTP is over UDP or TCP
		if (stack_index > 2) {
			struct proto_process_stack *l4_stack = &stack[stack_index - 2];
			unsigned int i;
			for (i = 0; !data_is_set(evt_data[analyzer_rtp_stream_src_port]) || !data_is_set(evt_data[analyzer_rtp_stream_dst_port]); i++) {
				struct proto_reg_info *l4_info = proto_get_info(l4_stack->proto);
				char *name = l4_info->pkt_fields[i].name;
				if (!name)
					break;
				if (!data_is_set(evt_data[analyzer_rtp_stream_src_port]) && !strcmp(name, "sport")) {
					ptype_copy(evt_data[analyzer_rtp_stream_src_port].value, l4_stack->pkt_info->fields_value[i]);
					data_set(evt_data[analyzer_rtp_stream_src_port]);
				} else if (!data_is_set(evt_data[analyzer_rtp_stream_dst_port]) && !strcmp(name, "dport")) {
					ptype_copy(evt_data[analyzer_rtp_stream_dst_port].value, l4_stack->pkt_info->fields_value[i]);
					data_set(evt_data[analyzer_rtp_stream_dst_port]);
				}
			}

		}

		if (stack_index > 3) {
			struct proto_process_stack *l3_stack = &stack[stack_index - 3];
			unsigned int i;
			for (i = 0; !data_is_set(evt_data[analyzer_rtp_stream_src_addr]) || !data_is_set(evt_data[analyzer_rtp_stream_dst_addr]); i++) {
				struct proto_reg_info *l3_info = proto_get_info(l3_stack->proto);
				char *name = l3_info->pkt_fields[i].name;
				if (!name)
					break;
				if (!data_is_set(evt_data[analyzer_rtp_stream_src_addr]) && !strcmp(name, "src")) {
					evt_data[analyzer_rtp_stream_src_addr].value = ptype_alloc_from(l3_stack->pkt_info->fields_value[i]);
					if (evt_data[analyzer_rtp_stream_src_addr].value)
						data_set(evt_data[analyzer_rtp_stream_src_addr]);
				} else if (!data_is_set(evt_data[analyzer_rtp_stream_dst_addr]) && !strcmp(name, "dst")) {
					evt_data[analyzer_rtp_stream_dst_addr].value = ptype_alloc_from(l3_stack->pkt_info->fields_value[i]);
					if (evt_data[analyzer_rtp_stream_dst_addr].value)
						data_set(evt_data[analyzer_rtp_stream_dst_addr]);
				}
			}

		}

		struct proto *sess_proto = telephony_stream_info_get_sess_proto(s->ce);
		if (sess_proto) {
			struct proto_reg_info *proto_reg = proto_get_info(sess_proto);
			PTYPE_STRING_SETVAL(evt_data[analyzer_rtp_stream_sess_proto].value, proto_reg->name);
			data_set(evt_data[analyzer_rtp_stream_sess_proto]);
		}

		char *call_id = telephony_stream_info_get_call_id(s->ce);
		if (call_id) {
			PTYPE_STRING_SETVAL_P(evt_data[analyzer_rtp_stream_call_id].value, call_id);
			data_set(evt_data[analyzer_rtp_stream_call_id]);
		}

		if (event_process_begin(cp->evt[dir], stack, stack_index, p->ts) != POM_OK)
			return POM_ERR;
	}

	if (!cp->pload[dir]) {
		cp->pload[dir] = pload_alloc(cp->evt[dir], 0);
		if (!cp->pload[dir])
			return POM_ERR;
	}

	if (pload_append(cp->pload[dir], pload_stack->pload, pload_stack->plen) != POM_OK)
		return POM_ERR;

	return POM_OK;
}

static int analyzer_rtp_ce_cleanup(void *obj, void *priv) {

	struct analyzer_rtp_ce_priv *cp = priv;

	int i;
	for (i = 0; i < POM_DIR_TOT; i++) {
		if (cp->pload[i])
			pload_end(cp->pload[i]);
		if (cp->evt[i])
			event_process_end(cp->evt[i]);
	}

	free(cp);

	return POM_OK;
}

static int analyzer_rtp_stream_event_cleanup(struct event *evt) {


	struct data *evt_data = event_get_data(evt);

	if (data_is_set(evt_data[analyzer_rtp_stream_src_addr]))
		ptype_cleanup(evt_data[analyzer_rtp_stream_src_addr].value);
	if (data_is_set(evt_data[analyzer_rtp_stream_dst_addr]))
		ptype_cleanup(evt_data[analyzer_rtp_stream_dst_addr].value);

	return POM_OK;
}

