/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2011 Guy Martin <gmsoft@tuxicoman.be>
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

#include <sys/time.h>
#include "analyzer_http.h"
#include <pom-ng/proto_http.h>
#include <pom-ng/ptype_uint16.h>

struct mod_reg_info* analyzer_http_reg_info() {

	static struct mod_reg_info reg_info;
	memset(&reg_info, 0, sizeof(struct mod_reg_info));
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = analyzer_http_mod_register;
	reg_info.unregister_func = analyzer_http_mod_unregister;

	return &reg_info;
}


static int analyzer_http_mod_register(struct mod_reg *mod) {

	static struct analyzer_reg_info analyzer_http;
	analyzer_http.name = "http";
	analyzer_http.api_ver = ANALYZER_API_VER;
	analyzer_http.mod = mod;
	analyzer_http.init = analyzer_http_init;
	analyzer_http.cleanup = analyzer_http_cleanup;

	return analyzer_register(&analyzer_http);

}

static int analyzer_http_mod_unregister() {

	int res = analyzer_unregister("http");

	return res;
}


static int analyzer_http_init(struct analyzer_reg *analyzer) {

	static struct analyzer_data_reg http_data_fields[ANALYZER_HTTP_DATA_FIELDS_COUNT + 1];
	memset(&http_data_fields, 0, sizeof(struct analyzer_data_reg) * (ANALYZER_HTTP_DATA_FIELDS_COUNT + 1));
	http_data_fields[analyzer_http_data_server_name].name = "server_name";
	http_data_fields[analyzer_http_data_server_addr].name = "server_addr";
	http_data_fields[analyzer_http_data_server_port].name = "server_port";
	http_data_fields[analyzer_http_data_client_addr].name = "client_addr";
	http_data_fields[analyzer_http_data_client_port].name = "client_port";
	http_data_fields[analyzer_http_data_request_proto].name = "request_proto";
	http_data_fields[analyzer_http_data_request_method].name = "request_method";
	http_data_fields[analyzer_http_data_first_line].name = "first_line";
	http_data_fields[analyzer_http_data_url].name = "url";
	http_data_fields[analyzer_http_data_query_time].name = "query_time";
	http_data_fields[analyzer_http_data_response_time].name = "response_time";
	http_data_fields[analyzer_http_data_username].name = "username";
	http_data_fields[analyzer_http_data_password].name = "password";
	http_data_fields[analyzer_http_data_status].name = "status";

	struct analyzer_http_priv *priv = malloc(sizeof(struct analyzer_http_priv));
	if (!priv) {
		pom_oom(sizeof(struct analyzer_http_priv));
		return POM_ERR;
	}
	memset(priv, 0, sizeof(struct analyzer_http_priv));

	// Parse the format


	priv->source = analyzer_register_data_conntrack_source(analyzer, "http", http_data_fields, "http", analyzer_http_conntrack_process);
	if (!priv->source) {
		free(priv);
		return POM_ERR;
	}
	analyzer->priv = priv;
		
	return POM_OK;
}

static int analyzer_http_cleanup(struct analyzer_reg *analyzer) {

	struct analyzer_http_priv *priv = analyzer->priv;
	if (!priv)
		return POM_OK;

	free(priv);

	return POM_OK;
}

static int analyzer_http_conntrack_process(struct analyzer_reg *analyzer, struct proto_process_stack *stack, unsigned int stack_index) {

	struct proto_process_stack *s = &stack[stack_index];
	if (!s->ce || !s->ce->con_info)
		return POM_ERR;

	struct conntrack_con_info *con_info = s->ce->con_info;

	struct analyzer_data data[ANALYZER_HTTP_DATA_FIELDS_COUNT + 1];
	memset(&data, 0, sizeof(struct analyzer_data) * (ANALYZER_HTTP_DATA_FIELDS_COUNT + 1));

	// Do the mapping, no flag checking or other, we just know how :)
	

	if (!con_info[proto_http_field_request_dir].val[0].set)
		return POM_ERR; // shouldn't happen but we need to know the direction

	uint16_t *dir;
	PTYPE_UINT16_GETVAL(con_info[proto_http_field_request_dir].val[0].value, dir);

	
	// analyzer_http_data_server_name
	if (con_info[proto_http_field_host].val[0].set)
		data[analyzer_http_data_server_name].value = con_info[proto_http_field_host].val[0].value;

	// analyzer_http_data_server_port, analyzer_http_data_client_port
	if (stack_index > 1) {
		struct ptype *sport = NULL, *dport = NULL;
		struct proto_process_stack *l4_stack = &stack[stack_index - 1];
		unsigned int i;
		for (i = 0; !sport || !dport ; i++) {
			char *name = l4_stack->proto->info->pkt_fields[i].name;
			if (!name)
				break;

			if (!sport && !strcmp(name, "sport"))
				sport = l4_stack->pkt_info->fields_value[i];
			else if (!dport && !strcmp(name, "dport"))
				dport = l4_stack->pkt_info->fields_value[i];
		}

		if (*dir) {
			data[analyzer_http_data_server_port].value = sport;
			data[analyzer_http_data_client_port].value = dport;
		} else {
			data[analyzer_http_data_server_port].value = dport;
			data[analyzer_http_data_client_port].value = sport;
		}
	}

	// analyzer_http_data_server_addr, analyzer_http_data_client_addr
	if (stack_index > 2) {
		struct ptype *src = NULL, *dst = NULL;
		struct proto_process_stack *l3_stack = &stack[stack_index - 2];
		unsigned int i;
		for (i = 0; !src || !dst ; i++) {
			char *name = l3_stack->proto->info->pkt_fields[i].name;
			if (!name)
				break;

			if (!src && !strcmp(name, "src"))
				src = l3_stack->pkt_info->fields_value[i];
			else if (!dst && !strcmp(name, "dst"))
				dst = l3_stack->pkt_info->fields_value[i];
		}

		if (*dir) {
			data[analyzer_http_data_server_addr].value = src;
			data[analyzer_http_data_client_addr].value = dst;
		} else {
			data[analyzer_http_data_server_addr].value = dst;
			data[analyzer_http_data_client_addr].value = src;
		}

	}

	// analyzer_http_data_request_proto	
	if (con_info[proto_http_field_request_proto].val[0].set)
		data[analyzer_http_data_request_proto].value = con_info[proto_http_field_request_proto].val[0].value;

	// analyzer_http_data_request_method
	if (con_info[proto_http_field_request_method].val[0].set)
		data[analyzer_http_data_request_method].value = con_info[proto_http_field_request_method].val[0].value;

	// analyzer_http_data_first_line
	if (con_info[proto_http_field_first_line].val[0].set)
		data[analyzer_http_data_first_line].value = con_info[proto_http_field_first_line].val[0].value;

	// analyzer_http_data_url
	if (con_info[proto_http_field_url].val[0].set)
		data[analyzer_http_data_url].value = con_info[proto_http_field_url].val[0].value;

	// analyzer_http_data_query_time
	// TODO
	
	// analyzer_http_data_response_time
	// TODO
	
	// analyzer_http_data_status
	if (con_info[proto_http_field_err_code].val[0].set)
		data[analyzer_http_data_status].value = con_info[proto_http_field_err_code].val[0].value;

	// analyzer_http_data_username
	// TODO

	// analyzer_http_data_password
	// TODO

	// TODO headers

	struct analyzer_http_priv *priv = analyzer->priv;

	return analyzer_data_source_process(priv->source, data);
}
