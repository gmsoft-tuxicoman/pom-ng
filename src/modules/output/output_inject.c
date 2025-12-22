/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2014-2015 Guy Martin <gmsoft@tuxicoman.be>
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



#include "output_inject.h"

#include <pom-ng/ptype_string.h>
#include <pom-ng/ptype_bool.h>
#include <pom-ng/ptype_uint16.h>


struct mod_reg_info *output_inject_reg_info() {

	static struct mod_reg_info reg_info;
	memset(&reg_info, 0, sizeof(struct mod_reg_info));
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = output_inject_mod_register;
	reg_info.unregister_func = output_inject_mod_unregister;
	reg_info.dependencies = "ptype_string, ptype_bool, ptype_uint16";

	return &reg_info;
}


static int output_inject_mod_register(struct mod_reg *mod) {

	static struct output_reg_info output_inject;
	memset(&output_inject, 0, sizeof(struct output_reg_info));
	output_inject.name = "inject";
	output_inject.description = "Inject packets on an interface";
	output_inject.mod = mod;

	output_inject.init = output_inject_init;
	output_inject.open = output_inject_open;
	output_inject.close = output_inject_close;
	output_inject.cleanup = output_inject_cleanup;

	return output_register(&output_inject);

}


static int output_inject_mod_unregister() {

	return output_unregister("inject");
}


static int output_inject_init(struct output *o) {


	struct output_inject_priv *priv = malloc(sizeof(struct output_inject_priv));
	if (!priv) {
		pom_oom(sizeof(struct output_inject_priv));
		return POM_ERR;
	}
	memset(priv, 0, sizeof(struct output_inject_priv));
	output_set_priv(o, priv);

	priv->p_interface = ptype_alloc("string");
	priv->p_filter = ptype_alloc("string");

	if (!priv->p_interface || !priv->p_filter)
		goto err;

	struct registry_instance *inst = output_get_reg_instance(o);
	priv->perf_pkts_out = registry_instance_add_perf(inst, "pkts_out", registry_perf_type_counter, "Number of packets injected", "pkts");
	priv->perf_bytes_out = registry_instance_add_perf(inst, "bytes_out", registry_perf_type_counter, "Number of packet bytes injected", "bytes");

	char err[PCAP_ERRBUF_SIZE] = { 0 };
	char *dev = NULL;

	pcap_if_t *alldevs = NULL;
	if (pcap_findalldevs(&alldevs, err) == -1 || !alldevs) {
		pomlog(POMLOG_WARN "Warning, could not find a suitable interface to inject packets to : %s", err);
		dev = "none";
	} else {

		// Pick the first non-loopback interface if possible, otherwise fall back to the first entry
		pcap_if_t *d = NULL;
		for (d = alldevs; d; d = d->next) {
			if (!(d->flags & PCAP_IF_LOOPBACK)) {
				dev = d->name;
				break;
			}
		}
		if (!dev)
			dev = alldevs->name;

	}

	if (alldevs)
		pcap_freealldevs(alldevs);

	struct registry_param *p = registry_new_param("interface", dev, priv->p_interface, "Output interface", 0);
	if (output_add_param(o, p) != POM_OK)
		goto err;

	p = registry_new_param("filter", "", priv->p_filter, "Filter", REGISTRY_PARAM_FLAG_NOT_LOCKED_WHILE_RUNNING);
	if (output_add_param(o, p) != POM_OK)
		goto err;

	registry_param_set_callbacks(p, priv, output_inject_filter_parse, output_inject_filter_update);

	return POM_OK;

err:
	output_inject_cleanup(priv);
	return POM_ERR;

}

static int output_inject_cleanup(void *output_priv) {

	struct output_inject_priv *priv = output_priv;

	if (priv) {
		if (priv->p_interface)
			ptype_cleanup(priv->p_interface);
		if (priv->p_filter)
			ptype_cleanup(priv->p_filter);

		free(priv);

	}

	return POM_OK;
}

static int output_inject_open(void *output_priv) {

	struct output_inject_priv *priv = output_priv;


	struct proto *proto = proto_get("ethernet");
	if (!proto) {
		pomlog(POMLOG_ERR "Protocol ethernet not available !");
		goto err;
	}

	int snaplen = 9999; // Not used anyway

	char errbuf[PCAP_ERRBUF_SIZE] = { 0 };

	priv->p = pcap_open_live(PTYPE_STRING_GETVAL(priv->p_interface), snaplen, 0, 0, errbuf);
	if (!priv->p) {
		pomlog(POMLOG_ERR "Cannot open interface %s with pcap : %s", PTYPE_STRING_GETVAL(priv->p_interface), errbuf);
		goto err;
	}

	priv->listener = proto_packet_listener_register(proto, 0, priv, output_inject_process, priv->filter);
	if (!priv->listener) 
		goto err;

	return POM_OK;

err:

	if (priv->p) {
		pcap_close(priv->p);
		priv->p = NULL;
	}

	return POM_ERR;

}

static int output_inject_close(void *output_priv) {

	struct output_inject_priv *priv = output_priv;

	if (!priv)
		return POM_ERR;

	if (proto_packet_listener_unregister(priv->listener) != POM_OK)
		return POM_ERR;

	priv->listener = NULL;

	if (priv->p) {
		pcap_close(priv->p);
		priv->p = NULL;
	}


	return POM_OK;

}

static int output_inject_process(void *obj, struct packet *p, struct proto_process_stack *s, unsigned int stack_index) {

	struct output_inject_priv *priv = obj;

	struct proto_process_stack *stack = &s[stack_index];

 	size_t len = stack->plen;
	if (len > 1500)
		len = 1500;

	int bytes = pcap_inject(priv->p, stack->pload, len);

	if (bytes == -1) {
		pomlog(POMLOG_ERR "Error while injecting packet : %s", pcap_geterr(priv->p));
		return POM_ERR;
	}

	registry_perf_inc(priv->perf_pkts_out, 1);
	registry_perf_inc(priv->perf_bytes_out, stack->plen);


	return POM_OK;

}

static int output_inject_filter_parse(void *priv, struct registry_param *param, char *value) {

	struct output_inject_priv *p = priv;
	if (p->filter) {
		filter_cleanup(p->filter);
		p->filter = NULL;
	}
	if (!strlen(value))
		return POM_OK;
	p->filter = packet_filter_compile(value);

	if (!p->filter)
		return POM_ERR;

	return POM_OK;
}

static int output_inject_filter_update(void *priv, struct registry_param *param, struct ptype *value) {

	struct output_inject_priv *p = priv;
	if (p->listener)
		proto_packet_listener_set_filter(p->listener, p->filter);
	return POM_OK;

}


