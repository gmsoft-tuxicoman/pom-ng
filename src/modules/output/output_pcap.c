/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2011-2013 Guy Martin <gmsoft@tuxicoman.be>
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



#include "output_pcap.h"

#include <pom-ng/ptype_string.h>
#include <pom-ng/ptype_bool.h>
#include <pom-ng/ptype_uint16.h>


struct mod_reg_info *output_pcap_reg_info() {

	static struct mod_reg_info reg_info;
	memset(&reg_info, 0, sizeof(struct mod_reg_info));
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = output_pcap_mod_register;
	reg_info.unregister_func = output_pcap_mod_unregister;
	reg_info.dependencies = "proto_docsis, proto_ethernet, proto_ipv4, ptype_string, ptype_bool, ptype_uint16";

	return &reg_info;
}


static int output_pcap_mod_register(struct mod_reg *mod) {

	static struct output_reg_info output_pcap_file;
	memset(&output_pcap_file, 0, sizeof(struct output_reg_info));
	output_pcap_file.name = "pcap_file";
	output_pcap_file.api_ver = OUTPUT_API_VER;
	output_pcap_file.mod = mod;

	output_pcap_file.init = output_pcap_file_init;
	output_pcap_file.open = output_pcap_file_open;
	output_pcap_file.close = output_pcap_file_close;
	output_pcap_file.cleanup = output_pcap_file_cleanup;

	return output_register(&output_pcap_file);

}


static int output_pcap_mod_unregister() {

	return output_unregister("pcap_file");
}


static int output_pcap_file_init(struct output *o) {


	struct output_pcap_file_priv *priv = malloc(sizeof(struct output_pcap_file_priv));
	if (!priv) {
		pom_oom(sizeof(struct output_pcap_file_priv));
		return POM_ERR;
	}
	memset(priv, 0, sizeof(struct output_pcap_file_priv));
	output_set_priv(o, priv);

	priv->p_filename = ptype_alloc("string");
	priv->p_snaplen = ptype_alloc_unit("uint16", "bytes");
	priv->p_proto = ptype_alloc("string");
	priv->p_unbuffered = ptype_alloc("bool");
	priv->p_filter = ptype_alloc("string");

	if (!priv->p_filename || !priv->p_snaplen || !priv->p_proto || !priv->p_unbuffered || !priv->p_filter)
		goto err;

	struct registry_instance *inst = output_get_reg_instance(o);
	priv->perf_pkts_out = registry_instance_add_perf(inst, "pkts_out", registry_perf_type_counter, "Number of packets written", "pkts");
	priv->perf_bytes_out = registry_instance_add_perf(inst, "bytes_out", registry_perf_type_counter, "Number of packet bytes written", "bytes");

	struct registry_param *p = registry_new_param("filename", "out.pcap", priv->p_filename, "Output PCAP file", 0);
	if (registry_instance_add_param(inst, p) != POM_OK)
		goto err;
	
	p = registry_new_param("snaplen", "1550", priv->p_snaplen, "Snaplen", 0);
	if (registry_instance_add_param(inst, p) != POM_OK)
		goto err;

	p = registry_new_param("protocol", "ethernet", priv->p_proto, "Protocol to capture", 0);
	if (registry_instance_add_param(inst, p) != POM_OK)
		goto err;

	p = registry_new_param("unbuffered", "no", priv->p_unbuffered, "Write packets directly without using a buffer (slower)", 0);
	if (registry_instance_add_param(inst, p) != POM_OK)
		goto err;

	p = registry_new_param("filter", "", priv->p_filter, "Filter", 0);
	if (registry_instance_add_param(inst, p) != POM_OK)
		goto err;

	registry_param_set_callbacks(p, priv, output_pcap_filter_parse, output_pcap_filter_update);

	return POM_OK;

err:
	output_pcap_file_cleanup(priv);
	return POM_ERR;

}

static int output_pcap_file_cleanup(void *output_priv) {

	struct output_pcap_file_priv *priv = output_priv;
	
	if (priv) {
		if (priv->p_filename)
			ptype_cleanup(priv->p_filename);
		if (priv->p_snaplen)
			ptype_cleanup(priv->p_snaplen);
		if (priv->p_proto)
			ptype_cleanup(priv->p_proto);
		if (priv->p_unbuffered)
			ptype_cleanup(priv->p_unbuffered);
		if (priv->p_filter)
			ptype_cleanup(priv->p_filter);
		
		free(priv);

	}

	return POM_OK;
}

static int output_pcap_file_open(void *output_priv) {

	struct output_pcap_file_priv *priv = output_priv;

	uint16_t *snaplen = PTYPE_UINT16_GETVAL(priv->p_snaplen);

	int linktype;
	char *proto = PTYPE_STRING_GETVAL(priv->p_proto);

	if (!strcasecmp("ethernet", proto)) {
		linktype = DLT_EN10MB;
/*	} else if (!strcasecmp("linux_cooked", proto)) {
		linktype = DLT_LINUX_SLL;
*/	} else if (!strcasecmp("ipv4", proto)) {
		linktype = DLT_RAW;
#ifdef DLT_DOCSIS
	} else if (!strcasecmp("docsis", proto)) {
		linktype = DLT_DOCSIS;
#endif
	} else if (!strcasecmp("80211", proto)) {
		linktype = DLT_IEEE802_11;
	} else if (!strcasecmp("radiotap", proto)){
		linktype = DLT_IEEE802_11_RADIO;
#ifdef DLT_MPEGTS
	} else if (!strcasecmp("mpeg_ts", proto)) {
		linktype = DLT_MPEGTS;
#endif
	} else if (!strcasecmp("ppi", proto)) {
		linktype = DLT_PPI;
	} else {
		pomlog(POMLOG_ERR "Protocol %s is not supported", proto);
		return POM_ERR;
	}

	priv->proto = proto_get(proto);
	if (!priv->proto) {
		pomlog(POMLOG_ERR "Protocol %s not yet implemented", proto);
		goto err;
	}

	priv->p = pcap_open_dead(linktype, *snaplen);
	if (!priv->p) {
		pomlog(POMLOG_ERR "Unable to open pcap");
		goto err;
	}

	char *filename = PTYPE_STRING_GETVAL(priv->p_filename);
	priv->pdump = pcap_dump_open(priv->p, filename);
	if (!priv->pdump) {
		pomlog(POMLOG_ERR "Unable to open pcap file %s for writing !", filename);
		goto err;
	}


	priv->listener = proto_packet_listener_register(priv->proto, 0, priv, output_pcap_file_process);
	if (!priv->listener) 
		goto err;

	proto_packet_listener_set_filter(priv->listener, priv->filter);

	return POM_OK;

err:

	if (priv->pdump) {
		pcap_dump_close(priv->pdump);
		priv->pdump = NULL;
	}

	if (priv->p) {
		pcap_close(priv->p);
		priv->p = NULL;
	}

	return POM_ERR;

}

static int output_pcap_file_close(void *output_priv) {

	struct output_pcap_file_priv *priv = output_priv;

	if (!priv)
		return POM_ERR;

	if (proto_packet_listener_unregister(priv->listener) != POM_OK)
		return POM_ERR;

	priv->listener = NULL;

	if (priv->pdump) {
		pcap_dump_close(priv->pdump);
		priv->pdump = NULL;
	}

	if (priv->p) {
		pcap_close(priv->p);
		priv->p = NULL;
	}


	return POM_OK;

}

static int output_pcap_file_process(void *obj, struct packet *p, struct proto_process_stack *s, unsigned int stack_index) {

	struct output_pcap_file_priv *priv = obj;

	struct pcap_pkthdr phdr;
	memset(&phdr, 0, sizeof(struct pcap_pkthdr));

	memcpy(&phdr.ts, &p->ts, sizeof(struct timeval));

	struct proto_process_stack *stack = &s[stack_index];

	phdr.len = stack->plen;

	uint16_t *snaplen = PTYPE_UINT16_GETVAL(priv->p_snaplen);

	if (*snaplen > stack->plen)
		phdr.caplen = stack->plen;
	else
		phdr.caplen = *snaplen;

	pcap_dump((u_char*)priv->pdump, &phdr, stack->pload);
	registry_perf_inc(priv->perf_pkts_out, 1);
	registry_perf_inc(priv->perf_bytes_out, phdr.caplen);

	if (PTYPE_BOOL_GETVAL(priv->p_unbuffered))
		pcap_dump_flush(priv->pdump);

	return POM_OK;

}

static int output_pcap_filter_parse(void *priv, char *value) {

	struct output_pcap_file_priv *p = priv;
	return filter_proto_parse(value, strlen(value), &p->filter);
}

static int output_pcap_filter_update(void *priv, struct ptype *value) {

	struct output_pcap_file_priv *p = priv;
	if (p->listener)
		proto_packet_listener_set_filter(p->listener, p->filter);
	return POM_OK;

}


