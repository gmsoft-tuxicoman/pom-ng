/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2011-2014 Guy Martin <gmsoft@tuxicoman.be>
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

#include <pom-ng/core.h>
#include <pom-ng/ptype_string.h>
#include <pom-ng/ptype_bool.h>
#include <pom-ng/ptype_uint16.h>


struct mod_reg_info *output_pcap_reg_info() {

	static struct mod_reg_info reg_info;
	memset(&reg_info, 0, sizeof(struct mod_reg_info));
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = output_pcap_mod_register;
	reg_info.unregister_func = output_pcap_mod_unregister;
	reg_info.dependencies = "ptype_string, ptype_bool, ptype_uint16";

	return &reg_info;
}


static int output_pcap_mod_register(struct mod_reg *mod) {

	static struct output_reg_info output_pcap_file = { 0 };
	output_pcap_file.name = "pcap_file";
	output_pcap_file.description = "Save specified packets in a pcap file";
	output_pcap_file.mod = mod;

	output_pcap_file.init = output_pcap_file_init;
	output_pcap_file.open = output_pcap_file_open;
	output_pcap_file.close = output_pcap_file_close;
	output_pcap_file.cleanup = output_pcap_file_cleanup;

	if (output_register(&output_pcap_file) != POM_OK)
		return POM_ERR;


	static struct output_reg_info output_pcap_flow = { 0 };
	output_pcap_flow.name = "pcap_flow";
	output_pcap_flow.description = "Save packets of each flow in separate pcap files";
	output_pcap_flow.mod = mod;

	output_pcap_flow.init = output_pcap_flow_init;
	output_pcap_flow.cleanup = output_pcap_flow_cleanup;
	output_pcap_flow.open = output_pcap_flow_open;
	output_pcap_flow.close = output_pcap_flow_close;


	return output_register(&output_pcap_flow);
}


static int output_pcap_mod_unregister() {

	output_unregister("pcap_file");
	output_unregister("pcap_flow");
	return POM_OK;
}


static int output_pcap_linktype_to_dlt(char *link_type) {


	if (!strcasecmp("ethernet", link_type)) {
		return DLT_EN10MB;
	} else if (!strcasecmp("ipv4", link_type)) {
		return DLT_RAW;
#ifdef DLT_DOCSIS
	} else if (!strcasecmp("docsis", link_type)) {
		return DLT_DOCSIS;
#endif
	} else if (!strcasecmp("80211", link_type)) {
		return DLT_IEEE802_11;
	} else if (!strcasecmp("radiotap", link_type)){
		return DLT_IEEE802_11_RADIO;
#ifdef DLT_MPEG_2_TS
	} else if (!strcasecmp("mpeg_ts", link_type)) {
		return DLT_MPEG_2_TS;
#endif
	} else if (!strcasecmp("ppi", link_type)) {
		return DLT_PPI;
	}


	pomlog(POMLOG_ERR "Protocol %s is not supported", link_type);
	return POM_ERR;
}

static int output_pcap_file_init(struct output *o) {


	struct output_pcap_file_priv *priv = malloc(sizeof(struct output_pcap_file_priv));
	if (!priv) {
		pom_oom(sizeof(struct output_pcap_file_priv));
		return POM_ERR;
	}
	memset(priv, 0, sizeof(struct output_pcap_file_priv));

	int res = pthread_mutex_init(&priv->lock, NULL);
	if (res) {
		pomlog(POMLOG_ERR "Error while initializing mutex : %s", pom_strerror(res));
		free(priv);
		return POM_ERR;
	}

	output_set_priv(o, priv);

	priv->p_filename = ptype_alloc("string");
	priv->p_snaplen = ptype_alloc_unit("uint16", "bytes");
	priv->p_link_type = ptype_alloc("string");
	priv->p_unbuffered = ptype_alloc("bool");
	priv->p_filter = ptype_alloc("string");

	if (!priv->p_filename || !priv->p_snaplen || !priv->p_link_type || !priv->p_unbuffered || !priv->p_filter)
		goto err;

	struct registry_instance *inst = output_get_reg_instance(o);
	priv->perf_pkts_out = registry_instance_add_perf(inst, "pkts_out", registry_perf_type_counter, "Number of packets written", "pkts");
	priv->perf_bytes_out = registry_instance_add_perf(inst, "bytes_out", registry_perf_type_counter, "Number of packet bytes written", "bytes");

	if (!priv->perf_pkts_out || !priv->perf_bytes_out)
		goto err;

	struct registry_param *p = registry_new_param("filename", "out.pcap", priv->p_filename, "Output PCAP file", 0);
	if (registry_instance_add_param(inst, p) != POM_OK)
		goto err;
	
	p = registry_new_param("snaplen", "1550", priv->p_snaplen, "Snaplen", 0);
	if (registry_instance_add_param(inst, p) != POM_OK)
		goto err;

	p = registry_new_param("link_type", "ethernet", priv->p_link_type, "Link type to use for the pcap file", 0);
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
	
	if (!priv)
		return POM_OK;

	pthread_mutex_destroy(&priv->lock);

	if (priv->p_filename)
		ptype_cleanup(priv->p_filename);
	if (priv->p_snaplen)
		ptype_cleanup(priv->p_snaplen);
	if (priv->p_link_type)
		ptype_cleanup(priv->p_link_type);
	if (priv->p_unbuffered)
		ptype_cleanup(priv->p_unbuffered);
	if (priv->p_filter)
		ptype_cleanup(priv->p_filter);
	
	free(priv);


	return POM_OK;
}

static int output_pcap_file_open(void *output_priv) {

	struct output_pcap_file_priv *priv = output_priv;

	uint16_t *snaplen = PTYPE_UINT16_GETVAL(priv->p_snaplen);

	char *link_type_str = PTYPE_STRING_GETVAL(priv->p_link_type);

	int link_type = output_pcap_linktype_to_dlt(link_type_str);

	struct proto *proto = proto_get(link_type_str);
	if (!proto) {
		pomlog(POMLOG_ERR "Protocol %s not yet implemented", link_type_str);
		goto err;
	}

	priv->p = pcap_open_dead(link_type, *snaplen);
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


	priv->listener = proto_packet_listener_register(proto, 0, priv, output_pcap_file_process, priv->filter);
	if (!priv->listener) 
		goto err;

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

	struct pcap_pkthdr phdr = { { 0 } };

	memcpy(&phdr.ts, &p->ts, sizeof(struct timeval));

	struct proto_process_stack *stack = &s[stack_index];

	phdr.len = stack->plen;

	uint16_t *snaplen = PTYPE_UINT16_GETVAL(priv->p_snaplen);

	if (*snaplen > stack->plen)
		phdr.caplen = stack->plen;
	else
		phdr.caplen = *snaplen;

	registry_perf_inc(priv->perf_pkts_out, 1);
	registry_perf_inc(priv->perf_bytes_out, phdr.caplen);
	
	pom_mutex_lock(&priv->lock);
	pcap_dump((u_char*)priv->pdump, &phdr, stack->pload);
	if (PTYPE_BOOL_GETVAL(priv->p_unbuffered))
		pcap_dump_flush(priv->pdump);
	pom_mutex_unlock(&priv->lock);

	return POM_OK;

}

static int output_pcap_filter_parse(void *priv, char *value) {

	struct output_pcap_file_priv *p = priv;
	return filter_packet(value, &p->filter);
}

static int output_pcap_filter_update(void *priv, struct ptype *value) {

	struct output_pcap_file_priv *p = priv;
	if (p->listener)
		proto_packet_listener_set_filter(p->listener, p->filter);
	return POM_OK;

}

static int output_pcap_flow_init(struct output *o) {


	struct output_pcap_flow_priv *priv = malloc(sizeof(struct output_pcap_flow_priv));
	if (!priv) {
		pom_oom(sizeof(struct output_pcap_flow_priv));
		return POM_ERR;
	}
	memset(priv, 0, sizeof(struct output_pcap_flow_priv));
	output_set_priv(o, priv);

	int res = pthread_mutex_init(&priv->lock, NULL);
	if (res) {
		pomlog(POMLOG_ERR "Error while initializing the flow mutex : %s", pom_strerror(errno));
		goto err;
	}

	priv->p_link_type = ptype_alloc("string");
	priv->p_flow_proto = ptype_alloc("string");
	priv->p_snaplen = ptype_alloc_unit("uint16", "bytes");
	priv->p_unbuffered = ptype_alloc("bool");
	priv->p_prefix = ptype_alloc("string");

	if (!priv->p_link_type || !priv->p_flow_proto || !priv->p_snaplen || !priv->p_unbuffered || !priv->p_prefix)
		goto err;

	struct registry_instance *inst = output_get_reg_instance(o);
	priv->perf_pkts_out = registry_instance_add_perf(inst, "pkts_out", registry_perf_type_counter, "Number of packets written", "pkts");
	priv->perf_bytes_out = registry_instance_add_perf(inst, "bytes_out", registry_perf_type_counter, "Number of packet bytes written", "bytes");
	priv->perf_flows_cur = registry_instance_add_perf(inst, "flows_cur", registry_perf_type_gauge, "Number of flows being processed", "flows");
	priv->perf_flows_tot = registry_instance_add_perf(inst, "flows_tot", registry_perf_type_counter, "Total number of flows processed", "flows");

	if (!priv->perf_pkts_out || !priv->perf_bytes_out || !priv->perf_flows_cur || !priv->perf_flows_tot)
		goto err;


	struct registry_param *p = registry_new_param("flow_proto", "tcp", priv->p_flow_proto, "Protocol to use for flows", 0);
	if (registry_instance_add_param(inst, p) != POM_OK)
		goto err;
	
	p = registry_new_param("snaplen", "1550", priv->p_snaplen, "Snaplen", 0);
	if (registry_instance_add_param(inst, p) != POM_OK)
		goto err;

	p = registry_new_param("link_type", "ethernet", priv->p_link_type, "Link type to use for the pcap files", 0);
	if (registry_instance_add_param(inst, p) != POM_OK)
		goto err;

	p = registry_new_param("unbuffered", "no", priv->p_unbuffered, "Write packets directly without using a buffer (slower)", 0);
	if (registry_instance_add_param(inst, p) != POM_OK)
		goto err;

	p = registry_new_param("prefix", "/tmp/${ipv4.src}.${tcp.sport}-${ipv4.dst}.${tcp.dport}-", priv->p_prefix, "File name prefix", 0);
	if (registry_instance_add_param(inst, p) != POM_OK)
		goto err;

	return POM_OK;
err:

	output_pcap_flow_cleanup(priv);
	return POM_ERR;
}

static int output_pcap_flow_cleanup(void *output_priv) {

	struct output_pcap_flow_priv *priv = output_priv;

	if (!priv)
		return POM_OK;

	if (priv->p_link_type)
		ptype_cleanup(priv->p_link_type);

	if (priv->p_flow_proto)
		ptype_cleanup(priv->p_flow_proto);

	if (priv->p_snaplen)
		ptype_cleanup(priv->p_snaplen);

	if (priv->p_unbuffered)
		ptype_cleanup(priv->p_unbuffered);
	
	if (priv->p_prefix)
		ptype_cleanup(priv->p_prefix);

	free(priv);

	return POM_OK;
}

static int output_pcap_flow_process(void *obj, struct packet *p, struct proto_process_stack *s, unsigned int stack_index) {

	struct output_pcap_flow_priv *priv = obj;

	int i;
	for (i = CORE_PROTO_STACK_START; i < CORE_PROTO_STACK_MAX && s[i].proto && s[i].proto != priv->proto; i++);
	
	if (!s[i].proto) // No protocol for our flow has been found
		return POM_OK;


	struct conntrack_entry *ce = s[i].ce;

	if (!ce) // No conntrack for this packet
		return POM_OK;

	uint16_t *snaplen = PTYPE_UINT16_GETVAL(priv->p_snaplen);

	conntrack_lock(ce);

	struct output_pcap_flow_ce_priv *cpriv = conntrack_get_priv(ce, priv);
	if (!cpriv) {
		cpriv = malloc(sizeof(struct output_pcap_flow_ce_priv));
		if (!cpriv) {
			pom_oom(sizeof(struct output_pcap_flow_ce_priv));
			goto err;
		}
		memset(cpriv, 0, sizeof(struct output_pcap_flow_ce_priv));

		cpriv->ce = ce;

		int res = pthread_mutex_init(&cpriv->lock, NULL);
		if (res) {
			pomlog(POMLOG_ERR "Error while initializing mutex : %s", strerror(res));
			goto err;
		}

		char filename[FILENAME_MAX + 1] = { 0 };

		if (output_pcap_flow_parse_filename(s, p, PTYPE_STRING_GETVAL(priv->p_prefix), filename, FILENAME_MAX) != POM_OK)
			goto err;

		char postfix[32] = { 0 };
		snprintf(postfix, sizeof(postfix) - 1, "%"PRIu64".cap", p->ts);
		strncat(filename, postfix, FILENAME_MAX - strlen(filename));

		cpriv->filename = strdup(filename);
		if (!cpriv->filename) {
			pom_oom(strlen(filename) + 1);
			goto err;
		}

		cpriv->p = pcap_open_dead(priv->link_type, *snaplen);
		if (!cpriv->p) {
			pomlog(POMLOG_ERR "Unable to open pcap");
			goto err;
		}

		cpriv->pdump = pcap_dump_open(cpriv->p, cpriv->filename);
		if (!cpriv->pdump) {
			pomlog(POMLOG_ERR "Error while opening file %s", cpriv->filename);
			goto err;
		}

		if (conntrack_add_priv(ce, priv, cpriv, output_pcap_flow_ce_cleanup) != POM_OK)
			goto err;

		pom_mutex_lock(&priv->lock);
		cpriv->next = priv->flows;
		if (cpriv->next)
			cpriv->next->prev = cpriv;
		priv->flows = cpriv;
		pom_mutex_unlock(&priv->lock);
		
	}

	conntrack_unlock(ce);

	struct pcap_pkthdr phdr = { { 0 } };

	memcpy(&phdr.ts, &p->ts, sizeof(struct timeval));

	struct proto_process_stack *stack = &s[stack_index];

	phdr.len = stack->plen;

	if (*snaplen > stack->plen)
		phdr.caplen = stack->plen;
	else
		phdr.caplen = *snaplen;

	registry_perf_inc(priv->perf_pkts_out, 1);
	registry_perf_inc(priv->perf_bytes_out, phdr.caplen);

	// pcap is not multithread
	pom_mutex_lock(&cpriv->lock);

	pcap_dump((u_char*)cpriv->pdump, &phdr, stack->pload);
	if (PTYPE_BOOL_GETVAL(priv->p_unbuffered))
		pcap_dump_flush(cpriv->pdump);

	pom_mutex_unlock(&cpriv->lock);

	return POM_OK;

err:
	conntrack_unlock(ce);
	output_pcap_flow_ce_cleanup(NULL, cpriv);
	return POM_ERR;

}

static int output_pcap_flow_ce_cleanup(void *obj, void *priv) {

	struct output_pcap_flow_priv *opriv = obj;

	struct output_pcap_flow_ce_priv *cpriv = priv;

	if (!priv)
		return POM_OK;

	pthread_mutex_destroy(&cpriv->lock);

	if (opriv) {
		pom_mutex_lock(&opriv->lock);

		if (cpriv->next)
			cpriv->next->prev = cpriv->prev;

		if (cpriv->prev)
			cpriv->prev->next = cpriv->next;
		else
			opriv->flows = cpriv->next;

		pom_mutex_unlock(&opriv->lock);
	}

	if (cpriv->pdump)
		pcap_dump_close(cpriv->pdump);
	if (cpriv->p)
		pcap_close(cpriv->p);

	if (cpriv->filename)
		free(cpriv->filename);

	free(cpriv);

	return POM_OK;

}

static int output_pcap_flow_open(void *output_priv) {

	struct output_pcap_flow_priv *priv = output_priv;

	priv->proto = proto_get(PTYPE_STRING_GETVAL(priv->p_flow_proto));

	priv->link_type = output_pcap_linktype_to_dlt(PTYPE_STRING_GETVAL(priv->p_link_type));

	struct proto *proto = proto_get(PTYPE_STRING_GETVAL(priv->p_link_type));
	if (!proto) {
		pomlog(POMLOG_ERR "Protocol %s not yet implemented", PTYPE_STRING_GETVAL(priv->p_link_type));
		return POM_ERR;
	}


	priv->listener = proto_packet_listener_register(proto, 0, priv, output_pcap_flow_process, NULL);
	if (!priv->listener)
		return POM_ERR;

	return POM_OK;

}


static int output_pcap_flow_close(void *output_priv) {

	struct output_pcap_flow_priv *priv = output_priv;

	if (proto_packet_listener_unregister(priv->listener) != POM_OK)
		return POM_ERR;

	priv->listener = NULL;

	while (priv->flows) {
		conntrack_lock(priv->flows->ce);
		conntrack_remove_priv(priv->flows->ce, priv);
		conntrack_unlock(priv->flows->ce);
		output_pcap_flow_ce_cleanup(priv, priv->flows);
	}

	return POM_OK;

}


static int output_pcap_flow_parse_filename(struct proto_process_stack *s, struct packet *p, char *format, char *filename, size_t filename_len) {

	char *sep = NULL, *cur = format;
	while ((sep = strchr(cur, '$')) && filename_len > 0) {
		if (*(sep + 1) != '{') {
			strcat(filename, "$");
			filename_len--;
			cur++;
			continue;
		}


		char *start = sep + 2;
		// Find the dot
		char *dot = strchr(start, '.');

		if (!dot) {
			pomlog(POMLOG_ERR "Dot not found in filename inside ${}.");
			return POM_ERR;
		}

		char *end = strchr(dot, '}');
		if (!end) {
			pomlog(POMLOG_ERR "'}' not found in file name");
			return POM_ERR;
		}

		// We have everything we need now
		// Find the right proto
		
		int found = 0;
		size_t proto_len = dot - start;
	
		struct proto_reg_info *proto_info = NULL;
		int i, j;
		for (i = CORE_PROTO_STACK_START; i < CORE_PROTO_STACK_MAX && s[i].proto; i++) {
			struct proto_reg_info *info = proto_get_info(s[i].proto);
			if (!memcmp(info->name, start, proto_len)) {
				proto_info = info;
				break;
			}
		}

		if (proto_info) {
			// Find the right field
			size_t field_len = end - dot - 1;
			for (j = 0; proto_info->pkt_fields[j].name; j++) {
				if (!memcmp(proto_info->pkt_fields[j].name, dot + 1, field_len)) {
					found = 1;
					break;
				}
			}
		}

		// Append whatever is between cur and sep
		size_t len = sep - cur;
		if (len > filename_len)
			len = filename_len;
		strncat(filename, cur, len);
		filename_len -= len;

		if (found) {
			int size = ptype_print_val(s[i].pkt_info->fields_value[j], filename + strlen(filename), filename_len, NULL);
			if (size < 0)
				return POM_ERR;
			filename_len -= size;

		} else {
			len = end - start;
			if (len > filename_len)
				len = filename_len;
			strncat(filename, start, len);
			filename_len -= len;
		}

		cur = end + 1;
	}

	// Copy whatever is left after the last field
	size_t len = format + strlen(format) - cur;
	if (len > filename_len)
		len = filename_len;
	strncat(filename, cur, len);

	return POM_OK;
}
