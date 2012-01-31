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

#include <pom-ng/input.h>
#include <pom-ng/ptype_string.h>
#include <pom-ng/ptype_bool.h>

#include <pom-ng/registry.h>

#include <pom-ng/packet.h>
#include <pom-ng/core.h>

#include "input_pcap.h"
#include <string.h>

// FIXME change this define when this value gets upstream
#define DLT_MPEGTS DLT_USER0

struct mod_reg_info* input_pcap_reg_info() {
	static struct mod_reg_info reg_info;
	memset(&reg_info, 0, sizeof(struct mod_reg_info));
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = input_pcap_mod_register;
	reg_info.unregister_func = input_pcap_mod_unregister;
	reg_info.dependencies = "ptype_string, ptype_bool";

	return &reg_info;
}


static int input_pcap_mod_register(struct mod_reg *mod) {

	int res = POM_OK;

	static struct input_reg_info in_pcap_interface;
	memset(&in_pcap_interface, 0, sizeof(struct input_reg_info));
	in_pcap_interface.name = "pcap_interface";
	in_pcap_interface.api_ver = INPUT_API_VER;
	in_pcap_interface.flags = INPUT_REG_FLAG_LIVE;
	in_pcap_interface.mod = mod;
	in_pcap_interface.init = input_pcap_interface_init;
	in_pcap_interface.open = input_pcap_interface_open;
	in_pcap_interface.read = input_pcap_read;
	in_pcap_interface.close = input_pcap_close;
	in_pcap_interface.cleanup = input_pcap_cleanup;
	res += input_register(&in_pcap_interface);


	static struct input_reg_info in_pcap_file;
	memset(&in_pcap_file, 0, sizeof(struct input_reg_info));
	in_pcap_file.name = "pcap_file";
	in_pcap_file.api_ver = INPUT_API_VER;
	in_pcap_file.mod = mod;
	in_pcap_file.init = input_pcap_file_init;
	in_pcap_file.open = input_pcap_file_open;
	in_pcap_file.read = input_pcap_read;
	in_pcap_file.close = input_pcap_close;
	in_pcap_file.cleanup = input_pcap_cleanup;
	res += input_register(&in_pcap_file);

	return res;

}

static int input_pcap_mod_unregister() {

	int res = POM_OK;
	res += input_unregister("pcap_file");
	res += input_unregister("pcap_interface");
	return res;
}

static int input_pcap_common_open(struct input *i) {

	struct input_pcap_priv *priv = i->priv;

	if (!priv || !priv->p)
		return POM_ERR;

	char *datalink = "undefined";

	priv->datalink_dlt = pcap_datalink(priv->p);
	switch (priv->datalink_dlt) {
		case DLT_EN10MB:
			datalink = "ethernet";
			// Ethernet is 14 bytes long
			priv->align_offset = 2;
			break;

		case DLT_DOCSIS:
			datalink = "docsis";
			break;

		case DLT_LINUX_SLL:
			datalink = "linux_cooked";
			break;

		case DLT_RAW:
			datalink = "ipv4";
			break;

		case DLT_MPEGTS: // FIXME update this when upstream add it
			datalink = "mpeg_ts";
			break;
	}

	priv->datalink_proto = proto_add_dependency(datalink);

	if (!priv->datalink_proto || !priv->datalink_proto->proto) {
		pomlog(POMLOG_ERR "Cannot open input pcap : protocol %s not registered", datalink);
		input_pcap_close(i);
		return POM_ERR;
	}

	return POM_OK;

}

/*
 * input pcap type interface
 */

static int input_pcap_interface_init(struct input *i) {

	struct input_pcap_priv *priv;
	priv = malloc(sizeof(struct input_pcap_priv));
	if (!priv) {
		pom_oom(sizeof(struct input_pcap_priv));
		return POM_ERR;
	}
	memset(priv, 0, sizeof(struct input_pcap_priv));
	
	struct registry_param *p = NULL;

	priv->tpriv.iface.interface = ptype_alloc("string");
	priv->tpriv.iface.promisc = ptype_alloc("bool");
	if (!priv->tpriv.iface.interface || !priv->tpriv.iface.promisc)
		goto err;

	char err[PCAP_ERRBUF_SIZE];
	char *dev = pcap_lookupdev(err);
	if (!dev)
		dev = "none";

	p = registry_new_param("interface", dev, priv->tpriv.iface.interface, "Interface to capture packets from", 0);
	if (registry_instance_add_param(i->reg_instance, p) != POM_OK)
		goto err;

	p = registry_new_param("promisc", "no", priv->tpriv.iface.promisc, "Promiscious mode", 0);
	if (registry_instance_add_param(i->reg_instance, p) != POM_OK)
		goto err;

	priv->type = input_pcap_type_interface;

	i->priv = priv;

	return POM_OK;

err:

	if (priv->tpriv.iface.interface)
		ptype_cleanup(priv->tpriv.iface.interface);

	if (priv->tpriv.iface.promisc)
		ptype_cleanup(priv->tpriv.iface.promisc);

	if (p)
		registry_cleanup_param(p);

	free(priv);

	return POM_ERR;

}

static int input_pcap_interface_open(struct input *i) {

	struct input_pcap_priv *p = i->priv;
	char errbuf[PCAP_ERRBUF_SIZE + 1];
	memset(errbuf, 0, PCAP_ERRBUF_SIZE + 1);

	char *interface = PTYPE_STRING_GETVAL(p->tpriv.iface.interface);
	char *promisc = PTYPE_BOOL_GETVAL(p->tpriv.iface.promisc);

	p->p = pcap_open_live(interface, INPUT_PCAP_SNAPLEN_MAX, *promisc, 0,errbuf);
	if (!p->p) {
		pomlog(POMLOG_ERR "Error opening interface %s : %s", interface, errbuf);
		return POM_ERR;
	}

	return input_pcap_common_open(i);

}

/*
 * input pcap type file
 */

static int input_pcap_file_init(struct input *i) {

	struct input_pcap_priv *priv;
	priv = malloc(sizeof(struct input_pcap_priv));
	if (!priv) {
		pom_oom(sizeof(struct input_pcap_priv));
		return POM_ERR;
	}
	memset(priv, 0, sizeof(struct input_pcap_priv));

	struct registry_param *p = NULL;

	priv->tpriv.file.file = ptype_alloc("string");
	if (!priv->tpriv.file.file)
		goto err;

	p = registry_new_param("filename", "dump.cap", priv->tpriv.file.file, "File in PCAP format", 0);
	if (registry_instance_add_param(i->reg_instance, p) != POM_OK)
		goto err;

	priv->type = input_pcap_type_file;

	i->priv = priv;

	return POM_OK;

err:

	if (priv->tpriv.file.file)
		ptype_cleanup(priv->tpriv.file.file);

	if (p)
		registry_cleanup_param(p);

	free(priv);

	return POM_ERR;
}

static int input_pcap_file_open(struct input *i) {

	struct input_pcap_priv *p = i->priv;
	char errbuf[PCAP_ERRBUF_SIZE + 1];
	memset(errbuf, 0, PCAP_ERRBUF_SIZE + 1);

	char *filename = PTYPE_STRING_GETVAL(p->tpriv.file.file);
	p->p = pcap_open_offline(filename, errbuf);
	if (!p->p) {
		pomlog(POMLOG_ERR "Error opening file %s for reading : %s", filename, errbuf);
		return POM_ERR;
	}

	return input_pcap_common_open(i);

}


/*
 * common input pcap functions
 */

static int input_pcap_read(struct input *i) {

	struct input_pcap_priv *p = i->priv;

	struct pcap_pkthdr *phdr;
	
	u_char *data;
	int result = pcap_next_ex(p->p, &phdr, (const u_char**) &data);
	if (phdr->len > phdr->caplen) 
		pomlog(POMLOG_WARN "Warning, some packets were truncated at capture time");

	if (result == -2) // EOF
		return POM_ERR;

	if (result == 0) // Timeout
		return POM_OK;

	if (result != 1)
		return POM_ERR;
	
	struct packet *pkt = packet_pool_get();
	if (!pkt)
		return POM_ERR;

	if (packet_buffer_pool_get(pkt, phdr->caplen, p->align_offset)) {
		packet_pool_release(pkt);
		return POM_ERR;
	}

	pkt->input = i;
	pkt->datalink = p->datalink_proto->proto;
	memcpy(&pkt->ts, &phdr->ts, sizeof(struct timeval));
	memcpy(pkt->buff, data, phdr->caplen);

	unsigned int flags = 0, affinity = 0;

	if (p->datalink_dlt == DLT_MPEGTS) {
		// MPEG2 TS has thread affinity based on the PID
		flags |= CORE_QUEUE_HAS_THREAD_AFFINITY;
		affinity = ((((char*)pkt->buff)[1] & 0x1F) << 8) | ((char *)pkt->buff)[2];
	}

	return core_queue_packet(pkt, flags, affinity);
}

static int input_pcap_close(struct input *i) {

	struct input_pcap_priv *priv = i->priv;

	if (!priv->p)
		return POM_OK;
	pcap_close(priv->p);
	priv->p = NULL;
	proto_remove_dependency(priv->datalink_proto);
	priv->datalink_proto = NULL;
	priv->align_offset = 0;

	return POM_OK;
}

static int input_pcap_cleanup(struct input *i) {

	struct input_pcap_priv *priv;
	priv = i->priv;
	if (priv->p)
		pcap_close(priv->p);
	switch (priv->type) {
		case input_pcap_type_interface:
			ptype_cleanup(priv->tpriv.iface.interface);
			ptype_cleanup(priv->tpriv.iface.promisc);
			break;
		case input_pcap_type_file:
			ptype_cleanup(priv->tpriv.file.file);
			break;
	}
	free(priv);

	return POM_OK;

}

