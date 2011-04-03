/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2010 Guy Martin <gmsoft@tuxicoman.be>
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

#include "input_pcap.h"
#include <string.h>

struct mod_reg_info* input_pcap_reg_info() {
	static struct mod_reg_info reg_info;
	memset(&reg_info, 0, sizeof(struct mod_reg_info));
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = input_pcap_mod_register;
	reg_info.unregister_func = input_pcap_mod_unregister;

	return &reg_info;
}


static int input_pcap_mod_register(struct mod_reg *mod) {

	static struct input_reg_info in_pcap_interface;
	memset(&in_pcap_interface, 0, sizeof(struct input_reg_info));
	in_pcap_interface.name = "pcap_interface";
	in_pcap_interface.api_ver = INPUT_API_VER;
	in_pcap_interface.alloc = input_pcap_interface_alloc;
	in_pcap_interface.open = input_pcap_interface_open;
	in_pcap_interface.read = input_pcap_read;
	in_pcap_interface.get_caps = input_pcap_get_caps;
	in_pcap_interface.close = input_pcap_close;
	in_pcap_interface.cleanup = input_pcap_cleanup;
	input_register(&in_pcap_interface, mod);


	static struct input_reg_info in_pcap_file;
	memset(&in_pcap_file, 0, sizeof(struct input_reg_info));
	in_pcap_file.name = "pcap_file";
	in_pcap_file.api_ver = INPUT_API_VER;
	in_pcap_file.alloc = input_pcap_file_alloc;
	in_pcap_file.open = input_pcap_file_open;
	in_pcap_file.read = input_pcap_read;
	in_pcap_file.get_caps = input_pcap_get_caps;
	in_pcap_file.close = input_pcap_close;
	in_pcap_file.cleanup = input_pcap_cleanup;
	input_register(&in_pcap_file, mod);

	return POM_OK;

}

static int input_pcap_mod_unregister() {

	int res = POM_OK;
	res += input_unregister("pcap_file");
	res += input_unregister("pcap_interface");
	return res;
}


/*
 * input pcap type interface
 */

static int input_pcap_interface_alloc(struct input *i) {

	struct input_pcap_priv *priv;
	priv = malloc(sizeof(struct input_pcap_priv));
	if (!priv) {
		pom_oom(sizeof(struct input_pcap_priv));
		return POM_ERR;
	}
	memset(priv, 0, sizeof(struct input_pcap_priv));
	
	priv->tpriv.iface.interface = ptype_alloc("string");
	priv->tpriv.iface.promisc = ptype_alloc("bool");
	if (!priv->tpriv.iface.interface || !priv->tpriv.iface.promisc)
		return POM_ERR;

	char err[PCAP_ERRBUF_SIZE];
	char *dev = pcap_lookupdev(err);
	if (!dev)
		dev = "none";

	input_register_param(i, "interface", priv->tpriv.iface.interface, dev, "Interface to capture packets from", 0);
	input_register_param(i, "promisc", priv->tpriv.iface.promisc, "no", "Promiscious mode", 0);

	priv->type = input_pcap_type_interface;

	i->priv = priv;

	return POM_OK;

}

static int input_pcap_interface_open(struct input *i) {

	struct input_pcap_priv *p = i->priv;
	char errbuf[PCAP_ERRBUF_SIZE + 1];
	memset(errbuf, 0, PCAP_ERRBUF_SIZE + 1);

	char *interface; PTYPE_STRING_GETVAL(p->tpriv.iface.interface, interface);
	char *promisc; PTYPE_BOOL_GETVAL(p->tpriv.iface.promisc, promisc);

	p->p = pcap_open_live(interface, INPUT_PCAP_SNAPLEN_MAX, *promisc, 0,errbuf);
	if (!p->p) {
		pomlog(POMLOG_ERR "Error opening interface %s : %s", interface, errbuf);
		return POM_ERR;
	}

	return POM_OK;

}

/*
 * input pcap type file
 */

static int input_pcap_file_alloc(struct input *i) {

	struct input_pcap_priv *priv;
	priv = malloc(sizeof(struct input_pcap_priv));
	if (!priv) {
		pom_oom(sizeof(struct input_pcap_priv));
		return POM_ERR;
	}
	memset(priv, 0, sizeof(struct input_pcap_priv));
	
	priv->tpriv.file.file = ptype_alloc("string");
	if (!priv->tpriv.file.file)
		return POM_ERR;

	input_register_param(i, "filename", priv->tpriv.file.file, "dump.cap", "File in PCAP format", 0);

	priv->type = input_pcap_type_file;

	i->priv = priv;

	return POM_OK;

}

static int input_pcap_file_open(struct input *i) {

	struct input_pcap_priv *p = i->priv;
	char errbuf[PCAP_ERRBUF_SIZE + 1];
	memset(errbuf, 0, PCAP_ERRBUF_SIZE + 1);

	char *filename; PTYPE_STRING_GETVAL(p->tpriv.file.file, filename);
	p->p = pcap_open_offline(filename, errbuf);
	if (!p->p) {
		pomlog(POMLOG_ERR "Error opening file %s for reading : %s", filename, errbuf);
		return POM_ERR;
	}

	return POM_OK;

}


/*
 * common input pcap functions
 */

static int input_pcap_read(struct input *i) {

	struct input_pcap_priv *p = i->priv;
	unsigned char *data;

	struct pcap_pkthdr *phdr;

	int result = pcap_next_ex(p->p, &phdr, (const u_char**) &data);
	if (phdr->len > phdr->caplen) 
		pomlog(POMLOG_WARN "Warning, some packets were truncated at capture time");

	if (result == -2) // EOF
		return POM_ERR;

	if (result == 0) // Timeout
		return POM_OK;

	if (result != 1)
		return POM_ERR;

	return input_add_processed_packet(i, phdr->caplen, data, &phdr->ts, (p->type == input_pcap_type_interface));
}

static int input_pcap_get_caps(struct input *i, struct input_caps *ic) {

	struct input_pcap_priv *p = i->priv;

	if (!p->p)
		return POM_ERR;

	switch (pcap_datalink(p->p)) {
		case DLT_EN10MB:
			ic->datalink = "ethernet";
			// Ethernet is 14 bytes long
			ic->align_offset = 2;
			break;

		case DLT_DOCSIS:
			ic->datalink = "docsis";
			break;

		case DLT_LINUX_SLL:
			ic->datalink = "linux_cooked";
			break;

		case DLT_RAW:
			ic->datalink = "ipv4";
			break;
	
		default:
			ic->datalink = "undefined";
	}

	if (p->type == input_pcap_type_interface)
		ic->is_live = 1;
	else
		ic->is_live = 0;

	return POM_OK;

}

static int input_pcap_close(struct input *i) {

	struct input_pcap_priv *p = i->priv;

	if (!p->p)
		return POM_OK;
	pcap_close(p->p);
	p->p = NULL;
	
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

