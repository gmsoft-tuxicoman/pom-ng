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

#ifndef __INPUT_PCAP_H__
#define __INPUT_PCAP_H__

#include <pcap.h>

#define INPUT_PCAP_SNAPLEN_MAX 65535

enum input_pcap_type {
	input_pcap_type_interface,
	input_pcap_type_file

};

struct input_pcap_interface_priv {
	struct ptype *interface;
	struct ptype *promisc;
};

struct input_pcap_file_priv {
	struct ptype *file;
};

struct input_pcap_priv {

	uint64_t last_pkt_id;
	pcap_t *p;
	enum input_pcap_type type;
	union {
		struct input_pcap_interface_priv iface;
		struct input_pcap_file_priv file;
	} tpriv;

	struct proto_dependency *datalink;
	unsigned int align_offset;

};

static int input_pcap_mod_register(struct mod_reg *mod);
static int input_pcap_mod_unregister();

static int input_pcap_common_open(struct input *i);

static int input_pcap_interface_init(struct input *i);
static int input_pcap_interface_open(struct input *i);

static int input_pcap_file_init(struct input *i);
static int input_pcap_file_open(struct input *i);

static int input_pcap_read(struct input *i);
static int input_pcap_close(struct input *i);
static int input_pcap_cleanup(struct input *i);


#endif
