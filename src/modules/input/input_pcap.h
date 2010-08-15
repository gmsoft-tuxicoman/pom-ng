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

#ifndef __INPUT_PCAP_H__
#define __INPUT_PCAP_H__

#include <pcap.h>

#define INPUT_PCAP_SNAPLEN_MAX 65535

struct input_pcap_interface_priv {
	struct ptype *interface;
	struct ptype *promisc;
	pcap_t *p;
};

struct input_pcap_file_priv {
	struct ptype *file;
	pcap_t *p;
};

static int input_pcap_mod_register(struct mod_reg *mod);
static int input_pcap_mod_unregister();


static int input_pcap_interface_alloc(struct input *i);
static int input_pcap_interface_open(struct input *i);
static int input_pcap_interface_read(struct input *i);
static int input_pcap_interface_get_caps(struct input *i, struct input_caps *ic);
static int input_pcap_interface_close(struct input *i);
static int input_pcap_interface_cleanup(struct input *i);

static int input_pcap_file_alloc(struct input *i);
static int input_pcap_file_open(struct input *i);
static int input_pcap_file_read(struct input *i);
static int input_pcap_file_get_caps(struct input *i, struct input_caps *ic);
static int input_pcap_file_close(struct input *i);
static int input_pcap_file_cleanup(struct input *i);


#endif
