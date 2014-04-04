/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2010-2013 Guy Martin <gmsoft@tuxicoman.be>
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
	input_pcap_type_file,
	input_pcap_type_dir

};

struct input_pcap_interface_priv {
	struct ptype *p_interface;
	struct ptype *p_promisc;
	struct registry_perf *perf_dropped;
};

struct input_pcap_file_priv {
	struct ptype *p_file;
};


struct input_pcap_dir_file {
	char *filename, *full_path;
	ptime first_pkt;
	struct input_pcap_dir_file *prev, *next;
};

struct input_pcap_dir_priv {
	struct ptype *p_dir;
	struct ptype *p_match;
	struct input_pcap_dir_file *files;
	struct input_pcap_dir_file *cur_file;
	unsigned int interrupt_scan;
};

struct input_pcap_priv {

	pcap_t *p;
	enum input_pcap_type type;
	union {
		struct input_pcap_interface_priv iface;
		struct input_pcap_file_priv file;
		struct input_pcap_dir_priv dir;
	} tpriv;

	struct ptype *p_filter;

	struct proto *datalink_proto;
	int datalink_type;
	unsigned int align_offset;
	unsigned int skip_offset;
	int warning;
};

static int input_pcap_mod_register(struct mod_reg *mod);
static int input_pcap_mod_unregister();

static int input_pcap_common_open(struct input *i);

static int input_pcap_interface_perf_dropped(uint64_t *value, void *priv);
static int input_pcap_interface_init(struct input *i);
static int input_pcap_interface_open(struct input *i);

static int input_pcap_file_init(struct input *i);
static int input_pcap_file_open(struct input *i);

static int input_pcap_dir_init(struct input *i);
static int input_pcap_dir_open(struct input *i);
static int input_pcap_dir_browse(struct input_pcap_priv *priv);
static int input_pcap_dir_open_next(struct input_pcap_priv *p);

static int input_pcap_read(struct input *i);
static int input_pcap_close(struct input *i);
static int input_pcap_cleanup(struct input *i);

static int input_pcap_interrupt(struct input *i);

#endif
