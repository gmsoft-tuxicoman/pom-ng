/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2011-2012 Guy Martin <gmsoft@tuxicoman.be>
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

#ifndef __OUTPUT_PCAP_H__
#define __OUTPUT_PCAP_H__


#include <pom-ng/output.h>
#include <pom-ng/filter.h>

#include <pcap.h>


struct output_pcap_file_priv {

	pcap_dumper_t *pdump;
	pcap_t *p;
	struct proto *proto;
	struct filter_proto *filter;

	struct proto_packet_listener *listener;

	struct ptype *p_filename;
	struct ptype *p_snaplen;
	struct ptype *p_proto;
	struct ptype *p_unbuffered;
	struct ptype *p_filter;

};

struct mod_reg_info *output_pcap_reg_info();
static int output_pcap_mod_register(struct mod_reg *mod);
static int output_pcap_mod_unregister();

static int output_pcap_file_init(struct output *o);
static int output_pcap_file_cleanup(struct output *o);
static int output_pcap_file_open(struct output *o);
static int output_pcap_file_close(struct output *o);
static int output_pcap_file_process(void *obj, struct packet *p, struct proto_process_stack *s, unsigned int stack_index);
static int output_pcap_filter_change(void *priv, char *value);

#endif
