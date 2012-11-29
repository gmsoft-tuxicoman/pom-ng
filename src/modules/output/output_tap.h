/*
 *  This tap is part of pom-ng.
 *  Copyright (C) 2012 Guy Martin <gmsoft@tuxicoman.be>
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

#ifndef __OUTPUT_TAP_H__
#define __OUTPUT_TAP_H__

#include <pom-ng/output.h>
#include <pom-ng/addon.h>

struct output_tap_priv {

	struct ptype *p_ifname;
	struct ptype *p_persistent;
	int fd;
	struct proto_packet_listener *listener;
};

struct mod_reg_info* output_tap_reg_info();
int output_tap_mod_register(struct mod_reg *mod);
int output_tap_mod_unregister();

int addon_tap_init(struct addon_plugin *a);
int output_tap_init(struct output *o);
int output_tap_cleanup(void *output_priv);
int output_tap_open(void *output_priv);
int output_tap_close(void *output_priv);

int output_tap_pkt_process(void *obj, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index);




#endif
