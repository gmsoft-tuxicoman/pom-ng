/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2012-2014 Guy Martin <gmsoft@tuxicoman.be>
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

#ifndef __ANALYZER_TFTP_H__
#define __ANALYZER_TFTP_H__

#include <pom-ng/analyzer.h>
#include <pom-ng/pload.h>

#define ANALYZER_TFTP_BLK_SIZE 512

#define ANALYZER_TFTP_EVT_FILE_DATA_COUNT 4

enum {
	analyzer_tftp_file_filename,
	analyzer_tftp_file_mode,
	analyzer_tftp_file_write,
	analyzer_tftp_file_size,
};



struct mod_reg_info *analyzer_tftp_reg_info();

static int analyzer_tftp_mod_register(struct mod_reg *mod);
static int analyzer_tftp_mod_unregister();

static int analyzer_tftp_init(struct analyzer *analyzer);
static int analyzer_tftp_cleanup(struct analyzer *analyzer);

static int analyzer_tftp_event_listeners_notify(void *obj, struct event_reg *evt_reg, int has_listeners);
static int analyzer_tftp_pkt_process(void *obj, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index);


struct analyzer_tftp_priv {
	struct event_reg *evt_file;
	struct proto_packet_listener *pkt_listener;
};


struct analyzer_tftp_file {
	struct event *evt;
	uint16_t port;
	struct pload *pload;
	struct analyzer_tftp_file *prev, *next;
};

struct analyzer_tftp_session_priv {
	struct analyzer_tftp_file *files;
};

#endif
