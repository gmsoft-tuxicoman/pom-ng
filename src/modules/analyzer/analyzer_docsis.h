/*
 *  This file is part of pom-ng.
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


#ifndef __ANALYZER_DOCSIS_H__
#define __ANALYZER_DOCSIS_H__

#include <pom-ng/analyzer.h>
#include <pom-ng/filter.h>

#define ANALYZER_DOCSIS_CM_TABLE_SIZE (1 << 12)
#define ANALYZER_DOCSIS_CM_MASK (ANALYZER_DOCSIS_CM_TABLE_SIZE - 1)

#define ANALYZER_DOCSIS_CM_TIMEOUT 60

#define ANALYZER_DOCSIS_EVT_NEW_CM_DATA_COUNT 3

enum {
	analyzer_docsis_new_cm_mac,
	analyzer_docsis_new_cm_input,
	analyzer_docsis_new_cm_time
};

#define ANALYZER_DOCSIS_EVT_CM_TIMEOUT_DATA_COUNT 2

enum {
	analyzer_docsis_cm_timeout_mac,
	analyzer_docsis_cm_timeout_time
};

struct analyzer_docsis_cm {

	char mac[6];
	struct analyzer_docsis_cm *prev, *next;
	struct timer *t;
	struct analyzer *analyzer;

};

struct analyzer_docsis_priv {

	struct event_reg *evt_new_cm;
	struct event_reg *evt_cm_timeout;
	struct proto_packet_listener *pkt_listener;

	pthread_mutex_t lock;
	struct analyzer_docsis_cm *cms[ANALYZER_DOCSIS_CM_TABLE_SIZE];

	struct filter_proto *filter;
};

struct mod_reg_info *analyzer_docsis_reg_info();
static int analyzer_docsis_mod_register(struct mod_reg *mod);
static int analyzer_docsis_mod_unregister();
static int analyzer_docsis_init(struct analyzer *analyzer);
static int analyzer_docsis_cleanup(struct analyzer *analyzer);
static int analyzer_docsis_event_listeners_notify(void *obj, struct event_reg *evt_reg, int has_listeners);
static int analyzer_docsis_pkt_process(void *obj, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index);
static int analyzer_docsis_cm_timeout(void *cable_modem, struct timeval *now);

#endif
