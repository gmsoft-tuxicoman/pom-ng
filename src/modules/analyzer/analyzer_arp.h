/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2012-14 Guy Martin <gmsoft@tuxicoman.be>
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


#ifndef __ANALYZER_ARP_H__
#define __ANALYZER_ARP_H__

#include <pom-ng/analyzer.h>

#define ANALYZER_ARP_HOST_TABLE_SIZE (1 << 12)
#define ANALYZER_ARP_HOST_MASK (ANALYZER_ARP_HOST_TABLE_SIZE - 1)

#define ANALYZER_ARP_EVT_NEW_STA_DATA_COUNT 4

enum {
	analyzer_arp_new_sta_mac_addr,
	analyzer_arp_new_sta_ip_addr,
	analyzer_arp_new_sta_vlan,
	analyzer_arp_new_sta_input
};

#define ANALYZER_ARP_EVT_STA_CHANGED_DATA_COUNT 5

enum {
	analyzer_arp_sta_changed_old_mac_addr,
	analyzer_arp_sta_changed_new_mac_addr,
	analyzer_arp_sta_changed_ip_addr,
	analyzer_arp_sta_changed_vlan,
	analyzer_arp_sta_changed_input
};


struct analyzer_arp_host {

	struct in_addr ip;
	uint16_t vlan;
	char mac[6];
	struct analyzer_arp_host *prev, *next;

};

struct analyzer_arp_priv {

	struct event_reg *evt_new_sta;
	struct event_reg *evt_sta_changed;
	struct proto_packet_listener *pkt_listener;
	struct proto *proto_vlan;

	struct registry_perf *perf_known_sta;

	pthread_mutex_t lock;
	struct analyzer_arp_host *hosts[ANALYZER_ARP_HOST_TABLE_SIZE];
};

struct mod_reg_info *analyzer_arp_reg_info();
static int analyzer_arp_mod_register(struct mod_reg *mod);
static int analyzer_arp_mod_unregister();
static int analyzer_arp_init(struct analyzer *analyzer);
static int analyzer_arp_cleanup(struct analyzer *analyzer);
static int analyzer_arp_event_listeners_notify(void *obj, struct event_reg *evt_reg, int has_listeners);
static int analyzer_arp_pkt_process(void *obj, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index);

#endif
