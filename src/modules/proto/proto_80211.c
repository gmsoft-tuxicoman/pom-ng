/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2012-2013 Guy Martin <gmsoft@tuxicoman.be>
 *
 *  Part of this is taken from packet-o-matic :
 *  Copyright (C) 2009 Mike Kershaw <dragorn@kismetwireless.net>
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

#include <pom-ng/ptype.h>
#include <pom-ng/proto.h>
#include <pom-ng/ptype_mac.h>
#include <pom-ng/ptype_string.h>
#include <pom-ng/ptype_uint8.h>

#include "proto_80211.h"

#include <string.h>
#include <arpa/inet.h>
#include <ieee80211.h>
#include <stddef.h>

struct mod_reg_info* proto_80211_reg_info() {

	static struct mod_reg_info reg_info = { 0 };
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = proto_80211_mod_register;
	reg_info.unregister_func = proto_80211_mod_unregister;
	reg_info.dependencies = "ptype_mac, ptype_string, ptype_uint8";

	return &reg_info;
}

static int proto_80211_mod_register(struct mod_reg *mod) {

	static struct proto_pkt_field fields[PROTO_80211_FIELD_NUM + 1] = { { 0 } };
	fields[0].name = "src";
	fields[0].value_type = ptype_get_type("mac");
	fields[0].description = "Source address";
	fields[1].name = "dst";
	fields[1].value_type = ptype_get_type("mac");
	fields[1].description = "Destination address";
	fields[2].name = "bssid";
	fields[2].value_type = ptype_get_type("mac");
	fields[2].description = "BSSID address";
	fields[3].name = "type";
	fields[3].value_type = ptype_get_type("uint8");
	fields[3].description = "802.11 frame type";
	fields[4].name = "subtype";
	fields[4].value_type = ptype_get_type("uint8");
	fields[4].description = "802.11 frame sub-type";


	static struct proto_reg_info proto_80211 = { 0 };
	proto_80211.name = "80211";
	proto_80211.api_ver = PROTO_API_VER;
	proto_80211.mod = mod;
	proto_80211.pkt_fields = fields;
	proto_80211.number_class = "ethernet";

	// No contrack here

	proto_80211.process = proto_80211_process;

	if (proto_register(&proto_80211) == POM_OK)
		return POM_OK;


	return POM_ERR;

}

static int proto_80211_process(void *proto_priv, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct proto_process_stack *s = &stack[stack_index];
	struct proto_process_stack *s_next = &stack[stack_index + 1];

	if (s->plen < offsetof(struct ieee80211_hdr, duration)) // We need at least the type field
		return PROTO_INVALID;

	struct ieee80211_hdr *i80211hdr = s->pload;

	unsigned int offt = 0;

	PTYPE_UINT8_SETVAL(s->pkt_info->fields_value[proto_80211_field_type], i80211hdr->u1.fc.type);
	PTYPE_UINT8_SETVAL(s->pkt_info->fields_value[proto_80211_field_subtype], i80211hdr->u1.fc.subtype);

	uint8_t empty_addr[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	switch (i80211hdr->u1.fc.type) {
		case WLAN_FC_TYPE_MGMT:
			/* Management frames */
			switch (i80211hdr->u1.fc.subtype) {
				case WLAN_FC_SUBTYPE_PROBEREQ:
					if (s->plen < 24)
						return PROTO_INVALID;
					PTYPE_MAC_SETADDR(s->pkt_info->fields_value[proto_80211_field_src], i80211hdr->addr2);
					PTYPE_MAC_SETADDR(s->pkt_info->fields_value[proto_80211_field_dst], i80211hdr->addr2);
					PTYPE_MAC_SETADDR(s->pkt_info->fields_value[proto_80211_field_bssid], i80211hdr->addr2);
					offt = 24;
					break;
				case WLAN_FC_SUBTYPE_DISASSOC:
				case WLAN_FC_SUBTYPE_AUTH:
				case WLAN_FC_SUBTYPE_DEAUTH:
					if (s->plen < 24)
						return PROTO_INVALID;
					PTYPE_MAC_SETADDR(s->pkt_info->fields_value[proto_80211_field_dst], i80211hdr->addr1);
					PTYPE_MAC_SETADDR(s->pkt_info->fields_value[proto_80211_field_src], i80211hdr->addr2);
					PTYPE_MAC_SETADDR(s->pkt_info->fields_value[proto_80211_field_bssid], i80211hdr->addr3);
					offt = 24;
					break;
				default:
					if (s->plen < 32)
						return PROTO_INVALID;
					PTYPE_MAC_SETADDR(s->pkt_info->fields_value[proto_80211_field_dst], i80211hdr->addr1);
					PTYPE_MAC_SETADDR(s->pkt_info->fields_value[proto_80211_field_src], i80211hdr->addr2);
					PTYPE_MAC_SETADDR(s->pkt_info->fields_value[proto_80211_field_bssid], i80211hdr->addr3);
					offt = 32;
					break;
			}
			break;
		case WLAN_FC_TYPE_CTRL:
			/* Control frame */
			switch (i80211hdr->u1.fc.subtype) {
				case WLAN_FC_SUBTYPE_PSPOLL:
				case WLAN_FC_SUBTYPE_RTS:
				case WLAN_FC_SUBTYPE_CFEND:
				case WLAN_FC_SUBTYPE_CFENDACK:
					if (s->plen < 16)
						return PROTO_INVALID;
					PTYPE_MAC_SETADDR(s->pkt_info->fields_value[proto_80211_field_dst], i80211hdr->addr1);
					PTYPE_MAC_SETADDR(s->pkt_info->fields_value[proto_80211_field_src], i80211hdr->addr2);
					PTYPE_MAC_SETADDR(s->pkt_info->fields_value[proto_80211_field_bssid], empty_addr);
					offt = 16;
					break;

				case WLAN_FC_SUBTYPE_CTS:
				case WLAN_FC_SUBTYPE_ACK:
					if (s->plen < 10)
						return PROTO_INVALID;
					PTYPE_MAC_SETADDR(s->pkt_info->fields_value[proto_80211_field_dst], i80211hdr->addr1);
					PTYPE_MAC_SETADDR(s->pkt_info->fields_value[proto_80211_field_src], empty_addr);
					PTYPE_MAC_SETADDR(s->pkt_info->fields_value[proto_80211_field_bssid], empty_addr);
					offt = 10;
					break;

				case WLAN_FC_SUBTYPE_BLOCKACKREQ:
					if (s->plen < 20)
						return PROTO_INVALID;
					PTYPE_MAC_SETADDR(s->pkt_info->fields_value[proto_80211_field_dst], i80211hdr->addr1);
					PTYPE_MAC_SETADDR(s->pkt_info->fields_value[proto_80211_field_src], i80211hdr->addr2);
					offt = 20; // 16 + 2 for BAR Control + 2 BAR Seq Control
					break;
				
				case WLAN_FC_SUBTYPE_BLOCKACK:
					if (s->plen < 148)
						return PROTO_INVALID;
					PTYPE_MAC_SETADDR(s->pkt_info->fields_value[proto_80211_field_dst], i80211hdr->addr1);
					PTYPE_MAC_SETADDR(s->pkt_info->fields_value[proto_80211_field_src], i80211hdr->addr2);
					offt = 148; // 16 + 2 for BA Control + 2 Seq Control + 128 BA Bitmap
					break;

			}
			break;
		case WLAN_FC_TYPE_DATA:
			/* Data frames can have funny-length headers and offsets */

			if (s->plen < 24)
				return PROTO_INVALID;

			/* Handle QoS */
			switch (i80211hdr->u1.fc.subtype) {
				case WLAN_FC_SUBTYPE_QOSDATA:
				case WLAN_FC_SUBTYPE_QOSDATACFACK:
				case WLAN_FC_SUBTYPE_QOSDATACFPOLL:
				case WLAN_FC_SUBTYPE_QOSDATACFACKPOLL:
				case WLAN_FC_SUBTYPE_QOSNULL:
				case WLAN_FC_SUBTYPE_QOSNULLCFPOLL:
				case WLAN_FC_SUBTYPE_QOSNULLCFACKPOLL:
					offt += 2;
					break;
			}

			if (i80211hdr->u1.fc.to_ds == 0 && i80211hdr->u1.fc.from_ds == 0) {
				PTYPE_MAC_SETADDR(s->pkt_info->fields_value[proto_80211_field_dst], i80211hdr->addr1);
				PTYPE_MAC_SETADDR(s->pkt_info->fields_value[proto_80211_field_src], i80211hdr->addr2);
				PTYPE_MAC_SETADDR(s->pkt_info->fields_value[proto_80211_field_bssid], i80211hdr->addr3);
				offt += 24;
			} else if (i80211hdr->u1.fc.to_ds == 0 && 
					   i80211hdr->u1.fc.from_ds == 1) {
				PTYPE_MAC_SETADDR(s->pkt_info->fields_value[proto_80211_field_dst], i80211hdr->addr1);
				PTYPE_MAC_SETADDR(s->pkt_info->fields_value[proto_80211_field_bssid], i80211hdr->addr2);
				PTYPE_MAC_SETADDR(s->pkt_info->fields_value[proto_80211_field_src], i80211hdr->addr3);
				offt += 24;
			} else if (i80211hdr->u1.fc.to_ds == 1 && 
					   i80211hdr->u1.fc.from_ds == 0) {
				PTYPE_MAC_SETADDR(s->pkt_info->fields_value[proto_80211_field_bssid], i80211hdr->addr1);
				PTYPE_MAC_SETADDR(s->pkt_info->fields_value[proto_80211_field_src], i80211hdr->addr2);
				PTYPE_MAC_SETADDR(s->pkt_info->fields_value[proto_80211_field_dst], i80211hdr->addr3);
				offt += 24;
			} else if (i80211hdr->u1.fc.to_ds == 1 && 
					   i80211hdr->u1.fc.from_ds == 1) {
				if (s->plen < offt + 30)
					return PROTO_INVALID;

				PTYPE_MAC_SETADDR(s->pkt_info->fields_value[proto_80211_field_bssid], i80211hdr->addr2);
				PTYPE_MAC_SETADDR(s->pkt_info->fields_value[proto_80211_field_dst], i80211hdr->addr1);
				PTYPE_MAC_SETADDR(s->pkt_info->fields_value[proto_80211_field_src], s->pload + sizeof(i80211hdr));
				offt += 30;
			}

			if (i80211hdr->u1.fc.subtype & WLAN_FC_SUBTYPE_MASK_NODATA) {
				s_next->pload = s->pload + offt;
				s_next->plen = 0;
				return PROTO_OK;
			}

			if (offt + sizeof(struct ieee80211_llc) > s->plen)
				return PROTO_INVALID;

			struct ieee80211_llc *llc = s->pload + offt;

			if (llc->dsnap != 0xaa || llc->ssap != 0xaa ||
				llc->control != 0x03) {
				// looks like wrong LLC? 
				return PROTO_OK;
			}

			offt += sizeof(struct ieee80211_llc);

			s_next->proto = proto_get_by_number(s->proto, ntohs(llc->ethertype));
			break;

		default:
			return PROTO_INVALID;

	}

	if (offt > s->plen)
		return PROTO_INVALID;

	s_next->pload = s->pload + offt;
	s_next->plen = s->plen - offt;

// x86 can do non aligned access 
#if !defined(__i386__) && !defined(__x86_64__)

	// Let's align the buffer
	// Why is this stupid header not always a multiple of 4 bytes ?
	char offset = (long)(f->buff + l->payload_start) & 3;
	if (offset) {
		if (f->buff - offset > f->buff_base) {
			memmove(f->buff - offset, f->buff, f->len);
			f->buff -= offset;
		} else {
			memmove(f->buff + offset, f->buff, f->len);
			f->buff += offset;

		}
	}

#endif

	return PROTO_OK;

}

static int proto_80211_mod_unregister() {

	return proto_unregister("80211");
}
