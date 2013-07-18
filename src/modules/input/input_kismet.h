/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2013 Guy Martin <gmsoft@tuxicoman.be>
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


#ifndef __INPUT_KISMET_H__
#define __INPUT_KISMET_H__

#define KISMET_DRONE_SENTINEL	0xDEADBEEF

// Avoid depending on libpcap just for DLT values
#define DLT_IEEE802_11		105
#define DLT_IEEE802_11_RADIO	127

#define KISMET_DRONE_BIT_DATA_IEEEPACKET 0x80000000

struct kismet_drone_source {

	char uuid[16];
	char *name;
	char *interface;
	char *type;

	struct kismet_drone_source *prev, *next;

};

struct input_kismet_drone_priv {
	
	struct ptype *p_host;
	struct ptype *p_port;

	int fd;

	struct proto *datalink_80211;
	struct proto *datalink_radiotap;

	struct kismet_drone_source *srcs;

};

enum kismet_drone_cmd {
	kismet_drone_cmd_null = 0,
	kismet_drone_cmd_hello,
	kismet_drone_cmd_string,
	kismet_drone_cmd_cappacket,
	kismet_drone_cmd_channelset,
	kismet_drone_cmd_source,
	kismet_drone_cmd_report
};

struct kismet_drone_packet {
	uint32_t sentinel;
	uint32_t drone_cmdnum;
	uint32_t data_len;
	uint8_t data[0];
} __attribute__((__packed__));

struct kismet_drone_packet_hello {
	uint32_t drone_version;
	char kismet_version[32];
	char host_name[32];
} __attribute__((__packed__));

struct kismet_drone_packet_source {
	uint16_t source_hdr_len;
	uint32_t source_content_bitmap;
	char uuid[16];
	uint16_t invalidate;
	char name_str[16];
	char interface_str[16];
	char type_str[16];
	uint8_t channel_hop;
	uint16_t channel_dwell;
	uint16_t channel_rate;
} __attribute__((__packed__));

struct kismet_drone_packet_capture {
	uint32_t content_bitmap;
	uint32_t packet_offset;
	uint8_t data[0];
} __attribute__((__packed__));

struct kismet_drone_sub_packet_data {
	uint16_t data_hdr_len;
	uint32_t content_bitmap;
	char uuid[16];
	uint16_t packet_len;
	uint64_t tv_sec;
	uint64_t tv_usec;
	uint32_t dlt;
	uint8_t data[0];
} __attribute__((__packed__));

static int input_kismet_mod_register(struct mod_reg *mod);
static int input_kismet_mod_unregister();

static int input_kismet_drone_init(struct input *i);
static int input_kismet_drone_cleanup(struct input *i);

static int input_kismet_drone_open(struct input *i);
static int input_kismet_drone_close(struct input *i);

static int input_kismet_drone_read(struct input *i);

static int input_kismet_drone_interrupt(struct input *i);

#endif

