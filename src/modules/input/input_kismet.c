/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2013-2015 Guy Martin <gmsoft@tuxicoman.be>
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

#include <pom-ng/input.h>
#include <pom-ng/registry.h>
#include <pom-ng/proto.h>
#include <pom-ng/core.h>

#include <pom-ng/ptype_string.h>
#include <pom-ng/ptype_uint16.h>

#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include "input_kismet.h"

#if 0
#define debug_kismet(x...) pomlog(POMLOG_DEBUG x)
#else
#define debug_kismet(x...)
#endif


struct mod_reg_info* input_kismet_reg_info() {
	static struct mod_reg_info reg_info;
	memset(&reg_info, 0, sizeof(struct mod_reg_info));
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = input_kismet_mod_register;
	reg_info.unregister_func = input_kismet_mod_unregister;
	reg_info.dependencies = "proto_80211, proto_radiotap, ptype_string, ptype_uint16";

	return &reg_info;
}


static int input_kismet_mod_register(struct mod_reg *mod) {

	static struct input_reg_info in_kismet_drone;
	memset(&in_kismet_drone, 0, sizeof(struct input_reg_info));
	in_kismet_drone.name = "kismet_drone";
	in_kismet_drone.description = "Connect to a Kismet drone and read the packets";
	in_kismet_drone.flags = INPUT_REG_FLAG_LIVE;
	in_kismet_drone.mod = mod;
	in_kismet_drone.init = input_kismet_drone_init;
	in_kismet_drone.open = input_kismet_drone_open;
	in_kismet_drone.read = input_kismet_drone_read;
	in_kismet_drone.close = input_kismet_drone_close;
	in_kismet_drone.cleanup = input_kismet_drone_cleanup;
	in_kismet_drone.interrupt = input_kismet_drone_interrupt;
	return input_register(&in_kismet_drone);
}

static int input_kismet_mod_unregister() {

	return input_unregister("kismet_drone");
}


static int input_kismet_drone_init(struct input *i) {


	struct input_kismet_drone_priv *priv;
	priv = malloc(sizeof(struct input_kismet_drone_priv));
	if (!priv) {
		pom_oom(sizeof(struct input_kismet_drone_priv));
		return POM_ERR;
	}
	memset(priv, 0, sizeof(struct input_kismet_drone_priv));
	priv->fd = -1;

	struct registry_param *p = NULL;

	priv->datalink_80211 = proto_get("80211");
	priv->datalink_radiotap = proto_get("radiotap");
	if (!priv->datalink_80211 || !priv->datalink_radiotap) {
		pomlog(POMLOG_ERR "Could not find datalink 80211 or radiotap");
		goto err;
	}

	priv->p_host = ptype_alloc("string");
	priv->p_port = ptype_alloc("uint16");
	if (!priv->p_host || !priv->p_port)
		goto err;

	p = registry_new_param("host", "localhost", priv->p_host, "Kismet drone host", 0);
	if (input_add_param(i, p) != POM_OK)
		goto err;
	
	p = registry_new_param("port", "2502", priv->p_port, "Kismet drone port", 0);
	if (input_add_param(i, p) != POM_OK)
		goto err;


	i->priv = priv;

	return POM_OK;
err:
	if (p)
		registry_cleanup_param(p);

	if (priv->p_host)
		ptype_cleanup(priv->p_host);

	if (priv->p_port)
		ptype_cleanup(priv->p_port);

	free(priv);

	return POM_ERR;
}

static int input_kismet_drone_cleanup(struct input *i) {

	struct input_kismet_drone_priv *priv;
	priv = i->priv;

	if (priv->fd != -1)
		close(priv->fd);
	
	if (priv->p_host)
		ptype_cleanup(priv->p_host);
	if (priv->p_port)
		ptype_cleanup(priv->p_port);

	free(priv);

	return POM_OK;
}

static int input_kismet_drone_open(struct input *i) {
	
	struct input_kismet_drone_priv *priv = i->priv;

	char *host = PTYPE_STRING_GETVAL(priv->p_host);

	char *port = ptype_print_val_alloc(priv->p_port, NULL);
	if (!port)
		return POM_ERR;

	struct addrinfo hints = { 0 };
	//hints.ai_family = AF_UNSPEC;
	hints.ai_family = AF_INET; // kismet_drone seem to only listen on ipv4 address
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = 0;
	hints.ai_flags = AI_ADDRCONFIG;

	struct addrinfo *res = NULL;
	int err = getaddrinfo(host, port, &hints, &res);

	free(port);

	if (err) {
		pomlog(POMLOG_ERR "Error while resolving hostname %s : %s", host, gai_strerror(err));
		return POM_ERR;
	}


	priv->fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);

	if (priv->fd == -1) {
		freeaddrinfo(res);
		pomlog(POMLOG_ERR "Error while creating socket : %s", pom_strerror(errno));
		return POM_ERR;
	}
	
	if (connect(priv->fd, res->ai_addr, res->ai_addrlen)) {
		freeaddrinfo(res);
		close(priv->fd);
		priv->fd = -1;
		pomlog(POMLOG_ERR "Error while connecting to Kismet drone : %s", pom_strerror(errno));
		return POM_ERR;
	}

	freeaddrinfo(res);

	pomlog("Connection established to Kismet drone %s:%u", host, *PTYPE_UINT16_GETVAL(priv->p_port));

	return POM_OK;
}

static int input_kismet_drone_close(struct input *i) {

	struct input_kismet_drone_priv *priv = i->priv;
	if (priv->fd != -1) {
		if (close(priv->fd))
			pomlog(POMLOG_WARN "Error while closing socket to kismet_drone : %s", pom_strerror(errno));
		priv->fd = -1;
	}

	while (priv->srcs) {
		struct kismet_drone_source *src = priv->srcs;
		priv->srcs = src->next;
		free(src->name);
		free(src->interface);
		free(src->type);
		free(src);
	}

	return POM_OK;
}

static int input_kismet_drone_discard_bytes(struct input_kismet_drone_priv *priv, size_t len) {

	// Discard whatever command we dont need/support
	char buffer[256];
	size_t r = len;
	while (r > 0) {
		size_t rlen = sizeof(buffer);
		if (rlen > r)
			rlen = r;
		ssize_t res = read(priv->fd, buffer, rlen);
		if (res < 0) {
			pomlog(POMLOG_ERR "Read error : %s", pom_strerror(errno));
			return POM_ERR;
		}
		r -= res;
	}
	return POM_OK;
}

static int input_kismet_drone_read(struct input *i) {

	struct input_kismet_drone_priv *priv = i->priv;

	if (priv->fd == -1)
		return POM_ERR;

	while (1) {
		struct kismet_drone_packet kpkt;
		if (pom_read(priv->fd, &kpkt, sizeof(struct kismet_drone_packet)) != POM_OK)
			return POM_ERR;

		if (ntohl(kpkt.sentinel) != KISMET_DRONE_SENTINEL) {
			pomlog(POMLOG_ERR "Invalid sentinel value : 0x%X, expected 0x%X", kpkt.sentinel, KISMET_DRONE_SENTINEL);
			return POM_ERR;
		}

		enum kismet_drone_cmd cmdnum = ntohl(kpkt.drone_cmdnum);
		uint32_t data_len = ntohl(kpkt.data_len);

		debug_kismet("CMD %u, data_len %u", cmdnum, data_len);

		switch (cmdnum) {
			case kismet_drone_cmd_hello: {
				if (data_len != sizeof(struct kismet_drone_packet_hello)) {
					pomlog(POMLOG_ERR "Invalid length for hello packet : got %u, expected %u", data_len, sizeof(struct kismet_drone_packet_hello));
					return POM_ERR;
				}
				struct kismet_drone_packet_hello hello_pkt;
				if (pom_read(priv->fd, &hello_pkt, sizeof(struct kismet_drone_packet_hello)) != POM_OK)
					return POM_ERR;
				char version[33] = { 0 };
				strncpy(version, hello_pkt.kismet_version, 32);
				char hostname[33] = { 0 };
				strncpy(hostname, hello_pkt.host_name, 32);
				pomlog("Input %s connected to Kismet %s on %s (drone version %u)", i->name, version, hostname, ntohl(hello_pkt.drone_version));
				break;

			}
			case kismet_drone_cmd_source: {
				if (data_len != sizeof(struct kismet_drone_packet_source)) {
					pomlog(POMLOG_ERR "Invalid length for source packet : got %u, expected %u", data_len, sizeof(struct kismet_drone_packet_source));
					return POM_ERR;
				}
				struct kismet_drone_packet_source source_pkt;
				if (pom_read(priv->fd, &source_pkt, sizeof(struct kismet_drone_packet_source)) != POM_OK)
					return POM_ERR;

				if (source_pkt.invalidate) {
					// TODO
					return POM_ERR;
				}

				struct kismet_drone_source *src = malloc(sizeof(struct kismet_drone_source));
				if (!src) {
					pom_oom(sizeof(struct kismet_drone_source));
					return POM_ERR;
				}
				memset(src, 0, sizeof(struct kismet_drone_source));
				
				memcpy(src->uuid, source_pkt.uuid, sizeof(src->uuid));
				src->name = strndup(source_pkt.name_str, sizeof(source_pkt.name_str));
				src->interface = strndup(source_pkt.interface_str, sizeof(source_pkt.interface_str));
				src->type = strndup(source_pkt.type_str, sizeof(source_pkt.type_str));
				if (!src->name || !src->interface || !src->type) {
					if (src->name)
						free(src->name);
					if (src->interface)
						free(src->interface);
					if (src->type)
						free(src->type);
					free(src);
					pom_oom(sizeof(source_pkt.name_str));
					return POM_ERR;
				}

				pomlog("New Kismet drone source for input %s : %s (interface: %s, type: %s)", i->name, src->name, src->interface, src->type);

				if (source_pkt.channel_hop && !source_pkt.channel_dwell) {
					pomlog(POMLOG_WARN "Warning, source %s from input %s is configured to hop channels without dwelling !", i->name, src->name);
				}

				src->next = priv->srcs;
				if (priv->srcs)
					priv->srcs->prev = src;
				priv->srcs = src;

				break;
			}

			case kismet_drone_cmd_cappacket: {
				if (data_len < sizeof(struct kismet_drone_packet_capture)) {
					pomlog(POMLOG_ERR "Packet capture data length too small");
					return POM_ERR;
				}
				struct kismet_drone_packet_capture capture_pkt;
				if (pom_read(priv->fd, &capture_pkt, sizeof(struct kismet_drone_packet_capture)) != POM_OK)
					return POM_ERR;

				debug_kismet("Capture packet bitmap 0x%X, offset %u", ntohl(capture_pkt.content_bitmap), ntohl(capture_pkt.packet_offset));

				data_len -= sizeof(struct kismet_drone_packet_capture);

				uint32_t bitmap = ntohl(capture_pkt.content_bitmap);

				if (!(bitmap & KISMET_DRONE_BIT_DATA_IEEEPACKET)) {
					debug_kismet("No data in this packet, skipping %u bytes of data", data_len);
					if (input_kismet_drone_discard_bytes(priv, data_len) != POM_OK)
						return POM_ERR;
					break;
				}

				uint32_t offset = ntohl(capture_pkt.packet_offset);
				if (offset > data_len) {
					pomlog(POMLOG_ERR "Packet offset bigger than expected length");
					return POM_ERR;
				}

				if (input_kismet_drone_discard_bytes(priv, offset) != POM_OK)
					return POM_ERR;

				data_len -= offset;

				if (data_len < sizeof(struct kismet_drone_sub_packet_data)) {
					pomlog(POMLOG_ERR "Remaining data smaller than sub_packet_data");
					return POM_ERR;
				}

				struct kismet_drone_sub_packet_data data_pkt;
				if (pom_read(priv->fd, &data_pkt, sizeof(struct kismet_drone_sub_packet_data)) != POM_OK)
					return POM_ERR;

				data_len -= sizeof(struct kismet_drone_sub_packet_data);

				debug_kismet("Capture data packet bitmap 0x%X, hdr len %u, pkt len %u", ntohl(data_pkt.content_bitmap), ntohs(data_pkt.data_hdr_len), ntohs(data_pkt.packet_len));

				size_t pkt_len = ntohs(data_pkt.packet_len);

				if (pkt_len > data_len) {
					pomlog(POMLOG_ERR "Data packet length bigger than expected data size");
					return POM_ERR;
				}

				uint32_t dlt = ntohl(data_pkt.dlt);
				struct proto *datalink = NULL;
				switch (dlt) {
					case DLT_IEEE802_11:
						datalink = priv->datalink_80211;
						break;
					case DLT_IEEE802_11_RADIO:
						datalink = priv->datalink_radiotap;
						break;
					default:
						pomlog(POMLOG_ERR "Unexpected DLT received : %u", dlt);
						return POM_ERR;
				}

				struct packet *pkt = packet_alloc();
				if (!pkt)
					return POM_ERR;

				if (packet_buffer_alloc(pkt, pkt_len, 0) != POM_OK) {
					packet_release(pkt);
					return POM_ERR;
				}

				pkt->input = i;
				pkt->datalink = datalink;
				pkt->ts = (ntohll(data_pkt.tv_sec) *  1000000UL) + ntohll(data_pkt.tv_usec);

				if (pom_read(priv->fd, pkt->buff, pkt_len) != POM_OK) {
					packet_release(pkt);
					return POM_ERR;
				}

				return core_queue_packet(pkt, 0, 0);
			}

			default: {
				if (input_kismet_drone_discard_bytes(priv, data_len) != POM_OK)
					return POM_ERR;
				break;
			}
		}


	}

	return POM_OK;

}

static int input_kismet_drone_interrupt(struct input *i) {
	
	struct input_kismet_drone_priv *priv = i->priv;
	if (priv->fd != -1)
		pthread_kill(i->thread, SIGCHLD);

	return POM_OK;
}
