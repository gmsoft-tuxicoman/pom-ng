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



#ifndef __PACKET_H__
#define __PACKET_H__

#include <pom-ng/proto.h>
#include <pom-ng/packet.h>

#define PACKET_HALF_SEQ (0x1 << 31)

struct packet_info_pool {
	pthread_mutex_t lock;
	struct packet_info *used, *unused;
	unsigned int pool_size, usage;
};

struct packet *packet_pool_get();
int packet_pool_release(struct packet *p);


int packet_info_pool_init(struct packet_info_pool *pool);
struct packet_info *packet_info_pool_get(struct proto_reg *p);
int packet_pool_cleanup();
int packet_info_pool_release(struct packet_info_pool *pool, struct packet_info *info);
int packet_info_pool_cleanup(struct packet_info_pool *pool);

struct packet_stream_pkt *packet_stream_get_next(struct packet_stream *stream, unsigned int direction);

#endif
