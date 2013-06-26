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



#ifndef __PACKET_H__
#define __PACKET_H__

#include <pom-ng/proto.h>
#include <pom-ng/packet.h>

#define PACKET_BUFFER_ALIGNMENT 4
#define PACKET_BUFFER_POOL_ID_UNUSED -1

struct packet_buffer {

	void *base_buff;
	void *aligned_buff;
	volatile int pool_id;
	struct packet_buffer *next, *prev;

	// The actual data will be after this
	
};

struct packet_stream_parser {
	unsigned int max_line_size;
	char *buff;
	unsigned int buff_len;
	unsigned int buff_pos;
	char *pload;
	unsigned int plen;
	unsigned int flags;
};

void packet_buffer_pool_release(struct packet_buffer *pb);
void packet_pool_thread_cleanup();
void packet_buffer_pool_thread_cleanup();
int packet_buffer_pool_cleanup();


struct packet_info *packet_info_pool_get(struct proto *p);
struct packet_info *packet_info_pool_clone(struct proto *p, struct packet_info *info);
int packet_pool_cleanup();
int packet_info_pool_init();
int packet_info_pool_release(struct packet_info *info, unsigned int protocol_id);
int packet_info_pool_cleanup();

#endif
