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


#ifndef __POM_NG_PACKET_H__
#define __POM_NG_PACKET_H__

#include <pthread.h>

struct packet {

	// Packet description
	struct timeval ts;
	size_t len;
	struct proto_reg *datalink;
	unsigned char *buff;
	struct input_client_entry *input; // Input the packet came from initially
	struct input_packet *input_pkt; // Input packet, present if buff points to the input IPC buffer
	struct packet_multipart *multipart; // Multipart details if the current packet is compose of multiple ones
	struct packet_info_list *info_head, *info_tail;
	unsigned int refcount; // Reference count
	struct packet *prev, *next; // Used internally
};

struct packet_info {
	struct ptype **fields_value;
	struct packet_info *pool_next, *pool_prev;
};


struct packet_multipart_pkt {

	size_t offset, len, pkt_buff_offset;
	struct packet *pkt;
	struct packet_multipart_pkt *prev, *next;

};

struct packet_multipart {

	size_t cur; // Current ammount of data in the buffer
	unsigned int gaps; // Number of gaps
	struct packet_multipart_pkt *head, *tail;
	struct proto_dependency *proto;
};


struct packet *packet_copy(struct packet *src);
struct packet_multipart *packet_multipart_alloc(struct proto_dependency *proto_dep);
int packet_multipart_cleanup(struct packet_multipart *m);
int packet_multipart_add(struct packet_multipart *multipart, struct packet *pkt, size_t offset, size_t len, size_t pkt_buff_offset);
int packet_multipart_process(struct packet_multipart *multipart, struct proto_process_stack *stack, unsigned int stack_index);

#endif
