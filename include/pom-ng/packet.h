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

#define PACKET_FLAG_FORCE_NO_COPY	0x1
#define PACKET_FLAG_STREAM_BIDIR	0x2

struct packet {

	// Packet description
	struct timeval ts;
	size_t len;
	struct proto_reg *datalink;
	void *buff;
	struct input_client_entry *input; // Input the packet came from initially
	uint64_t id; // Unique packet number per input
	struct input_packet *input_pkt; // Input packet, present if buff points to the input IPC buffer
	struct packet_multipart *multipart; // Multipart details if the current packet is compose of multiple ones
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
	unsigned int flags;
	struct packet_multipart_pkt *head, *tail;
	struct proto_dependency *proto;
};

struct packet_stream_pkt {

	struct packet *pkt;
	uint32_t seq, len, pkt_buff_offset;
	struct proto_reg *proto;
	unsigned int flags;
	struct packet_info *pkt_info;
	struct packet_stream_pkt *prev, *next;

};

struct packet_stream {

	uint32_t cur_seq[CT_DIR_TOT];
	uint32_t cur_buff_size, max_buff_size;
	unsigned int flags;
	pthread_mutex_t lock;
	struct packet_stream_pkt *head[CT_DIR_TOT], *tail[CT_DIR_TOT];
	int (*handler) (void *priv, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index);
	void *priv;
};


struct packet_stream_parser {
	unsigned int max_line_size;
	char *buff;
	unsigned int bufflen;
	unsigned int buffpos;
	char *pload;
	unsigned int plen;
};

struct packet *packet_clone(struct packet *src, unsigned int flags);

struct packet_multipart *packet_multipart_alloc(struct proto_dependency *proto_dep, unsigned int flags);
int packet_multipart_cleanup(struct packet_multipart *m);
int packet_multipart_add_packet(struct packet_multipart *multipart, struct packet *pkt, size_t offset, size_t len, size_t pkt_buff_offset);
int packet_multipart_process(struct packet_multipart *multipart, struct proto_process_stack *stack, unsigned int stack_index);

struct packet_stream* packet_stream_alloc(uint32_t start_seq, uint32_t start_ack, int direction, uint32_t max_buff_size, unsigned int flags, int (*handler) (void *priv, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index),  void *priv);
int packet_stream_cleanup(struct packet_stream *stream);
int packet_stream_process_packet(struct packet_stream *stream, struct packet *pkt, struct proto_process_stack *stack, unsigned int stack_index, uint32_t seq, uint32_t ack);

struct packet_stream_parser *packet_stream_parser_alloc(unsigned int max_line_size);
int packet_stream_parser_add_payload(struct packet_stream_parser *sp, void *pload, unsigned int len);
int packet_stream_parser_get_line(struct packet_stream_parser *sp, char **line, unsigned int *len);
int packet_stream_parser_cleanup(struct packet_stream_parser *sp);
#endif
