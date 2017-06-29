/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2010-2015 Guy Martin <gmsoft@tuxicoman.be>
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

#include <pom-ng/base.h>
#include <pom-ng/timer.h>
#include <pom-ng/conntrack.h>
#include <pom-ng/filter.h>

#define PACKET_FLAG_FORCE_NO_COPY	0x1

#define PACKET_STREAM_PARSER_FLAG_TRIM		0x1
#define PACKET_STREAM_PARSER_FLAG_INCLUDE_CRLF	0x2

struct packet {

	// Packet description
	size_t len;  // Packet length
	ptime ts;
	struct proto *datalink;
	void *buff;
	struct input *input; // Input the packet came from initially
	struct packet_buffer *pkt_buff; // Structure pointing to the buffer information (if any)
	struct packet_multipart *multipart; // Multipart details if the current packet is compose of multiple ones
	unsigned int refcount; // Reference count
	struct packet *prev, *next; // Used internally
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
	struct proto *proto;
	unsigned int align_offset;
};

struct packet_info {
	struct ptype **fields_value;
	struct packet_info *next;
};

int packet_buffer_alloc(struct packet *pkt, size_t size, size_t align_offset);

struct packet *packet_alloc();
struct packet *packet_clone(struct packet *src, unsigned int flags);
int packet_release(struct packet *p);

struct packet_multipart *packet_multipart_alloc(struct proto *proto, unsigned int flags, unsigned int align_offset);
int packet_multipart_cleanup(struct packet_multipart *m);
int packet_multipart_add_packet(struct packet_multipart *multipart, struct packet *pkt, size_t offset, size_t len, size_t pkt_buff_offset);
int packet_multipart_process(struct packet_multipart *multipart, struct proto_process_stack *stack, unsigned int stack_index);

struct packet_stream_parser *packet_stream_parser_alloc(size_t max_line_size, unsigned int flags);
int packet_stream_parser_add_payload(struct packet_stream_parser *sp, void *pload, size_t len);
// Add payload to the stream parser and use it as or own buffer (or copy then free it if we already have some stuff buffered)
int packet_stream_parser_add_payload_buffer(struct packet_stream_parser *sp, void *pload, size_t len);
int packet_stream_parser_get_line(struct packet_stream_parser *sp, char **line, size_t *len);
int packet_stream_parser_get_bytes(struct packet_stream_parser *p, size_t len, void **pload);
int packet_stream_parser_get_remaining(struct packet_stream_parser *sp, void **pload, size_t *len);
int packet_stream_parser_skip_bytes(struct packet_stream_parser *sp, size_t len);
int packet_stream_parser_empty(struct packet_stream_parser *sp);
int packet_stream_parser_cleanup(struct packet_stream_parser *sp);

struct filter *packet_filter_compile(char *filter_expr);
int packet_filter_match(struct filter *f, struct proto_process_stack *stack);

#endif
