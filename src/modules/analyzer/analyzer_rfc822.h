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


#ifndef __ANALYZER_RFC822_H__
#define __ANALYZER_RFC822_H__

#include <pom-ng/analyzer.h>
#include <pom-ng/packet.h>

#define ANALYZER_RFC822_PLOAD_TYPE		"rfc822"

#define ANALYZER_RFC822_PLOAD_DATA_COUNT	1

// RFC 5233 actually specifies 1000 char including CRLF
#define ANALYZER_RFC822_MAX_LINE_LEN		2048

enum analyzer_rfc822_pload_data {
	analyzer_rfc822_pload_headers,
};

enum analyzer_rfc822_pload_state {
	analyzer_rfc822_pload_state_initial,
	analyzer_rfc822_pload_state_processing,
	analyzer_rfc822_pload_state_done
};

struct analyzer_rfc822_pload_priv {
	char *last_hdr_name;
	char *last_hdr_value;
	size_t pload_pos;

	char *content_type;
	char *content_transfer_encoding;

	enum analyzer_rfc822_pload_state state;
	struct analyzer_pload_type *sub_type;
	struct analyzer_pload_buffer *sub_pload;
};

struct mod_reg_info* analyzer_rfc822_reg_info();
static int analyzer_rfc822_mod_register(struct mod_reg *mod);
static int analyzer_rfc822_mod_unregister();

static int analyzer_rfc822_init(struct analyzer *analyzer);
static int analyzer_rfc822_pload_cleanup(struct analyzer *analyzer, struct analyzer_pload_buffer *pload);
static int analyzer_rfc822_pload_analyze(struct analyzer *analyzer, struct analyzer_pload_buffer *pload);
static int analyzer_rfc822_pload_process(struct analyzer *analyzer, struct analyzer_pload_buffer *pload, void *data, size_t len);

#endif
