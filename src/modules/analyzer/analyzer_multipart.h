/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2013-2014 Guy Martin <gmsoft@tuxicoman.be>
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


#ifndef __ANALYZER_MULTIPART_H__
#define __ANALYZER_MULTIPART_H__

#include <pom-ng/analyzer.h>
#include <pom-ng/packet.h>
#include <pom-ng/pload.h>

#define ANALYZER_MULTIPART_PLOAD_TYPE		"multipart"

// RFC 5233 actually specifies 1000 char including CRLF
#define ANALYZER_MULTIPART_MAX_LINE_LEN		2048

enum analyzer_multipart_pload_state {
	analyzer_multipart_pload_state_init,
	analyzer_multipart_pload_state_error,
	analyzer_multipart_pload_state_header,
	analyzer_multipart_pload_state_content,
	analyzer_multipart_pload_state_end
};

struct analyzer_multipart_pload_priv {
	char *boundary;
	size_t boundary_len;
	char *last_line;
	enum analyzer_multipart_pload_state state;
	size_t last_line_len;

	struct pload *parent_pload;
	struct pload *pload; // One of the part
	struct data pload_data; // Header of the current part
	void *pload_start, *pload_end;

	char *last_hdr_name, *last_hdr_value;

};

struct mod_reg_info* analyzer_multipart_reg_info();
static int analyzer_multipart_mod_register(struct mod_reg *mod);
static int analyzer_multipart_mod_unregister();

static int analyzer_multipart_init(struct analyzer *analyzer);
static int analyzer_multipart_cleanup(struct analyzer *analyzer);
static int analyzer_multipart_pload_open(void *obj, void **priv, struct pload *pload);
static int analyzer_multipart_pload_process_line(struct analyzer_multipart_pload_priv *priv, char *line, size_t len);
static int analyzer_multipart_pload_write(void *obj, void *p, void *data, size_t len);
static int analyzer_multipart_pload_close(void *obj, void *p);

#endif
