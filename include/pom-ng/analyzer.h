/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2011-2012 Guy Martin <gmsoft@tuxicoman.be>
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


#ifndef __POM_NG_ANALYZER_H__
#define __POM_NG_ANALYZER_H__

#include <pom-ng/base.h>
#include <pom-ng/event.h>
#include <pom-ng/conntrack.h>
#include <pom-ng/data.h>

#ifdef HAVE_ZLIB
#include <zlib.h>
#endif

// Current analyzer API version
#define ANALYZER_API_VER 1


// Data flags
#define ANALYZER_DATA_FLAG_LIST 1

// Payload analyzer flags
#define ANALYZER_PLOAD_PROCESS_PARTIAL 0x1

// Payload buffer flags
#define ANALYZER_PLOAD_BUFFER_NEED_MAGIC	0x1
#define ANALYZER_PLOAD_BUFFER_IS_GZIP		0x2
#define ANALYZER_PLOAD_BUFFER_IS_DEFLATE	0x4
#define ANALYZER_PLOAD_BUFFER_IS_BASE64		0x8

struct analyzer {

	struct analyzer_reg *info;
	void *priv;

	struct analyzer *prev, *next;

};

struct analyzer_reg {

	unsigned int api_ver;
	char *name;
	struct mod_reg *mod;

	int (*init) (struct analyzer *analyzer);
	int (*cleanup) (struct analyzer *analyzer);

};

struct analyzer_pload_class {

	char *name;
	char *description;

};

#define ANALYZER_PLOAD_CLASS_COUNT 6
enum analyzer_pload_class_id {
	analyzer_pload_class_unknown,
	analyzer_pload_class_application,
	analyzer_pload_class_audio,
	analyzer_pload_class_image,
	analyzer_pload_class_video,
	analyzer_pload_class_document,
};

struct analyzer_pload_instance;
struct analyzer_pload_type;

enum analyzer_pload_buffer_state {
	
	analyzer_pload_buffer_state_empty = 0,
	analyzer_pload_buffer_state_magic,
	analyzer_pload_buffer_state_partial,
	analyzer_pload_buffer_state_analyzed,
	analyzer_pload_buffer_state_error,
	analyzer_pload_buffer_state_done,

};

struct analyzer_pload_buffer {

	struct analyzer_pload_type *type;
	size_t expected_size, buff_size;
	size_t buff_pos;

	void *buff;

	enum analyzer_pload_buffer_state state;
	unsigned int flags;

	struct data *data;
	struct event *rel_event;
	struct analyzer_pload_instance *output_list;
	void *analyzer_priv;

#ifdef HAVE_ZLIB
	z_stream *zbuff;
#endif

};

struct analyzer_pload_reg {

	struct analyzer *analyzer;
	struct data_reg *data_reg;
	unsigned int flags;

	int (*process) (struct analyzer *analyzer, struct analyzer_pload_buffer *pload);
	int (*cleanup) (struct analyzer *analyzer, struct analyzer_pload_buffer *pload);

};

struct analyzer_pload_output_reg {


	int (*open) (struct analyzer_pload_instance *pi, void *output_priv);
	int (*write) (void *pload_instance_priv, void *data, size_t len);
	int (*close) (void *pload_instance_priv);

};

int analyzer_register(struct analyzer_reg *reg_info);
int analyzer_unregister(char *name);

int analyzer_pload_register(struct analyzer_pload_type *pt, struct analyzer_pload_reg *pload_analyzer);
struct analyzer_pload_buffer *analyzer_pload_buffer_alloc(struct analyzer_pload_type *type, size_t expected_size, unsigned int flags);
int analyzer_pload_buffer_append(struct analyzer_pload_buffer *pload, void *data, size_t size);
int analyzer_pload_buffer_cleanup(struct analyzer_pload_buffer *pload);

struct analyzer_pload_type *analyzer_pload_type_get_by_name(char *name);
struct analyzer_pload_type *analyzer_pload_type_get_by_mime_type(char *mime_type);

int analyzer_pload_output_register(void *output_priv, struct analyzer_pload_output_reg *reg_info);
int analyzer_pload_output_unregister(void *output_priv);

void analyzer_pload_instance_set_priv(struct analyzer_pload_instance *pi, void *priv);
struct analyzer_pload_buffer *analyzer_pload_instance_get_buffer(struct analyzer_pload_instance *pi);

#endif
