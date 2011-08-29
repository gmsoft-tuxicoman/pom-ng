/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2011 Guy Martin <gmsoft@tuxicoman.be>
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
#include <pom-ng/proto.h>
#include <pom-ng/conntrack.h>
#include <pom-ng/output.h>

// Current analyzer API version
#define ANALYZER_API_VER 1


// Data flags
#define ANALYZER_DATA_FLAG_LIST 1

// Payload analyzer flags
#define ANALYZER_PLOAD_PROCESS_PARTIAL 0x1

// Payload buffer flags
#define ANALYZER_PLOAD_BUFFER_NEED_MAGIC 0x1

struct analyzer {

	struct analyzer_reg *info;
	void *priv;

	struct analyzer_event_reg *events;

	struct analyzer *prev, *next;

};

struct analyzer_event_reg {

	char *name;
	struct analyzer_data_reg *data;
	struct analyzer *analyzer;
	struct analyzer_event_listener_list *listeners;
	int (*listeners_notify) (struct analyzer *analyzer, struct analyzer_event_reg *evt_reg, int has_listeners);

	struct analyzer_event_reg *prev, *next;

};

struct analyzer_reg {

	unsigned int api_ver;
	char *name;
	struct mod_reg *mod;

	int (*init) (struct analyzer *analyzer);
	int (*cleanup) (struct analyzer *analyzer);

};


struct analyzer_event {
	struct analyzer_event_reg *info;
	struct analyzer_data *data;
};

struct analyzer_event_listener {
	void *obj;
	char *name;
	int (*process) (void *listener_obj, struct analyzer_event *evt);
};

typedef struct proto_event_data_item analyzer_data_item_t;

struct analyzer_data {
	
	union {
		struct ptype *value;
		analyzer_data_item_t *items;
	};
};


struct analyzer_data_reg {
	int flags;
	char *name;
	struct ptype *value_template;

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

struct analyzer_pload_type {

	enum analyzer_pload_class_id cls;
	char *name;
	char *description;
	char *extension;
	struct analyzer_pload_reg *analyzer;

	struct analyzer_pload_type *prev, *next;

};


struct analyzer_pload_mime_type {

	struct analyzer_pload_type *type;
	char *name;
	struct analyzer_pload_mime_type *prev, *next;
};

enum analyzer_pload_buffer_state {
	
	analyzer_pload_buffer_state_empty = 0,
	analyzer_pload_buffer_state_magic,
	analyzer_pload_buffer_state_partial,
	analyzer_pload_buffer_state_full,
	analyzer_pload_buffer_state_error,

};

struct analyzer_pload_buffer {

	struct analyzer_pload_type *type;
	size_t expected_size, buff_size;
	size_t buff_pos;

	void *buff;

	enum analyzer_pload_buffer_state state;
	unsigned int flags;

	struct analyzer_data *data;
	struct analyzer_event *rel_event;

};

struct analyzer_pload_reg {

	struct analyzer *analyzer;
	struct analyzer_data_reg *data;
	unsigned int flags;

	int (*process) (struct analyzer *analyzer, struct analyzer_pload_buffer *pload);

};

int analyzer_register(struct analyzer_reg *reg_info);
int analyzer_unregister(char *name);

struct analyzer_event_reg *analyzer_event_register(struct analyzer *analyzer, char *name, struct analyzer_data_reg *data, int (*listeners_notify) (struct analyzer *analyzer, struct analyzer_event_reg *evt_reg, int has_listeners));
struct analyzer_event_reg *analyzer_event_get(char *name);
int analyzer_event_process(struct analyzer_event *evt);
int analyzer_event_register_listener(struct analyzer_event_reg *evt, struct analyzer_event_listener *listener);
int analyzer_event_unregister_listener(struct analyzer_event_reg *evt, char *listener_name);
struct ptype *analyzer_event_data_item_add(struct analyzer_event *evt, unsigned int data_id, char *key);

int analyzer_pload_register(struct analyzer_pload_type *pt, struct analyzer_pload_reg *pload_analyzer);
struct analyzer_pload_buffer *analyzer_pload_buffer_alloc(struct analyzer_pload_type *type, size_t expected_size, unsigned int flags);
int analyzer_pload_buffer_append(struct analyzer_pload_buffer *pload, void *data, size_t size);
int analyzer_pload_buffer_cleanup(struct analyzer_pload_buffer *pload);

struct analyzer_pload_type *analyzer_pload_type_get_by_name(char *name);
struct analyzer_pload_type *analyzer_pload_type_get_by_mime_type(char *mime_type);


#endif
