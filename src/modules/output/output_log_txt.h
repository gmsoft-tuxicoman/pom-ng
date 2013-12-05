/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2011-2013 Guy Martin <gmsoft@tuxicoman.be>
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

#ifndef __OUTPUT_LOG_TXT_H__
#define __OUTPUT_LOG_TXT_H__

#include "output_log.h"

#define OUTPUT_LOG_TXT_RESOURCE "output_log_txt"

enum output_log_txt_field_type {
	output_log_txt_event_field,
	output_log_txt_event_property
};

enum output_log_txt_event_property {
	output_log_txt_event_property_ts,
	output_log_txt_event_property_name,
	output_log_txt_event_property_source_name,
	output_log_txt_event_property_description
};

struct output_log_txt_field {
	enum output_log_txt_field_type type;
	int id;
	unsigned int start_off, end_off;
	char *key;
	char *ptype_format;
};

struct output_log_txt_file {
	char *name;
	char *path;
	int fd;
	pthread_mutex_t lock;
	struct output_log_txt_file *prev, *next;
};

struct output_log_txt_event {
	struct event_reg *evt;
	struct ptype *p_prefix;
	struct output_log_txt_priv *priv;

	char *format;
	
	struct output_log_txt_field *fields;

	struct output_log_txt_event *prev, *next;
	struct output_log_txt_file *file;
};

struct output_log_txt_priv {
	struct ptype *p_prefix;
	struct ptype *p_template;

	struct output_log_txt_file *files;
	struct output_log_txt_event *events;

	struct registry_perf *perf_events;
};

struct addon_log_txt_priv {
	struct ptype *p_filename;
	struct ptype *p_event;
	struct ptype *p_format;

	struct output_log_txt_event txt_evt;
	struct output_log_txt_file txt_file;
};

int output_log_txt_init(struct output *o);
int output_log_txt_open(void *output_priv);
int output_log_txt_close(void *output_priv);
int output_log_txt_cleanup(void *output_priv);
int output_log_txt_process(struct event *evt, void *obj);

int addon_log_txt_init(struct addon_plugin *a);
int addon_log_txt_cleanup(void *addon_priv);
int addon_log_txt_open(void *addon_priv);
int addon_log_txt_close(void *addon_priv);
int addon_log_txt_process(struct event *evt, void *addon_priv);

#endif
