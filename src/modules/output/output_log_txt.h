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

#ifndef __OUTPUT_LOG_TXT_H__
#define __OUTPUT_LOG_TXT_H__

#include "output_log.h"

#define OUTPUT_LOG_TXT_RESOURCE "output_log_txt"

struct output_log_txt_event_field {
	int id;
	uint32_t hash;
	unsigned int start_off, end_off;
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
	struct event_listener listener;
	struct output_log_txt_priv *output_priv;

	char *format;
	
	struct output_log_txt_event_field *fields;
	unsigned int field_count;

	struct output_log_txt_event *prev, *next;
	struct output_log_txt_file *file;
};

struct output_log_txt_priv {
	struct ptype *p_prefix;
	struct ptype *p_template;

	struct output_log_txt_file *files;
	struct output_log_txt_event *events;

};

int output_log_txt_init(struct output *o);
int output_log_txt_open(struct output *o);
int output_log_txt_close(struct output *o);
int output_log_txt_cleanup(struct output *o);
int output_log_txt_process(struct event *evt, void *obj);


#endif
