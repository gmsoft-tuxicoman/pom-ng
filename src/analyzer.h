/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2011-2014 Guy Martin <gmsoft@tuxicoman.be>
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


#ifndef __ANALYZER_H__
#define __ANALYZER_H__

#include <pom-ng/analyzer.h>

#define ANALYZER_REGISTRY "analyzer"

// We require at least that ammount of bytes before passing the buffer to libmagic
#define ANALYZER_PLOAD_BUFFER_MAGIC_MIN_SIZE 64

struct analyzer_event_listener_list {

	struct analyzer_event_listener *listener;
	struct analyzer_event_listener_list *prev, *next;

};


struct analyzer_pload_mime_type {

	struct analyzer_pload_type *type;
	char *name;
	struct analyzer_pload_mime_type *prev, *next;
};

struct analyzer_pload_output {

	void *output_priv;
	struct analyzer_pload_output_reg *reg_info;

	struct analyzer_pload_output *prev, *next;

};

struct analyzer_pload_instance {

	struct analyzer_pload_output *o;
	struct analyzer_pload_buffer *pload;
	int is_err;

	void *priv;
	void *output_priv;

	struct analyzer_pload_instance *prev, *next;
	
};

struct analyzer_pload_buffer {

	struct analyzer_pload_type *type;
	struct mime_type *mime_type;
	size_t expected_size, buff_size;
	size_t buff_pos;
	struct analyzer_pload_buffer *container;

	void *buff;

	enum analyzer_pload_buffer_state state;
	unsigned int flags;

	struct data *data;
	struct event *rel_event;
	struct analyzer_pload_instance *output_list;
	void *analyzer_priv;

	struct decoder *decoder;

};

int analyzer_init();
int analyzer_cleanup();
int analyzer_finish();
int analyzer_pload_output(struct analyzer_pload_buffer *pload);

#endif
