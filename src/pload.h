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

#ifndef __PLOAD_H__
#define __PLOAD_H__

#include <pom-ng/event.h>
#include <pom-ng/pload.h>
#include <pom-ng/mime.h>
#include <pom-ng/decoder.h>

#define PLOAD_REGISTRY "payload"

struct pload_mime_type {
	char *name;
	struct pload_type *type;
	UT_hash_handle hh;
	struct pload_mime_type *next;
};

struct pload_listener_reg {

	void *obj;
	struct filter_node *filter;

	int (*open) (void *obj, void **priv, struct pload *pload);
	int (*write) (void *obj, void *priv, void *data, size_t len);
	int (*close) (void *obj, void *priv);

	struct pload_listener_reg *prev, *next;

};

struct pload_listener {

	struct pload_listener_reg *reg;

	struct priv *priv;

	struct pload_listener *prev, *next;

};


// Hold information about a payload
struct pload {
	
	int flags;

	struct pload_buffer buf;
	struct mime_type *mime_type;
	struct pload_type *type;
	struct decoder *decoder;
	size_t expected_size;
	struct event *rel_event;
	struct data *data;
	void *priv;
	struct pload_listener *listeners;
	struct pload *parent;
	uint32_t refcount;
};

int pload_init();
void pload_cleanup();
void pload_thread_cleanup();


#endif
