/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2011-2015 Guy Martin <gmsoft@tuxicoman.be>
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

#define PLOAD_STORE_FLAG_OPENED		0x1
#define PLOAD_STORE_FLAG_COMPLETE	0x2

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

	pthread_mutex_t lock;

	struct pload_listener_ploads *ploads;

	struct pload_listener_reg *prev, *next;

};

struct pload_listener {

	struct pload_listener_reg *reg;

	struct priv *priv;

	struct pload_listener *prev, *next;

};

struct pload_listener_ploads {

	struct pload *p;
	UT_hash_handle hh;
};

struct pload_store_map {
	
	off_t off_start; // Offset from the start of the file
	off_t off_cur; // Offset from the start of the mapped area
	size_t map_size; // Size of the mapping
	void *map;

	struct pload_store *store; // Pload to which it belongs

	struct pload_store_map *prev, *next;

};

struct pload_store {
	
	char *filename;
	int fd;
	size_t file_size;

	unsigned int refcount;
	struct pload_store_map *write_map;
	struct pload_store_map *read_maps;

	struct event *rel_event;

	unsigned int flags;

	pthread_mutex_t lock;
	pthread_cond_t cond;

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
	void *analyzer_priv;
	struct pload_listener *listeners;
	struct pload *parent;
	uint32_t refcount;
	struct pload_store *store;
};

int pload_init();
void pload_cleanup();
void pload_thread_cleanup();

int pload_store_open_file(struct pload_store *ps);
int pload_store_open(struct pload_store *ps);
void pload_store_map_cleanup(struct pload_store_map *map);
void pload_store_end(struct pload_store *ps);

#endif
