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

#ifndef __POM_NG_PLOAD_H__
#define __POM_NG_PLOAD_H__

#define PLOAD_FLAG_NEED_MAGIC		0x01
#define PLOAD_FLAG_NEED_ANALYSIS	0x02
#define PLOAD_FLAG_IS_ERR		0x04
#define PLOAD_FLAG_OPENED		0x08

#define PLOAD_ANALYSIS_ERR	POM_ERR		// Something went wrong
#define PLOAD_ANALYSIS_OK	POM_OK		// All went ok
#define PLOAD_ANALYSIS_FAILED	(POM_OK + 1)	// Payload not recognized
#define PLOAD_ANALYSIS_MORE	(POM_OK + 2)	// More data is needed for the analysis

#define PLOAD_OPEN_CONTINUE	POM_OK		// Continue
#define PLOAD_OPEN_ERR		POM_ERR		// Something went wrong
#define PLOAD_OPEN_STOP		(POM_OK + 1)	// Payload is not interesting for the listener


#include <uthash.h>
#include <pom-ng/filter.h>
#include <pom-ng/event.h>
#include <pom-ng/mime.h>

enum pload_class {
	pload_class_unknown = 0,
	pload_class_application,
	pload_class_audio,
	pload_class_image,
	pload_class_video,
	pload_class_document,
};

struct pload;
struct pload_store;

struct pload_type {

	enum pload_class cls;
	char *name;
	char *extension;
	char *description;
	struct pload_analyzer *analyzer;
	struct pload_listener_reg *listeners;
	struct registry_instance *reg_instance;

	struct registry_perf *perf_analyzed;


	UT_hash_handle hh;
};


struct pload_buffer {

	void *data;
	size_t data_len; // Current ammount of data stored in the buffer
	size_t buf_size; // Current size of the buffer

};

struct pload_analyzer {

	void *priv;
	struct data_reg *data_reg;
	
	int (*analyze) (struct pload *p, struct pload_buffer *pb, void *priv);
	int (*cleanup) (struct pload *p, void *priv);

};


struct pload *pload_alloc(struct event *rel_event, int flags);
int pload_end(struct pload *p);

int pload_set_mime_type_str(struct pload *p, char *mime_type);
int pload_set_mime_type(struct pload *p, struct mime_type *mime_type);
struct mime_type *pload_get_mime_type(struct pload *p);
int pload_set_type(struct pload *p, char *type);
int pload_set_encoding(struct pload *p, char *encoding);
void pload_set_expected_size(struct pload *p, size_t size);
int pload_append(struct pload *p, void *data, size_t len);
struct event *pload_get_related_event(struct pload *p);
void pload_set_parent(struct pload* p, struct pload *parent);
void pload_set_analyzer_priv(struct pload *p, void *priv);
void *pload_get_analyzer_priv(struct pload *p);
int pload_set_analyzer(char *pload_type, struct pload_analyzer *analyzer);
struct data *pload_get_data(struct pload *p);
struct data_reg *pload_get_data_reg(struct pload *p);

int pload_listen_start(void *obj, char *pload_type, struct filter_node *filter, int (*open) (void *obj, void **priv, struct pload *pload), int (*write) (void *obj, void *priv, void *data, size_t len), int (*close) (void *obj, void *priv));
int pload_listen_stop(void *obj, char *pload_type);

void pload_refcount_inc(struct pload *pload);
void pload_refcount_dec(struct pload *pload);

struct pload_store *pload_store_get(struct pload *pload);
void pload_store_get_ref(struct pload_store *ps);
void pload_store_release(struct pload_store *ps);
struct pload *pload_store_get_pload(struct pload_store *ps);

struct pload_store_map *pload_store_read_start(struct pload_store *ps);
ssize_t pload_store_read(struct pload_store_map *map, void **buff, size_t count);
void pload_store_read_end(struct pload_store_map *map);

#endif
