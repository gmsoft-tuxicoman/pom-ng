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

#include "config.h"

#ifdef HAVE_ZLIB
#include <zlib.h>
#endif

#include "analyzer.h"
#include "output.h"
#include "mod.h"
#include "common.h"
#include <pom-ng/resource.h>
#include <pom-ng/ptype_string.h>

#include <libxml/parser.h>

#if 0
#define debug_analyzer(x ...) pomlog(POMLOG_DEBUG x)
#else
#define debug_analyzer(x ...)
#endif


#ifdef HAVE_LIBMAGIC
#include <magic.h>

static magic_t magic_cookie = NULL;

#endif

static struct analyzer *analyzer_head = NULL;
static pthread_mutex_t analyzer_lock = PTHREAD_MUTEX_INITIALIZER;

static struct analyzer_pload_type *analyzer_pload_types = NULL;
static struct analyzer_pload_mime_type *analyzer_pload_mime_types = NULL;

static struct analyzer_pload_output *analyzer_pload_outputs = NULL;


static struct analyzer_pload_class pload_class_def[ANALYZER_PLOAD_CLASS_COUNT] = {
	{ "other", "Unclassified payload class" },
	{ "application", "Application files" },
	{ "audio", "Audio files and streams" },
	{ "image", "Images files" },
	{ "video", "Video files and streams" },
	{ "document", "Document files" },

};

static struct datavalue_template analyzer_payload_types_template[] = {
	{ .name = "name", .type = "string" },
	{ .name = "description", .type = "string" },
	{ .name = "extension", .type = "string" },
	{ .name = "class", .type = "string" },
	{ 0 }
};

static struct datavalue_template analyzer_mime_types_template[] = {
	{ .name = "name", .type = "string" },
	{ .name = "mime", .type = "string" },
	{ 0 }
};

static struct resource_template analyzer_mime_template[] = {
	{ "payload_types", analyzer_payload_types_template },
	{ "mime_types", analyzer_mime_types_template },
	{ 0 }
};


int analyzer_init() {

#ifdef HAVE_LIBMAGIC
	magic_cookie = magic_open(MAGIC_MIME);
	if (!magic_cookie) {
		pomlog(POMLOG_ERR "Error while allocating the magic cookie");
		return POM_ERR;
	}

	if (magic_load(magic_cookie, NULL)) {
		pomlog(POMLOG_ERR "Error while loading the magic database : %s", magic_error(magic_cookie));
		return POM_ERR;
	}
#endif

	struct resource *r = NULL;
	struct resource_dataset *pload_types = NULL, *mime_types = NULL;
	
	r = resource_open("payload_types", analyzer_mime_template);
	if (!r)
		goto err;

	pload_types = resource_dataset_open(r, "payload_types");
	if (!pload_types)
		goto err;

	while (1) {
		struct datavalue *v = NULL;
		int res = resource_dataset_read(pload_types, &v);
		if (res == DATASET_QUERY_OK)
			break;

		if (res < 0) {
			pomlog(POMLOG_ERR "Error while reading payload_types resource");
			goto err;
		}

		struct analyzer_pload_type *def = malloc(sizeof(struct analyzer_pload_type));
		if (!def) {
			pom_oom(sizeof(struct analyzer_pload_type));
			goto err;
		}
		memset(def, 0, sizeof(struct analyzer_pload_type));

		char *cls_name = PTYPE_STRING_GETVAL(v[3].value);
		int cls_id;
		for (cls_id = 0; cls_id < ANALYZER_PLOAD_CLASS_COUNT && strcmp(pload_class_def[cls_id].name, cls_name); cls_id++);
		if (cls_id >= ANALYZER_PLOAD_CLASS_COUNT) {
			pomlog(POMLOG_WARN "Class %s does not exists", cls_name);
			free(def);
			continue;
		}

		def->name = strdup(PTYPE_STRING_GETVAL(v[0].value));
		def->description = strdup(PTYPE_STRING_GETVAL(v[1].value));
		def->extension = strdup(PTYPE_STRING_GETVAL(v[2].value));
		def->cls = cls_id;

		if (!def->name || !def->description || !def->extension) {
			pom_oom(strlen(PTYPE_STRING_GETVAL(v[0].value)));
			if (def->name)
				free(def->name);
			if (def->description)
				free(def->description);
			if (def->extension)
				free(def->extension);
			free(def);
			goto err;
		}

		def->next = analyzer_pload_types;
		if (def->next)
			def->next->prev = def;
		analyzer_pload_types = def;

		pomlog(POMLOG_DEBUG "Registered payload type %s : class %s, extension .%s", def->name, pload_class_def[def->cls].name, def->extension);

	}

	resource_dataset_close(pload_types);
	pload_types = NULL;

	mime_types = resource_dataset_open(r, "mime_types");
	if (!mime_types)
		goto err;

	while (1) {
		struct datavalue *v = NULL;
		int res = resource_dataset_read(mime_types, &v);
		if (res == DATASET_QUERY_OK)
			break;

		if (res < 0) {
			pomlog(POMLOG_ERR "Error while reading mime_types resource");
			goto err;
		}

		char *name = PTYPE_STRING_GETVAL(v[0].value);

		struct analyzer_pload_type *defs = analyzer_pload_types;
		for (; defs && strcmp(defs->name, name); defs = defs->next);
		if (!defs) {
			pomlog(POMLOG_WARN "Definition %s not known", name);
			continue;
		}

		struct analyzer_pload_mime_type *type = malloc(sizeof(struct analyzer_pload_mime_type));
		if (!type) {
			pom_oom(sizeof(struct analyzer_pload_mime_type));
			goto err;
		}
		memset(type, 0, sizeof(struct analyzer_pload_mime_type));

		type->type = defs;
		type->name = strdup(PTYPE_STRING_GETVAL(v[1].value));
		if (!type->name) {
			free(type);
			pom_oom(strlen(PTYPE_STRING_GETVAL(v[1].value)) + 1);
			goto err;
		}
		type->next = analyzer_pload_mime_types;
		if (type->next)
			type->next->prev = type;
		analyzer_pload_mime_types = type;

		pomlog(POMLOG_DEBUG "Mime type %s registered as %s", type->name, type->type->name);

	}

	resource_dataset_close(mime_types);
	resource_close(r);


	return POM_OK;

err:

	if (mime_types)
		resource_dataset_close(mime_types);

	if (pload_types)
		resource_dataset_close(pload_types);

	if (r)
		resource_close(r);

#ifdef HAVE_LIBMAGIC
	magic_close(magic_cookie);
#endif

	return POM_ERR;
}

int analyzer_register(struct analyzer_reg *reg_info) {

	if (reg_info->api_ver != ANALYZER_API_VER) {
		pomlog(POMLOG_ERR "Cannot register analyzer as API version differ : expected %u got %u", ANALYZER_API_VER, reg_info->api_ver);
		return POM_ERR;
	}

	pom_mutex_lock(&analyzer_lock);

	// Allocate the analyzer
	struct analyzer *analyzer = malloc(sizeof(struct analyzer));
	if (!analyzer) {
		pom_mutex_unlock(&analyzer_lock);
		pom_oom(sizeof(struct analyzer));
		return POM_ERR;
	}
	memset(analyzer, 0, sizeof(struct analyzer));
	analyzer->info = reg_info;

	if (reg_info->init) {
		if (reg_info->init(analyzer) != POM_OK) {
			pom_mutex_unlock(&analyzer_lock);
			free(analyzer);
			pomlog(POMLOG_ERR "Error while initializing analyzer %s", reg_info->name);
			return POM_ERR;
		}
	}

	analyzer->next = analyzer_head;
	if (analyzer->next)
		analyzer->next->prev = analyzer;
	analyzer_head = analyzer;
	pom_mutex_unlock(&analyzer_lock);
	
	mod_refcount_inc(reg_info->mod);

	pomlog(POMLOG_DEBUG "Analyzer %s registered", reg_info->name);

	return POM_OK;
}

int analyzer_unregister(char *name) {

	pom_mutex_lock(&analyzer_lock);
	struct analyzer *tmp;
	for (tmp = analyzer_head; tmp && strcmp(tmp->info->name, name); tmp = tmp->next);

	if (!tmp) {
		pom_mutex_unlock(&analyzer_lock);
		return POM_OK;
	}

	if (tmp->info->cleanup) {
		if (tmp->info->cleanup(tmp) != POM_OK) {
			pomlog(POMLOG_ERR "Error while cleaning up analyzer %s", name);
			return POM_ERR;
		}
	}

	if (tmp->prev)
		tmp->prev->next = tmp->next;
	else
		analyzer_head = tmp->next;

	if (tmp->next)
		tmp->next->prev = tmp->prev;

	mod_refcount_dec(tmp->info->mod);
	
	free(tmp);

	pom_mutex_unlock(&analyzer_lock);

	return POM_OK;
}

int analyzer_cleanup() {
	
	pom_mutex_lock(&analyzer_lock);

	while (analyzer_head) {

		struct analyzer *tmp = analyzer_head;
		analyzer_head = tmp->next;

		if (tmp->info->cleanup) {
			if (tmp->info->cleanup(tmp))
				pomlog(POMLOG_WARN "Error while cleaning up analyzer %s", tmp->info->name);
		}

		mod_refcount_dec(tmp->info->mod);

		free(tmp);
	}

	pom_mutex_unlock(&analyzer_lock);

	while (analyzer_pload_types) {
		struct analyzer_pload_type *tmp = analyzer_pload_types;
		analyzer_pload_types = tmp->next;

		free(tmp->name);
		free(tmp->description);
		free(tmp->extension);
		free(tmp);
	}

	while (analyzer_pload_mime_types) {
		struct analyzer_pload_mime_type *tmp = analyzer_pload_mime_types;
		analyzer_pload_mime_types = tmp->next;
		free(tmp->name);
		free(tmp);
	}

#ifdef HAVE_LIBMAGIC
	magic_close(magic_cookie);
#endif

	return POM_OK;

}


int analyzer_pload_register(struct analyzer_pload_type *pt, struct analyzer_pload_reg *pload_analyzer) {

	if (!pt || !pload_analyzer)
		return POM_ERR;

	if (pt->analyzer) {
		pomlog(POMLOG_ERR "Payload %s already has an analyzer registered", pt->name);
		return POM_ERR;
	}

	pt->analyzer = pload_analyzer;

	return POM_OK;
}


struct analyzer_pload_buffer *analyzer_pload_buffer_alloc(struct analyzer_pload_type *type, size_t expected_size, unsigned int flags) {

	struct analyzer_pload_buffer *pload = malloc(sizeof(struct analyzer_pload_buffer));
	if (!pload) {
		pom_oom(sizeof(struct analyzer_pload_buffer));
		return NULL;
	}
	memset(pload, 0, sizeof(struct analyzer_pload_buffer));
	
	debug_analyzer(POMLOG_DEBUG "Got new pload of type %s", (type ? type->name : "unknown"));

	pload->expected_size = expected_size;
	pload->type = type;
	pload->flags = flags;

	return pload;

}

static int analyzer_pload_buffer_grow(struct analyzer_pload_buffer *pload) {

	long pagesize = sysconf(_SC_PAGESIZE);
	if (!pagesize)
		pagesize = 4096;

	size_t new_size = pload->buff_size + pagesize;

	void *new_buff = realloc(pload->buff, new_size);
	if (!new_buff) {
		pom_oom(new_size);
		pomlog(POMLOG_ERR "Could not allocate enough memory to hold the buffer");
		pload->state = analyzer_pload_buffer_state_error;
		return POM_ERR;
	}

	pload->buff = new_buff;
	pload->buff_size = new_size;
	return POM_OK;
}

static int analyzer_pload_buffer_append_to_buff(struct analyzer_pload_buffer *pload, void *data, size_t size) {

	if (!pload->buff_size) {
		size_t alloc_size = (pload->expected_size > 65535 ? 65535 : pload->expected_size);
		pload->buff_size = alloc_size;
		pload->buff = malloc(pload->expected_size);
		if (!pload->buff) {
			pom_oom(pload->expected_size);
			pload->state = analyzer_pload_buffer_state_error;
			return POM_ERR;
		}
	}

#ifdef HAVE_ZLIB
	
	if (pload->zbuff) {
		// Handle zlib compression
		pload->zbuff->next_in = data;
		pload->zbuff->avail_in = size;
		pload->zbuff->avail_out = pload->buff_size - pload->buff_pos;

		do {

			if (!pload->zbuff->avail_out) {
				if (analyzer_pload_buffer_grow(pload) != POM_OK)
					return POM_OK;
				pload->zbuff->avail_out = pload->buff_size - pload->buff_pos;
			}
			pload->zbuff->next_out = pload->buff + pload->buff_pos;

			int res = inflate(pload->zbuff, Z_SYNC_FLUSH);
			if (res == Z_STREAM_END) {
				inflateEnd(pload->zbuff);
				free(pload->zbuff);
				pload->zbuff = NULL;
				break;
			} else if (res != Z_OK) {
				char *msg = pload->zbuff->msg;
				if (!msg)
					msg = "Unknown error";
				pomlog(POMLOG_DEBUG "Error while uncompressing the gzip content : %s", msg);
				pload->state = analyzer_pload_buffer_state_error;
				inflateEnd(pload->zbuff);
				free(pload->zbuff);
				pload->zbuff = NULL;
				return POM_OK;
			}

		} while (pload->zbuff->avail_in);

	} else {
#endif /* HAVE_ZLIB */

		// Uncompressed stuff
		if (pload->buff_size < pload->buff_pos + size) {
			// Buffer is too small, add a page
			if (analyzer_pload_buffer_grow(pload) != POM_OK)
				return POM_OK;
		}

		memcpy(pload->buff + pload->buff_pos, data, size);
		pload->buff_pos += size;

#ifdef HAVE_ZLIB
	}
#endif

	return POM_OK;
}

int analyzer_pload_buffer_append(struct analyzer_pload_buffer *pload, void *data, size_t size) {

	if (pload->state == analyzer_pload_buffer_state_error || pload->state == analyzer_pload_buffer_state_done) {
		// Don't process payloads which encountered an error or which do not need additional processing
		if (pload->buff_size) {
			// Remove the buffer if still present
			pload->buff_size = 0;
			pload->buff_pos = 0;
			free(pload->buff);
			pload->buff = NULL;
		}
		return POM_OK;
	}

	if (pload->state == analyzer_pload_buffer_state_empty) {
		if (pload->flags & (ANALYZER_PLOAD_BUFFER_IS_GZIP | ANALYZER_PLOAD_BUFFER_IS_DEFLATE)) {
#ifdef HAVE_ZLIB
			pload->zbuff = malloc(sizeof(z_stream));
			if (!pload->zbuff) {
				pom_oom(sizeof(z_stream));
				pload->state = analyzer_pload_buffer_state_error;
				return POM_OK;
			}
			memset(pload->zbuff, 0, sizeof(z_stream));
			int window_bits = 15 + 32; // 15, default window bits. 32, magic value to enable header detection
			if (pload->flags & ANALYZER_PLOAD_BUFFER_IS_DEFLATE)
				window_bits = -15; // Raw data

			if (inflateInit2(pload->zbuff, window_bits) != Z_OK) {
				if (pload->zbuff->msg)
					pomlog(POMLOG_ERR "Unable to init Zlib : %s", pload->zbuff->msg);
				else
					pomlog(POMLOG_ERR "Unable to init Zlib : Unknown error");
				free(pload->zbuff);
				pload->zbuff = NULL;

				pload->state = analyzer_pload_buffer_state_error;
				return POM_OK;
			}

#else /* HAVE_ZLIB */
			pomlog(POMLOG_DEBUG "Got a zlib compressed payload but no zlib support. Ignoring");
			pload->state = analyzer_pload_buffer_state_done;
			return POM_OK;
#endif /* HAVE_ZLIB */

		} else if (pload->flags & ANALYZER_PLOAD_BUFFER_IS_BASE64) {
			pomlog(POMLOG_DEBUG "Got a base64 payload but no support for that encoding yet");
			pload->state = analyzer_pload_buffer_state_done;
			return POM_OK;
		} else {
			// Use the current data as the buffer
			pload->buff_pos = size;
			pload->buff = data;
		}


		// We need to allocate the buffer for this payload
#ifdef HAVE_LIBMAGIC
		pload->state = analyzer_pload_buffer_state_magic;
#else
		pload->state = analyzer_pload_buffer_state_partial;
#endif

	}

	if (pload->buff_size) { // There is a buffer, we need to append data to the current buffer
		if (analyzer_pload_buffer_append_to_buff(pload, data, size) != POM_OK)
			return POM_ERR;
	}

#ifdef HAVE_LIBMAGIC
	if (pload->state == analyzer_pload_buffer_state_magic) {
		// We need to perform some magic
		if (pload->buff_pos > ANALYZER_PLOAD_BUFFER_MAGIC_MIN_SIZE || (pload->expected_size && pload->expected_size < ANALYZER_PLOAD_BUFFER_MAGIC_MIN_SIZE)) {
			// We have enough to perform some magic
			

			// libmagic is no thread safe ...
			static pthread_mutex_t magic_lock = PTHREAD_MUTEX_INITIALIZER;
			pom_mutex_lock(&magic_lock);

			char *magic_mime_type = (char*) magic_buffer(magic_cookie, pload->buff, pload->buff_pos);

			if (!magic_mime_type) {
				pomlog(POMLOG_ERR "Error while proceeding with magic : %s", magic_error(magic_cookie));
				pload->state = analyzer_pload_buffer_state_error;
				pom_mutex_unlock(&magic_lock);
				return POM_ERR;
			}
			struct analyzer_pload_type *magic_pload_type = analyzer_pload_type_get_by_mime_type(magic_mime_type);

			// If magic found something different, use that instead
			if (magic_pload_type && (magic_pload_type != pload->type)) {
				debug_analyzer(POMLOG_DEBUG "Fixed payload type to %s according to libmagic", magic_mime_type);
				pload->type = magic_pload_type;
			}

			pom_mutex_unlock(&magic_lock);

			pload->state = analyzer_pload_buffer_state_partial;
		} else {
			if (!pload->buff_size) {
				// Not enough data. We need to buffer what we have
				pload->buff = NULL;
				pload->buff_pos = 0;
				return analyzer_pload_buffer_append_to_buff(pload, data, size);
			} else {
				// We already appended the data
				return POM_OK;
			}
		}
	}


#endif

	if (pload->state == analyzer_pload_buffer_state_partial) {
		// If we know what type of payload we are dealing with, try to analyze it
		if (pload->type && pload->type->analyzer) {

			struct analyzer_pload_reg *pload_analyzer = pload->type->analyzer;

			// Have the analyzer look at the payload
			// The analyzer will either leave the state as it is or change it to error or analyzed
			if ((pload_analyzer->flags & ANALYZER_PLOAD_PROCESS_PARTIAL) || (pload->expected_size && (pload->buff_pos >= pload->expected_size))) {

				// Allocate the pload data
				if (!pload->data && pload_analyzer->data_reg) {
					pload->data = data_alloc_table(pload_analyzer->data_reg);
					if (!pload->data) {
						pload->state = analyzer_pload_buffer_state_error;		
						return POM_OK;
					}
				}

				if (pload_analyzer->process(pload_analyzer->analyzer, pload) != POM_OK) {
					// The analyzer enountered an error. Not sure what is the best course of action here.
					pomlog(POMLOG_DEBUG "Error while analyzing pload of type %s", pload->type->name);

					// For now, remove the type from the payload
					pload->type = NULL;
				}
	
				if (!pload->type) {
					// The analyzer did not recognize the payload, nothing more to do
					pload->state = analyzer_pload_buffer_state_analyzed;

					if (pload->data) {
						data_cleanup_table(pload->data, pload_analyzer->data_reg);
						pload->data = NULL;
					}
				} else if (pload->state == analyzer_pload_buffer_state_partial) {
					// The analyzer need more data
					if (!pload->buff_size) {
						pload->buff = NULL;
						pload->buff_pos = 0;
						return analyzer_pload_buffer_append_to_buff(pload, data, size);
					} else {
						// We already appended the data
						return POM_OK;
					}
				}

			} else {
				// The analyzer needs the full buffer
				if (!pload->buff_size) {
					// Not enough data. We need to buffer what we have
					pload->buff = NULL;
					pload->buff_pos = 0;
					return analyzer_pload_buffer_append_to_buff(pload, data, size);
				} else {
					// We already appended the data
					return POM_OK;
				}
			}
		

		} else {
			// Nothing to analyze
			pload->state = analyzer_pload_buffer_state_analyzed;
		}


	}

	if (pload->state == analyzer_pload_buffer_state_analyzed) {
		if (!pload->output_list) {
			// Try to send this payload to all the outputs
			// TODO filtering
			struct analyzer_pload_output *tmp;
			for (tmp = analyzer_pload_outputs; tmp; tmp = tmp->next) {

				struct analyzer_pload_instance *lst = malloc(sizeof(struct analyzer_pload_instance));
				if (!lst) {
					pom_oom(sizeof(struct analyzer_pload_instance));
					// Error is not fatal
					return POM_OK;
				}
				memset(lst, 0, sizeof(struct analyzer_pload_instance));
				lst->o = tmp;
				lst->pload = pload;

				if (tmp->reg_info->open(lst, tmp->output_priv)) {
					// Either the pload is not needed or their was an error
					lst->is_err = 1;
				}

				lst->next = pload->output_list;
				if (lst->next)
					lst->next->prev = lst;

				pload->output_list = lst;

			}
			if (!pload->output_list) {
				pload->state = analyzer_pload_buffer_state_done;
				if (pload->buff_size) 
					free(pload->buff);
				
				pload->buff = NULL;
				pload->buff_size = 0;
				pload->buff_pos = 0;
				return POM_OK;
			}

		}

		struct analyzer_pload_instance *lst;
		for (lst = pload->output_list; lst; lst = lst->next) {
			if (lst->is_err)
				continue;
			int res;
			if (pload->buff_size) {
				res = lst->o->reg_info->write(lst->priv, pload->buff, pload->buff_pos);
			} else {
				res = lst->o->reg_info->write(lst->priv, data, size);
			}
			if (res != POM_OK) {
				pomlog(POMLOG_ERR "Error while writing to an output");
				lst->o->reg_info->close(lst->priv);
				lst->is_err = 1;
				continue;
			}

		}

		if (pload->buff_size) {
			// The buffer was written, we can safely get rid of it
			pload->buff_size = 0;
			free(pload->buff);
			pload->buff = NULL;

		}
	}

	return POM_OK;

}

int analyzer_pload_buffer_cleanup(struct analyzer_pload_buffer *pload) {

	if (pload->type && pload->type->analyzer) {

		struct analyzer_pload_reg *pload_analyzer = pload->type->analyzer;
		if (pload_analyzer->cleanup) {
			if (pload_analyzer->cleanup(pload_analyzer->analyzer, pload) != POM_OK)
				pomlog(POMLOG_WARN "Error while cleaning up payload buffer of type %s", pload->type->name);
		}

		if (pload->data) {
			data_cleanup_table(pload->data, pload_analyzer->data_reg);
			pload->data = NULL;
		}

	}

	while (pload->output_list) {
		struct analyzer_pload_instance *lst = pload->output_list;
		if (!lst->is_err && lst->o->reg_info->close(lst->priv) != POM_OK)
			pomlog(POMLOG_WARN "Error while closing payload");
		
		pload->output_list = lst->next;
		free(lst);

	}
#ifdef HAVE_ZLIB
	if (pload->zbuff) {
		inflateEnd(pload->zbuff);
		free(pload->zbuff);
	}
#endif
	if (pload->buff_size && pload->buff)
		free(pload->buff);

	free(pload);

	return POM_OK;
}

struct analyzer_pload_type *analyzer_pload_type_get_by_name(char *name) {

	struct analyzer_pload_type *tmp;
	for (tmp = analyzer_pload_types; tmp && strcmp(tmp->name, name); tmp = tmp->next);
	
	return tmp;

}

struct analyzer_pload_type *analyzer_pload_type_get_by_mime_type(char *mime_type) {

	if (!mime_type)
		return NULL;

	size_t len;
	char *end = strchr(mime_type, ';');
	if (end)
		len = end - mime_type;
	else
		len = strlen(mime_type);

	if (!len)
		return NULL;

	while (*mime_type == ' ')
		mime_type++;
	while (*(mime_type + len - 1) == ' ' && len >= 0)
		len--;


	struct analyzer_pload_mime_type *tmp;
	for (tmp = analyzer_pload_mime_types; tmp && strncmp(tmp->name, mime_type, len); tmp = tmp->next);

	if (tmp)
		return tmp->type;

	return NULL;
}


int analyzer_pload_output_register(void *output_priv, struct analyzer_pload_output_reg *reg_info) {


	struct analyzer_pload_output *po = malloc(sizeof(struct analyzer_pload_output));
	if (!po) {
		pom_oom(sizeof(struct analyzer_pload_output));
		return POM_ERR;
	}
	memset(po, 0, sizeof(struct analyzer_pload_output));

	po->reg_info = reg_info;
	po->output_priv = output_priv;

	po->next = analyzer_pload_outputs;
	if (po->next)
		po->next->prev = po;

	analyzer_pload_outputs = po;

	return POM_OK;

}


int analyzer_pload_output_unregister(void *output_priv) {

	struct analyzer_pload_output *po = analyzer_pload_outputs;
	for (; po && po->output_priv != output_priv; po = po->next);

	if (!po) {
		pomlog(POMLOG_ERR "Payload output not found in the list of registered outputs");
		return POM_ERR;
	}

	if (po->prev)
		po->prev->next = po->next;
	else
		analyzer_pload_outputs = po->next;
	
	if (po->next)
		po->next->prev = po->prev;

	free(po);

	return POM_OK;
}

void analyzer_pload_instance_set_priv(struct analyzer_pload_instance *pi, void *priv) {
	pi->priv = priv;
}

struct analyzer_pload_buffer *analyzer_pload_instance_get_buffer(struct analyzer_pload_instance *pi) {
	return pi->pload;
}
