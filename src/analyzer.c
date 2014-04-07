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

#include "config.h"

#include "analyzer.h"
#include "output.h"
#include "mod.h"
#include "common.h"
#include "registry.h"
#include <pom-ng/resource.h>
#include <pom-ng/ptype_string.h>
#include <pom-ng/mime.h>
#include <pom-ng/decoder.h>

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

static struct analyzer_pload_type *analyzer_pload_types = NULL;
static struct analyzer_pload_mime_type *analyzer_pload_mime_types = NULL;

static struct analyzer_pload_output *analyzer_pload_outputs = NULL;

static struct registry_class *analyzer_registry_class = NULL;


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

static char *analyzer_noop_decoders[] = {
	"7bit",
	"8bit",
	"binary",
	NULL
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

	analyzer_registry_class = registry_add_class(ANALYZER_REGISTRY);
	if (!analyzer_registry_class)
		return POM_ERR;

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

	if (analyzer_registry_class) {
		registry_remove_class(analyzer_registry_class);
		analyzer_registry_class = NULL;
	}

	return POM_ERR;
}

int analyzer_register(struct analyzer_reg *reg_info) {

	// Allocate the analyzer
	struct analyzer *analyzer = malloc(sizeof(struct analyzer));
	if (!analyzer) {
		pom_oom(sizeof(struct analyzer));
		return POM_ERR;
	}
	memset(analyzer, 0, sizeof(struct analyzer));
	analyzer->info = reg_info;

	analyzer->reg_instance = registry_add_instance(analyzer_registry_class, reg_info->name);
	if (!analyzer->reg_instance) {
		free(analyzer);
		return POM_ERR;
	}

	if (reg_info->init) {
		if (reg_info->init(analyzer) != POM_OK) {
			registry_remove_instance(analyzer->reg_instance);
			free(analyzer);
			pomlog(POMLOG_ERR "Error while initializing analyzer %s", reg_info->name);
			return POM_ERR;
		}
	}

	analyzer->next = analyzer_head;
	if (analyzer->next)
		analyzer->next->prev = analyzer;
	analyzer_head = analyzer;
	
	mod_refcount_inc(reg_info->mod);

	pomlog(POMLOG_DEBUG "Analyzer %s registered", reg_info->name);

	return POM_OK;
}

int analyzer_unregister(char *name) {

	struct analyzer *tmp;
	for (tmp = analyzer_head; tmp && strcmp(tmp->info->name, name); tmp = tmp->next);

	if (!tmp)
		return POM_OK;

	if (tmp->info->cleanup) {
		if (tmp->info->cleanup(tmp) != POM_OK) {
			pomlog(POMLOG_ERR "Error while cleaning up analyzer %s", name);
			return POM_ERR;
		}
	}

	registry_remove_instance(tmp->reg_instance);

	if (tmp->prev)
		tmp->prev->next = tmp->next;
	else
		analyzer_head = tmp->next;

	if (tmp->next)
		tmp->next->prev = tmp->prev;

	mod_refcount_dec(tmp->info->mod);
	
	free(tmp);

	return POM_OK;
}

int analyzer_cleanup() {
	
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

	registry_remove_class(analyzer_registry_class);
	analyzer_registry_class = NULL;

	return POM_OK;

}

int analyzer_finish() {

	struct analyzer *tmp;
	for (tmp = analyzer_head; tmp; tmp = tmp->next) {
		if (tmp->info->finish && tmp->info->finish(tmp) != POM_OK)
			pomlog(POMLOG_WARN "Error while running the finish() function of analyzer %s", tmp->info->name);
	}

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


struct analyzer_pload_buffer *analyzer_pload_buffer_alloc(size_t expected_size, unsigned int flags) {

	struct analyzer_pload_buffer *pload = malloc(sizeof(struct analyzer_pload_buffer));
	if (!pload) {
		pom_oom(sizeof(struct analyzer_pload_buffer));
		return NULL;
	}
	memset(pload, 0, sizeof(struct analyzer_pload_buffer));
	
	debug_analyzer(POMLOG_DEBUG "Got new pload of type %s", (type ? type->name : "unknown"));

	pload->expected_size = expected_size;
	pload->flags = flags;

	return pload;

}

static int analyzer_pload_buffer_grow(struct analyzer_pload_buffer *pload) {

	size_t growsize = sysconf(_SC_PAGESIZE);
	if (!growsize)
		growsize = 4096;

	size_t new_size = pload->buff_size + growsize;

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

	if (!pload->buff_size && pload->expected_size) {
		size_t alloc_size = (pload->expected_size > 65535 ? 65535 : pload->expected_size);
		pload->buff_size = alloc_size;
		pload->buff = malloc(pload->expected_size);
		if (!pload->buff) {
			pom_oom(pload->expected_size);
			pload->state = analyzer_pload_buffer_state_error;
			pload->buff_size = 0;
			return POM_ERR;
		}
	}

	if (pload->decoder) {
		// Handle decoding

		if (!pload->buff_size) {
			size_t len = decoder_estimate_output_size(pload->decoder, size);
			pload->buff = malloc(len);
			if (!pload->buff) {
				pom_oom(len);
				return POM_ERR;
			}
			pload->buff_size = len;
		}

		pload->decoder->next_in = data;
		pload->decoder->avail_in = size;
		pload->decoder->avail_out = pload->buff_size - pload->buff_pos;
		
		int res;

		while (1) {

			pload->decoder->next_out = pload->buff + pload->buff_pos;

			res = decoder_decode(pload->decoder);

			if (res == DEC_END) {
				break;
			} else if (res == DEC_ERR) {
				// Mark this as error
				pload->state = analyzer_pload_buffer_state_error;
				return POM_OK;
			} else if (res == DEC_MORE) {
				pload->buff_pos = pload->buff_size - pload->decoder->avail_out;
				if (analyzer_pload_buffer_grow(pload) != POM_OK)
					return POM_OK;
				pload->decoder->avail_out = pload->buff_size - pload->buff_pos;
			} else if (!pload->decoder->avail_in) {
				break;
			}

		}

		pload->buff_pos = pload->buff_size - pload->decoder->avail_out;

	} else {
		// Uncompressed stuff
		if (pload->buff_size < pload->buff_pos + size) {
			// Buffer is too small, add a page
			if (analyzer_pload_buffer_grow(pload) != POM_OK)
				return POM_OK;
		}
		memcpy(pload->buff + pload->buff_pos, data, size);
		pload->buff_pos += size;

	}

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


		if (!pload->decoder) {
			// Use the current data as the buffer
			pload->buff_pos = size;
			pload->buff = data;
		}


		// We need to allocate the buffer for this payload
#ifdef HAVE_LIBMAGIC
		if (pload->flags & ANALYZER_PLOAD_BUFFER_NEED_MAGIC)
			pload->state = analyzer_pload_buffer_state_magic;
		else
#endif
			pload->state = analyzer_pload_buffer_state_partial;

	}

	if (pload->buff_size) { // There is a buffer, we need to append data to the current buffer
		if (analyzer_pload_buffer_append_to_buff(pload, data, size) != POM_OK)
			return POM_ERR;
	}

#ifdef HAVE_LIBMAGIC
	if (pload->state == analyzer_pload_buffer_state_magic) {
		// We need to perform some magic

		if (!pload->buff_size && pload->decoder) {
			// We need to decode/decompress the buffer before analyzing it
			if (analyzer_pload_buffer_append_to_buff(pload, data, size) != POM_OK)
				return POM_ERR;
		}

		if (pload->buff_pos > ANALYZER_PLOAD_BUFFER_MAGIC_MIN_SIZE || (pload->expected_size && pload->expected_size < ANALYZER_PLOAD_BUFFER_MAGIC_MIN_SIZE)) {
			// We have enough to perform some magic
			

			// libmagic is no thread safe ...
			static pthread_mutex_t magic_lock = PTHREAD_MUTEX_INITIALIZER;
			pom_mutex_lock(&magic_lock);

			char *magic_mime_type_name = (char*) magic_buffer(magic_cookie, pload->buff, pload->buff_pos);

			if (!magic_mime_type_name) {
				pomlog(POMLOG_ERR "Error while proceeding with magic : %s", magic_error(magic_cookie));
				pload->state = analyzer_pload_buffer_state_error;
				pom_mutex_unlock(&magic_lock);
				return POM_ERR;
			}
			struct mime_type *magic_mime_type = mime_type_parse(magic_mime_type_name);
			pom_mutex_unlock(&magic_lock);

			if (!magic_mime_type) {
				pload->state = analyzer_pload_buffer_state_error;
				return POM_ERR;
			}
			
			// Drop the magic mime if it's the same as the original one or if it's a useless one
			if ((pload->mime_type && !strcmp(magic_mime_type->name, pload->mime_type->name)) || !strcmp(magic_mime_type->name, "application/octet-stream") || !strcmp(magic_mime_type->name, "plain/text")) {
				// Discard this
				if (!pload->mime_type) {
					pload->mime_type = magic_mime_type;
					struct analyzer_pload_mime_type *tmp;
					for (tmp = analyzer_pload_mime_types; tmp && strcmp(tmp->name, magic_mime_type->name); tmp = tmp->next);
					if (tmp)
						pload->type = tmp->type;
					else
						pload->type = NULL;
				} else {
					mime_type_cleanup(magic_mime_type);
				}
			} else {
				if (pload->mime_type) {
					mime_type_cleanup(pload->mime_type);
				}
				pload->mime_type = magic_mime_type;
				struct analyzer_pload_mime_type *tmp;
				for (tmp = analyzer_pload_mime_types; tmp && strcmp(tmp->name, magic_mime_type->name); tmp = tmp->next);

				if (tmp)
					pload->type = tmp->type;
				else
					pload->type = NULL;
			}

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
		if (pload->type && pload->type->analyzer && pload->type->analyzer->analyze) {

			if (!pload->buff_size && pload->decoder) {
				// We need to decode/decompress the buffer before analyzing it
				if (analyzer_pload_buffer_append_to_buff(pload, data, size) != POM_OK)
					return POM_ERR;
			}

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

				if (pload_analyzer->analyze(pload_analyzer->analyzer, pload, pload->buff, pload->buff_pos) != POM_OK) {
					// The analyzer enountered an error. Not sure what is the best course of action here.
					pomlog(POMLOG_DEBUG "Error while analyzing pload of type %s", pload->type->name);

					if (pload_analyzer->cleanup)
						pload_analyzer->cleanup(pload_analyzer->analyzer, pload);

					// For now, remove the type from the payload
					pload->type = NULL;
					if (pload->data) {
						data_cleanup_table(pload->data, pload_analyzer->data_reg);
						pload->data = NULL;
					}
				}
	
				if (!pload->state == analyzer_pload_buffer_state_analysis_failed) {
					// The analyzer did not recognize the payload, nothing more to do
					pload->state = analyzer_pload_buffer_state_analyzed;
					pload->type = NULL;

					pload_analyzer->cleanup(pload_analyzer->analyzer, pload);
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
		struct analyzer_pload_reg *pload_analyzer = NULL;
		if (pload->type)
			pload_analyzer = pload->type->analyzer;

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
				lst->output_priv = tmp->output_priv;

				if (tmp->reg_info->open(lst, tmp->output_priv)) {
					// Either the pload is not needed or their was an error
					lst->is_err = 1;
				}

				lst->next = pload->output_list;
				if (lst->next)
					lst->next->prev = lst;

				pload->output_list = lst;

			}

			if (!pload->output_list && !(pload_analyzer && pload_analyzer->process)) {
				pload->state = analyzer_pload_buffer_state_done;
				if (pload->buff_size) 
					free(pload->buff);
				
				pload->buff = NULL;
				pload->buff_size = 0;
				pload->buff_pos = 0;
				return POM_OK;
			}


		}

		// There was some output for this pload, decode/decompress the buffer since it'll be needed
		if (!pload->buff_size && pload->decoder) {
			if (analyzer_pload_buffer_append_to_buff(pload, data, size) != POM_OK)
				return POM_ERR;
		}

		struct analyzer_pload_instance *lst;
		for (lst = pload->output_list; lst; lst = lst->next) {
			if (lst->is_err)
				continue;
			int res = POM_OK;
			if (pload->buff_size) {
				if (pload->buff_pos)
					res = lst->o->reg_info->write(lst->output_priv, lst->priv, pload->buff, pload->buff_pos);
			} else {
				if (size)
					res = lst->o->reg_info->write(lst->output_priv, lst->priv, data, size);
			}
			if (res != POM_OK) {
				pomlog(POMLOG_ERR "Error while writing to an output");
				lst->o->reg_info->close(lst->output_priv, lst->priv);
				lst->is_err = 1;
				continue;
			}

		}

		if (pload_analyzer && pload_analyzer->process) {
			if (pload->buff_size) {
				if (pload->buff_pos) {
					if (pload_analyzer->process(pload_analyzer->analyzer, pload, pload->buff, pload->buff_pos) != POM_OK)
						return POM_ERR;
				}
			} else {
				if (size) {
					if (pload_analyzer->process(pload_analyzer->analyzer, pload, data, size) != POM_OK)
						return POM_ERR;
				}
			}
					
		}


		if (pload->buff_size) {
			// The buffer was written, we can safely get rid of it
			pload->buff_size = 0;
			pload->buff_pos = 0;
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
		if (!lst->is_err && lst->o->reg_info->close(lst->output_priv, lst->priv) != POM_OK)
			pomlog(POMLOG_WARN "Error while closing payload");
		
		pload->output_list = lst->next;
		free(lst);

	}

	if (pload->decoder)
		decoder_cleanup(pload->decoder);

	if (pload->buff_size && pload->buff)
		free(pload->buff);

	if (pload->mime_type)
		mime_type_cleanup(pload->mime_type);

	free(pload);

	return POM_OK;
}

struct analyzer_pload_type* analyzer_pload_type_get_by_name(char *name) {

	struct analyzer_pload_type *tmp;
	for (tmp = analyzer_pload_types; tmp && strcmp(tmp->name, name); tmp = tmp->next);

	return tmp;
}

int analyzer_pload_buffer_set_type_by_content_type(struct analyzer_pload_buffer *pload, char *content_type) {

	if (!content_type)
		return POM_ERR;

	if (pload->state != analyzer_pload_buffer_state_empty)
		return POM_ERR;

	pload->mime_type = mime_type_parse(content_type);
	if (!pload->mime_type)
		return POM_ERR;

	struct analyzer_pload_mime_type *tmp;
	for (tmp = analyzer_pload_mime_types; tmp && strcmp(tmp->name, pload->mime_type->name); tmp = tmp->next);

	if (tmp)
		pload->type = tmp->type;

	return POM_OK;
}

int analyzer_pload_buffer_set_type(struct analyzer_pload_buffer *pload, struct analyzer_pload_type *type) {

	if (!type)
		return POM_ERR;

	if (pload->state != analyzer_pload_buffer_state_empty)
		return POM_ERR;

	pload->type = type;

	return POM_OK;
}

struct analyzer_pload_type* analyzer_pload_buffer_get_type(struct analyzer_pload_buffer *pload) {

	return pload->type;
}

int analyzer_pload_buffer_set_encoding(struct analyzer_pload_buffer *pload, char *encoding) {

	if (pload->state != analyzer_pload_buffer_state_empty)
		return POM_ERR;

	// Check of the encoding is a NO OP
	int i;
	for (i = 0; analyzer_noop_decoders[i] && strcasecmp(encoding, analyzer_noop_decoders[i]); i++);
	
	if (analyzer_noop_decoders[i])
		return POM_OK;

	// Otherwise, try to allocate it
	pload->decoder = decoder_alloc(encoding);
	if (!pload->decoder) {
		pload->state = analyzer_pload_buffer_state_error;
		return POM_ERR;
	}

	return POM_OK;
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

int analyzer_pload_buffer_set_state(struct analyzer_pload_buffer *pload, enum analyzer_pload_buffer_state state) {
	if (state < pload->state) {
		pomlog(POMLOG_ERR "Pload cannot go from state %u to %u !", pload->state, state);
		return POM_ERR;
	}

	if (state < analyzer_pload_buffer_state_analyzed) {
		pomlog(POMLOG_ERR "Pload state %u cannot be set externally !", state);
		return POM_ERR;
	}

	pload->state = state;

	return POM_OK;
}

struct data* analyzer_pload_buffer_get_data(struct analyzer_pload_buffer *pload) {
	return pload->data;
}

struct event* analyzer_pload_buffer_get_related_event(struct analyzer_pload_buffer *pload) {
	return pload->rel_event;
}

void analyzer_pload_buffer_set_related_event(struct analyzer_pload_buffer *pload, struct event *evt) {
	pload->rel_event = evt;
}

void *analyzer_pload_buffer_get_priv(struct analyzer_pload_buffer *pload) {
	return pload->analyzer_priv;
}

void analyzer_pload_buffer_set_priv(struct analyzer_pload_buffer *pload, void *priv) {
	pload->analyzer_priv = priv;
}

struct mime_type *analyzer_pload_buffer_get_mime_type(struct analyzer_pload_buffer *pload) {
	return pload->mime_type;
}

void analyzer_pload_buffer_set_container(struct analyzer_pload_buffer *pload, struct analyzer_pload_buffer *container) {
	pload->container = container;
	pload->rel_event = container->rel_event;
}
