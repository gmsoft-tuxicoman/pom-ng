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

#include "analyzer.h"
#include "output.h"
#include "mod.h"
#include "input_server.h"
#include "common.h"

#include <libxml/parser.h>

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


int analyzer_init(char *mime_type_database) {

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

	xmlDocPtr doc;
	xmlNodePtr root, cur;

	doc = xmlParseFile(mime_type_database);

	if (!doc) {
		pomlog(POMLOG_ERR "Error while parsing mime type databse %s", mime_type_database);
		return POM_ERR;
	}

	root = xmlDocGetRootElement(doc);
	
	if (!root) {
		pomlog(POMLOG_ERR "Mime type database empty");
		xmlFreeDoc(doc);
		return POM_ERR;
	}

	if (xmlStrcmp(root->name, (const xmlChar*) "mime_types")) {
		pomlog(POMLOG_ERR "The first and only node should be <mime_types> !");
		xmlFreeDoc(doc);
		return POM_ERR;
	}


	// Parse definitions
	for (cur = root->xmlChildrenNode; cur && xmlStrcmp(cur->name, (const xmlChar *) "definitions"); cur = cur->next);
	if (!cur) {
		pomlog(POMLOG_ERR "<definitions> not found in the mime-types database");
		xmlFreeDoc(doc);
		return POM_ERR;
	}


	xmlNodePtr defs = cur->xmlChildrenNode;
	for (; defs; defs = defs->next) {

		if (xmlStrcmp(defs->name, (const xmlChar *) "def"))
			continue;

		char *cls_name = (char *) xmlGetProp(defs, (const xmlChar *) "class");
		if (!cls_name) {
			pomlog(POMLOG_WARN "Class name missing for definition");
			continue;
		}

		int cls_id;
		for (cls_id = 0; cls_id < ANALYZER_PLOAD_CLASS_COUNT && strcmp(pload_class_def[cls_id].name, cls_name); cls_id++);
		if (cls_id >= ANALYZER_PLOAD_CLASS_COUNT) {
			pomlog(POMLOG_WARN "Class %s does not exists for definition", cls_name);
			xmlFree(cls_name);
			continue;
		}
		xmlFree(cls_name);

		char *name = (char *) xmlGetProp(defs, (const xmlChar *) "name");
		if (!name) {
			pomlog(POMLOG_WARN "Definition name missing");
			continue;
		}

		char *description = (char *) xmlGetProp(defs, (const xmlChar *) "description");
		if (!description) {
			pomlog(POMLOG_WARN "Description missing for definition %s", name);
			xmlFree(name);
			continue;
		}

		char *extension = (char *) xmlGetProp(defs, (const xmlChar *) "extension");
		if (!extension) {
			pomlog(POMLOG_WARN "Extension missing for definition %s", name);
			xmlFree(name);
			xmlFree(description);
			continue;
		}


		struct analyzer_pload_type *def = malloc(sizeof(struct analyzer_pload_type));
		if (!def) {
			pom_oom(sizeof(struct analyzer_pload_type));
			xmlFree(name);
			xmlFree(description);
			xmlFree(extension);
			continue;
		}
		memset(def, 0, sizeof(struct analyzer_pload_type));

		def->cls = cls_id;
		def->name = strdup(name);
		if (!def->name) {
			free(def);
			xmlFree(description);
			xmlFree(extension);
			pom_oom(strlen(name) + 1);
			xmlFree(name);
			continue;
		}
		xmlFree(name);

		def->description = strdup(description);
		if (!def->description) {
			free(def->name);
			free(def);
			xmlFree(extension);
			pom_oom(strlen(description) + 1);
			xmlFree(description);
			continue;
		}
		xmlFree(description);

		def->extension = strdup(extension);
		if (!def->extension) {
			free(def->description);
			free(def->name);
			free(def);
			pom_oom(strlen(extension) + 1);
			xmlFree(extension);
			continue;

		}
		xmlFree(extension);

		def->next = analyzer_pload_types;
		if (def->next)
			def->next->prev = def;
		analyzer_pload_types = def;

		pomlog(POMLOG_DEBUG "Registered payload type %s : class %s, extension .%s", def->name, pload_class_def[def->cls].name, def->extension);

	}


	// Parse mime-types
	for (cur = root->xmlChildrenNode; cur && xmlStrcmp(cur->name, (const xmlChar *) "types"); cur = cur->next);
	if (!cur) {
		pomlog(POMLOG_ERR "<types> not found in the mime-types database");
		return POM_ERR;
	}

	xmlNodePtr types = cur->xmlChildrenNode;
	for (; types; types = types->next) {

		if (xmlStrcmp(types->name, (const xmlChar *) "type"))
			continue;

		char *def = (char *) xmlGetProp(types, (const xmlChar *) "def");
		if (!def) {
			pomlog(POMLOG_WARN "Type definition missing");
			continue;
		}

		struct analyzer_pload_type *defs = analyzer_pload_types;
		for (; defs && strcmp(defs->name, def); defs = defs->next);
		if (!defs) {
			pomlog(POMLOG_WARN "Definition %s not known", def);
			xmlFree(def);
			continue;
		}
		xmlFree(def);

		char *value = (char *) xmlNodeListGetString(doc, types->xmlChildrenNode, 1);
		if (!value) {
			pomlog(POMLOG_WARN "Empty mime type");
			continue;
		}

		struct analyzer_pload_mime_type *type = malloc(sizeof(struct analyzer_pload_mime_type));
		if (!type) {
			xmlFree(value);
			pom_oom(sizeof(struct analyzer_pload_mime_type));
			continue;
		}
		memset(type, 0, sizeof(struct analyzer_pload_mime_type));
		type->type = defs;
		type->name = strdup(value);
		if (!type->name) {
			pom_oom(strlen(value));
			xmlFree(value);
			continue;
		}
		xmlFree(value);

		type->next = analyzer_pload_mime_types;
		if (type->next)
			type->next->prev = type;
		analyzer_pload_mime_types = type;

		pomlog(POMLOG_DEBUG "Mime type %s registered as %s", type->name, type->type->name);

	}

	xmlFreeDoc(doc);

	return POM_OK;


}

int analyzer_register(struct analyzer_reg *reg_info) {

	if (reg_info->api_ver != ANALYZER_API_VER) {
		pomlog(POMLOG_ERR "Cannot register analyzer as API version differ : expected %u got %u", ANALYZER_API_VER, reg_info->api_ver);
		return POM_ERR;
	}

	if (input_server_is_current_process()) {
		pomlog(POMLOG_DEBUG "Not loading analyzer %s in the input process", reg_info->name);
		return POM_OK;
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
	
	char *type_str = (type ? type->name : "unknown");
	pomlog(POMLOG_DEBUG "Got new pload of type %s", type_str);

	pload->expected_size = expected_size;
	pload->type = type;
	pload->flags = flags;

	return pload;

}


int analyzer_pload_buffer_append(struct analyzer_pload_buffer *pload, void *data, size_t size) {

	if (pload->state == analyzer_pload_buffer_state_error || pload->state == analyzer_pload_buffer_state_done) {
		// Don't process payloads which encountered an error or which do not need additional processing
		return POM_OK;
	}


	if (pload->state == analyzer_pload_buffer_state_empty) {
		// We need to allocate the buffer for this payload
		if (pload->expected_size) {
			// Easy enough, we know what size it will be in total
			pload->buff_size = pload->expected_size;
			pload->buff = malloc(pload->expected_size);
			if (!pload->buff) {
				pom_oom(pload->expected_size);
				pload->state = analyzer_pload_buffer_state_error;
				return POM_ERR;
			}
		} else {
			// We don't know how big it will be, allocate a page
			long pagesize = sysconf(_SC_PAGESIZE);
			if (!pagesize)
				pagesize = 4096;
			pload->buff = malloc(pagesize);
			if (!pload->buff) {
				pom_oom(pagesize);
				pload->state = analyzer_pload_buffer_state_error;
				return POM_ERR;
			}
		}
#ifdef HAVE_LIBMAGIC
		pload->state = analyzer_pload_buffer_state_magic;
#else
		pload->state = analyzer_pload_buffer_state_partial;
#endif

	}


	// Add the data to the buffer
	if (pload->expected_size) {
		if (pload->expected_size < pload->buff_pos + size) {
			pomlog(POMLOG_DEBUG "Pload larger than expected size. Dropping");
			pload->state = analyzer_pload_buffer_state_error;
			return POM_OK;
		}
	} else {

		if (pload->buff_size < pload->buff_pos + size) {
			// Buffer is too small, add a page
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
		}
	}
	
	memcpy(pload->buff + pload->buff_pos, data, size);
	pload->buff_pos += size;

	if (pload->state == analyzer_pload_buffer_state_analyzed) {
		// Send the payload to the output
		return analyzer_pload_output(pload);
	}

#ifdef HAVE_LIBMAGIC
	if (pload->state == analyzer_pload_buffer_state_magic) {
		// We need to perform some magic
		if (pload->buff_pos > ANALYZER_PLOAD_BUFFER_MAGIC_MIN_SIZE || (pload->expected_size && pload->expected_size < ANALYZER_PLOAD_BUFFER_MAGIC_MIN_SIZE)) {
			// We have enough to perform some magic
			char *magic_mime_type = (char*) magic_buffer(magic_cookie, pload->buff, pload->buff_pos);
			if (!magic_mime_type) {
				pomlog(POMLOG_ERR "Error while proceeding with magic : %s", magic_error(magic_cookie));
				pload->state = analyzer_pload_buffer_state_error;
				return POM_ERR;
			}
			struct analyzer_pload_type *magic_pload_type = analyzer_pload_type_get_by_mime_type(magic_mime_type);

			// If magic found something different, use that instead
			if (magic_pload_type && (magic_pload_type != pload->type)) {
				pomlog(POMLOG_DEBUG "Fixed payload type to %s according to libmagic", magic_mime_type);
				pload->type = magic_pload_type;
			}

			pload->state = analyzer_pload_buffer_state_partial;
		}
	}


#endif

	if (pload->state == analyzer_pload_buffer_state_partial) {
		// If we know what type of payload we are dealing with, try to analyze it
		if (pload->type) {

			struct analyzer_pload_reg *pload_analyzer = pload->type->analyzer;


			// Have the analyzer look at the payload
			// The analyzer will either leave the state as it is or change it to error or analyzed
			if ((pload_analyzer->flags & ANALYZER_PLOAD_PROCESS_PARTIAL) || (pload->expected_size && (pload->buff_pos >= pload->expected_size))) {
				if (pload->type->analyzer->process(pload->type->analyzer->analyzer, pload) != POM_OK) {
					// The analyzer enountered an error. Not sure what is the best course of action here.
					pomlog(POMLOG_DEBUG "Error while analyzing pload of type %s", pload->type->name);
					// For now, remove the type from the payload
					pload->type = NULL;
				}
			}
		
			if (!pload->type) {
				// The analyzer did not recognize the payload, nothing more to do
				pload->state = analyzer_pload_buffer_state_analyzed;
			} 

		} else {
			// Nothing to analyze
			pload->state = analyzer_pload_buffer_state_analyzed;
		}

		if (pload->state == analyzer_pload_buffer_state_analyzed) {
			// Process the payload to the ouptut
			return analyzer_pload_output(pload);
		}

	}

	return POM_OK;

}

int analyzer_pload_output(struct analyzer_pload_buffer *pload) {


	if (!pload->output_list) {
		// Try to send this payload to all the outputs
		// TODO filtering
		struct analyzer_pload_output *tmp;
		for (tmp = analyzer_pload_outputs; tmp; tmp = tmp->next) {

			struct analyzer_pload_output_list *lst = malloc(sizeof(struct analyzer_pload_output_list));
			if (!lst) {
				pom_oom(sizeof(struct analyzer_pload_output_list));
				// Error is not fatal
				return POM_OK;
			}
			memset(lst, 0, sizeof(struct analyzer_pload_output_list));
			lst->o = tmp;
			lst->pload = pload;

			if (tmp->reg_info->open(lst)) {
				pomlog(POMLOG_ERR "Error while opending output %s for a payload", tmp->output->name);
				free(lst);
				continue;
			}

			lst->next = pload->output_list;
			if (lst->next)
				lst->next->prev = lst;

			pload->output_list = lst;

		}

	}

	struct analyzer_pload_output_list *lst;
	for (lst = pload->output_list; lst; lst = lst->next) {
		ssize_t res = lst->o->reg_info->write(lst, pload->buff + lst->cur_pos, pload->buff_pos - lst->cur_pos);
		if (res < 0) {
			pomlog(POMLOG_ERR "Error while writing to output %s", lst->o->output->name);
			lst->o->reg_info->close(lst);
			// Remove this input from the list
			if (lst->next)
				lst->next->prev = lst->prev;
			if (lst->prev)
				lst->prev->next = lst->next;
			else
				pload->output_list = lst->next;
			continue;
		}

		lst->cur_pos += res;

	}

	if (!pload->output_list)
		pload->state = analyzer_pload_buffer_state_done;

	return POM_OK;
}

int analyzer_pload_buffer_cleanup(struct analyzer_pload_buffer *pload) {

	if (pload->type) {

		struct analyzer_pload_reg *pload_analyzer = pload->type->analyzer;
		if (pload_analyzer->cleanup) {
			if (pload_analyzer->cleanup(pload_analyzer->analyzer, pload) != POM_OK)
				pomlog(POMLOG_WARN "Error while cleaning up payload buffer of type %s", pload->type->name);
		}
	}

	while (pload->output_list) {
		struct analyzer_pload_output_list *lst = pload->output_list;
		if (lst->o->reg_info->close(lst) != POM_OK)
			pomlog(POMLOG_WARN "Error while closing payload with output %s", lst->o->output->name);
		
		pload->output_list = lst->next;
		free(lst);

	}

	if (pload->buff)
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


	size_t len;
	char *end = strchr(mime_type, ';');
	if (end)
		len = end - mime_type;
	else
		len = strlen(mime_type);
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


int analyzer_pload_output_register(struct output *o, struct analyzer_pload_output_reg *reg_info) {


	struct analyzer_pload_output *po = malloc(sizeof(struct analyzer_pload_output));
	if (!po) {
		pom_oom(sizeof(struct analyzer_pload_output));
		return POM_ERR;
	}
	memset(po, 0, sizeof(struct analyzer_pload_output));

	po->reg_info = reg_info;
	po->output = o;

	po->next = analyzer_pload_outputs;
	if (po->next)
		po->next->prev = po;

	analyzer_pload_outputs = po;

	return POM_OK;

}


int analyzer_pload_output_unregister(struct output *o) {

	struct analyzer_pload_output *po = analyzer_pload_outputs;
	for (; po && po->output != o; po = po->next);

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
