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


#include "output_log_txt.h"

#include <pom-ng/ptype_string.h>
#include <pom-ng/resource.h>
#include <pom-ng/filter.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>


static struct datavalue_template output_log_txt_templates_name[] = {
	{ .name = "name", .type = "string" },
	{ .name = "description", .type = "string" },
	{ 0 }
};

static struct datavalue_template output_log_txt_events[] = {
	{ .name = "template", .type = "string" },
	{ .name = "event", .type = "string" },
	{ .name = "filter", .type = "string" },
	{ .name = "format", .type = "string" },
	{ .name = "file", .type = "string" },
	{ 0 }
};

static struct datavalue_template output_log_txt_files[] = {
	{ .name = "template", .type = "string" },
	{ .name = "name", .type = "string" },
	{ .name = "path", .type = "string" },
	{ 0 }
};

static struct resource_template output_log_txt_templates[] = {
	{ "templates", output_log_txt_templates_name },
	{ "events", output_log_txt_events },
	{ "files", output_log_txt_files },
	{ 0 }
};

int output_log_txt_init(struct output *o) {

	struct output_log_txt_priv *priv = malloc(sizeof(struct output_log_txt_priv));
	if (!priv) {
		pom_oom(sizeof(struct output_log_txt_priv));
		return POM_ERR;
	}
	memset(priv, 0, sizeof(struct output_log_txt_priv));
	output_set_priv(o, priv);

	struct registry_param *p = NULL;
	struct resource *r = NULL;
	struct resource_dataset *r_templates = NULL;

	priv->p_prefix = ptype_alloc("string");
	priv->p_template = ptype_alloc("string");
	if (!priv->p_prefix || !priv->p_template)
		goto err;

	struct registry_instance *inst = output_get_reg_instance(o);
	priv->perf_events = registry_instance_add_perf(inst, "events", registry_perf_type_counter, "Number of events process", "events");
	if (!priv->perf_events)
		goto err;

	p = registry_new_param("prefix", "/tmp/", priv->p_prefix, "Log files prefix", 0);
	if (output_add_param(o, p) != POM_OK)
		goto err;
	
	p = registry_new_param("template", "", priv->p_template, "Log template to use", 0);

	r = resource_open(OUTPUT_LOG_TXT_RESOURCE, output_log_txt_templates);

	if (!r)
		goto err;

	r_templates = resource_dataset_open(r, "templates");
	if (!r_templates)
		goto err;

	while (1) {
		struct datavalue *v;
		int res = resource_dataset_read(r_templates, &v);
		if (res < 0)
			goto err;
		if (res == DATASET_QUERY_OK)
			break;
		char *name = PTYPE_STRING_GETVAL(v[0].value);
		if (registry_param_info_add_value(p, name) != POM_OK)
			goto err;
	}

	resource_dataset_close(r_templates);
	resource_close(r);

	r_templates = NULL;
	r = NULL;

	if (output_add_param(o, p) != POM_OK)
		goto err;

	return POM_OK;
err:
	if (r_templates)
		resource_dataset_close(r_templates);
	if (r)
		resource_close(r);

	if (p)
		registry_cleanup_param(p);

	return POM_ERR;
}

int output_log_txt_cleanup(void *output_priv) {

	struct output_log_txt_priv *priv = output_priv;
	if (priv) {
		if (priv->p_prefix)
			ptype_cleanup(priv->p_prefix);
		if (priv->p_template)
			ptype_cleanup(priv->p_template);
		free(priv);
	}

	return POM_OK;
}

static struct output_log_txt_field *output_log_txt_parse_fields(struct event_reg *evt, const char *format) {

	unsigned int field_count = 0;
	struct output_log_txt_field *fields = NULL;
	const char *sep = NULL, *cur = format;
	while ((sep = strchr(cur, '$'))) {

		// Check if $ was escaped
		if (sep != format && *(sep - 1) == '\\') {
			cur = sep + 1;

			field_count++;
			struct output_log_txt_field *old_fields = fields;
			fields = realloc(fields, sizeof(struct output_log_txt_field) * (field_count + 1));
			if (!fields) {
				free(old_fields);
				pom_oom(sizeof(struct output_log_parsed_field *) * (field_count + 1));
				return NULL;
			}
			memset(&fields[field_count - 1], 0, sizeof(struct output_log_txt_field) * 2);
			// End marker
			fields[field_count].id = -1;

			struct output_log_txt_field *field = &fields[field_count - 1];
			field->type =  output_log_txt_dollar;
			field->start_off = sep - format - 1;
			field->end_off = sep - format;
			continue;
		}

		unsigned int start_off = sep - format;
		sep++;

		// Find the end of the name
		cur = sep;
		while ((*cur >= '0' && *cur <= '9') || (*cur >= 'a' && *cur <= 'z') || *cur == '_')
			cur++;
		unsigned int end_off = cur - format;

		// Copy the name in a temp variable
		unsigned int name_len = end_off - start_off - 1;
		char *field_name = strndup(sep, name_len);
		if (!field_name) {
			if (fields)
				free(fields);
			pom_oom(name_len + 1);
			return NULL;
		}

		enum output_log_txt_field_type field_type = output_log_txt_event_field;
		int field_id;

		if (*field_name == '_') {
			field_type = output_log_txt_event_property;
			// This is a event property
			if (!strcmp(field_name, "_time")) {
				field_id = output_log_txt_event_property_ts;
			} else if (!strcmp(field_name, "_name")) {
				field_id = output_log_txt_event_property_name;
			} else if (!strcmp(field_name, "_source_name")) {
				field_id = output_log_txt_event_property_source_name;
			} else if (!strcmp(field_name, "_description")) {
				field_id = output_log_txt_event_property_description;
			} else {
				pomlog(POMLOG_WARN "Even property %s does not exists", field_name);
				free(field_name);
				sep = cur + 1;
				continue;
			}
		} else {
	
			// Find the corresponding field
			struct event_reg_info *evt_info = event_reg_get_info(evt);
			struct data_reg *dreg = evt_info->data_reg;
			for (field_id = 0; field_id < dreg->data_count && strcmp(dreg->items[field_id].name, field_name); field_id++);

			if (field_id >= dreg->data_count) {
				pomlog(POMLOG_WARN "Field %s not found in event %s", field_name, evt_info->name);
				free(field_name);
				sep = cur + 1;
				continue;
			}
		}

		field_count++;
		struct output_log_txt_field *old_fields = fields;
		fields = realloc(fields, sizeof(struct output_log_txt_field) * (field_count + 1));
		if (!fields) {
			free(old_fields);
			pom_oom(sizeof(struct output_log_parsed_field *) * (field_count + 1));
			return NULL;
		}
		memset(&fields[field_count - 1], 0, sizeof(struct output_log_txt_field) * 2);
		// End marker
		fields[field_count].id = -1;

		struct output_log_txt_field *field = &fields[field_count - 1];

		if (field_type == output_log_txt_event_field) {
			struct event_reg_info *evt_info = event_reg_get_info(evt);
			struct data_reg *dreg = evt_info->data_reg;

			if (dreg->items[field_id].flags & DATA_REG_FLAG_LIST) {
				// We are dealing with a list
				const char *key = sep + name_len;
				if (*key != '[') {
					pomlog(POMLOG_WARN "Field %s is a list, need a key declaration", field_name);
					free(field_name);
					sep = cur + 1;
					field_count--;
					continue;
				}
				key++;

				cur = key;
				while ((*cur >= '0' && *cur <= '9') || (*cur >= 'a' && *cur <= 'z') || (*cur >= 'A' && *cur <= 'Z') || *cur == '_' || *cur == '*')
					cur++;
				
				if (*cur != ']') {
					pomlog(POMLOG_WARN "Unmatched ']' for field %s", field_name);
					free(field_name);
					sep = cur + 1;
					field_count--;
					continue;
				}
				unsigned int key_len = cur - key;
				if (key_len == 1 && *key == '*') {
					field->key = OUTPUT_LOG_TXT_FIELD_KEY_WILDCARD;
				} else {
					field->key = strndup(key, key_len);
					if (!field->key) {
						pom_oom(key_len + 1);
						free(field_name);
						free(fields);
						return NULL;
					}
				}

				end_off = cur - format + 1;

			}
		}

		// Parse the ptype print format

		if (*cur == '{') {
			cur++;
			const char *ptype_format = cur;
			while (*cur && *cur != '}')
				cur++;

			if (*cur != '}') {
				pomlog(POMLOG_WARN "Unmatched '}' for field %s", field_name);
				free(field_name);
				sep = cur + 1;
				field_count--;
				continue;
			}

			unsigned int ptype_format_len = cur - ptype_format;
			field->ptype_format = strndup(ptype_format, ptype_format_len);
			if (!field->ptype_format) {
				pom_oom(ptype_format_len + 1);
				free(field_name);
				if (field->key && field->key != OUTPUT_LOG_TXT_FIELD_KEY_WILDCARD)
					free(fields->key);
				free(fields);
				return NULL;
			}
			end_off = cur - format + 1;

		}

		field->id = field_id;
		field->start_off = start_off;
		field->end_off = end_off;

		free(field_name);
	}

	return fields;

}

int output_log_txt_open(void *output_priv) {

	struct output_log_txt_priv *priv = output_priv;

	struct resource *r = NULL;
	struct resource_dataset *r_templates = NULL, *r_events = NULL, *r_files = NULL;

	char *template_name = PTYPE_STRING_GETVAL(priv->p_template);
	if (!strlen(template_name)) {
		pomlog(POMLOG_ERR "You need to specify a log template");
		return POM_ERR;
	}

	r = resource_open(OUTPUT_LOG_TXT_RESOURCE, output_log_txt_templates);

	if (!r)
		goto err;

	// Check that the given template exists
	r_templates = resource_dataset_open(r, "templates");
	if (!r_templates)
		goto err;

	while (1) {
		struct datavalue *v;
		int res = resource_dataset_read(r_templates, &v);
		if (res < 0)
			goto err;
		if (res == DATASET_QUERY_OK) {
			pomlog(POMLOG_ERR "Log template %s does not exists", template_name);
			goto err;
		}
		char *name = PTYPE_STRING_GETVAL(v[0].value);
		if (!strcmp(name, template_name))
			break;
	}

	resource_dataset_close(r_templates);
	r_templates = NULL;

	// Fetch all the files that will be used for this template
	r_files = resource_dataset_open(r, "files");
	if (!r_files)
		goto err;

	while (1) {
		struct datavalue *v;
		int res = resource_dataset_read(r_files, &v);
		if (res < 0)
			goto err;
		if (res == DATASET_QUERY_OK)
			break;

		char *template = PTYPE_STRING_GETVAL(v[0].value);
		if (strcmp(template, template_name))
			continue;

		struct output_log_txt_file *file = malloc(sizeof(struct output_log_txt_file));
		if (!file) {
			pom_oom(sizeof(struct output_log_txt_file));
			goto err;
		}
		memset(file, 0, sizeof(struct output_log_txt_file));
		file->fd = -1;

		char *name = PTYPE_STRING_GETVAL(v[1].value);
		file->name = strdup(name);
		if (!file->name) {
			free(file);
			pom_oom(strlen(name) + 1);
			goto err;
		}

		char *path = PTYPE_STRING_GETVAL(v[2].value);
		file->path = strdup(path);
		if (!file->path) {
			free(file->name);
			free(file);
			pom_oom(strlen(path) + 1);
			goto err;
		}

		if (pthread_mutex_init(&file->lock, NULL)) {
			free(file->path);
			free(file->name);
			free(file);
			pomlog(POMLOG_ERR "Error while initializing file lock : %s", pom_strerror(errno));
			goto err;
		}

		file->next = priv->files;
		if (file->next)
			file->next->prev = file;

		priv->files = file;

	}

	resource_dataset_close(r_files);
	r_files = NULL;
		


	// Check all the events to register for this template
	r_events = resource_dataset_open(r, "events");
	if (!r_events)
		goto err;

	while (1) {
		struct datavalue *v;
		int res = resource_dataset_read(r_events, &v);
		if (res < 0)
			goto err;
		if (res == DATASET_QUERY_OK)
			break;

		char *template = PTYPE_STRING_GETVAL(v[0].value);
		if (strcmp(template, template_name))
			continue;

		// Find the event
		char *evt_name = PTYPE_STRING_GETVAL(v[1].value);
		struct event_reg *evt = event_find(evt_name);
		if (!evt) {
			pomlog(POMLOG_ERR "Event %s from template %s doesn't exists", evt_name, template_name);
			goto err;
		}
		
		// Add this event to our list of events
		struct output_log_txt_event *log_evt = malloc(sizeof(struct output_log_txt_event));
		if (!log_evt) {
			pom_oom(sizeof(struct output_log_txt_event));
			goto err;
		}
		memset(log_evt, 0, sizeof(struct output_log_txt_event));
		log_evt->p_prefix = priv->p_prefix;
		log_evt->priv = priv;

		// Add this event to our list
		log_evt->next = priv->events;
		if (log_evt->next)
			log_evt->next->prev = log_evt;

		priv->events = log_evt;

		log_evt->evt = evt;


		// Parse the filter for this event if any
		struct filter_node *filter = NULL;
		if (v[2].value) {
			char *filter_str = PTYPE_STRING_GETVAL(v[2].value);
			if (filter_event(filter_str, log_evt->evt, &filter) != POM_OK) {
				pomlog(POMLOG_ERR "Error while parsing filter \"%s\"", filter_str);
				goto err;
			}
		}

		// Listen to the event
		if (event_listener_register(evt, log_evt, NULL, output_log_txt_process, filter) != POM_OK)
			goto err;

		// Find in which file this event will be saved
		char *file = PTYPE_STRING_GETVAL(v[4].value);
		for (log_evt->file = priv->files; log_evt->file && strcmp(log_evt->file->name, file); log_evt->file = log_evt->file->next);
		if (!log_evt->file) {
			pomlog(POMLOG_ERR "File \"%s\" has not been decladed but it's used in event \"%s\"", file, evt_name);
			goto err;
		}
		

		// Parse the format of this event
		char *format = PTYPE_STRING_GETVAL(v[3].value);

		log_evt->format = strdup(format);
		if (!log_evt->format)
			goto err;

		log_evt->fields = output_log_txt_parse_fields(evt, format);

		if (!log_evt->fields) {
			pomlog(POMLOG_ERR "No field found in format string : \"%s\"", format);
			goto err;
		}




	}
	resource_dataset_close(r_events);
	r_events = NULL;

	resource_close(r);

	return POM_OK;

err:

	if (r_templates)
		resource_dataset_close(r_templates);

	if (r_events)
		resource_dataset_close(r_events);

	if (r_files)
		resource_dataset_close(r_files);

	if (r)
		resource_close(r);

	output_log_txt_close(priv);

	return POM_ERR;
}

int output_log_txt_close(void *output_priv) {
	
	struct output_log_txt_priv *priv = output_priv;


	while (priv->events) {
		struct output_log_txt_event *evt = priv->events;
		priv->events = evt->next;

		if (event_listener_unregister(evt->evt, evt) != POM_OK)
			pomlog(POMLOG_WARN "Error while unregistering event listener !");

		if (evt->format)
			free(evt->format);

		if (evt->fields) {
			int i;
			for (i = 0; evt->fields[i].id != -1; i++) {
				if (evt->fields[i].key && evt->fields[i].key != OUTPUT_LOG_TXT_FIELD_KEY_WILDCARD)
					free(evt->fields[i].key);
				if (evt->fields[i].ptype_format)
					free(evt->fields[i].ptype_format);
			}

			free(evt->fields);
		}

		free(evt);
	}

	while (priv->files) {
		struct output_log_txt_file *file = priv->files;
		priv->files = file->next;

		if (file->fd != -1) {
			if (close(file->fd) < 0) 
				pomlog(POMLOG_WARN "Error while closing file : %s", pom_strerror(errno));
		}
		
		if (file->name)
			free(file->name);
		if (file->path)
			free(file->path);

		if (pthread_mutex_destroy(&file->lock))
			pomlog(POMLOG_WARN "Error while destroying file lock : %s", pom_strerror(errno)); 

		free(file);

	}


	return POM_OK;
}	

int output_log_txt_process(struct event *evt, void *obj) {

	struct output_log_txt_event *log_evt = obj;

	// Open the log file
	struct output_log_txt_file *file = log_evt->file;

	char fname[FILENAME_MAX + 1] = {0};
	pom_mutex_lock(&file->lock);
	if (file->fd == -1) {
		// File is not open, let's do it
		char *filename = NULL;
		if (log_evt->p_prefix) {
			char *prefix = PTYPE_STRING_GETVAL(log_evt->p_prefix);
			snprintf(fname, FILENAME_MAX, "%s%s", prefix, file->path);
			filename = fname;
		} else {
			filename = file->path;
		}
		file->fd = open(filename, O_WRONLY | O_CREAT | O_APPEND, 0666);

		if (file->fd == -1) {
			pomlog(POMLOG_ERR "Error while opening file \"%s\" : %s", pom_strerror(errno));
			pom_mutex_unlock(&file->lock);
			return POM_ERR;
		}
	}

	char *format = log_evt->format;

	int i;
	unsigned int format_pos = 0;

	// Write to the log file
	for (i = 0; log_evt->fields[i].id != -1; i++) {
	
		struct output_log_txt_field *field = &log_evt->fields[i];
		if (format_pos < field->start_off) {
			unsigned int len = field->start_off - format_pos;
			if (pom_write(file->fd, format + format_pos, len) != POM_OK)
				goto write_err;
		}

		format_pos = field->end_off;
	
		char *value = NULL;
		int allocated = 1;

		if (field->type == output_log_txt_event_property) {
			// Fetch the property value
			struct event_reg_info *evt_reg = event_reg_get_info(event_get_reg(evt));
			switch (field->id) {
				case output_log_txt_event_property_ts: {
					value = malloc(20);
					if (!value) {
						pom_mutex_unlock(&file->lock);
						pom_oom(20);
						return POM_ERR;
					}
					memset(value, 0, 20);
					char *format = "%Y-%m-%d %H:%M:%S";
					struct tm tmp;
					time_t sec = pom_ptime_sec(event_get_timestamp(evt));
					localtime_r(&sec, &tmp);
					strftime(value, 20, format, &tmp);
					break;
				}
				case output_log_txt_event_property_name:
					value = evt_reg->name;
					allocated = 0;
					break;
				case output_log_txt_event_property_source_name:
					value = evt_reg->source_name;
					allocated = 0;
					break;
				case output_log_txt_event_property_description:
					value = evt_reg->description;
					allocated = 0;
					break;
				default:
					pom_mutex_unlock(&file->lock);
					return POM_ERR;
			}
		} else if (field->type == output_log_txt_event_field) {

			struct data *evt_data = event_get_data(evt);
			if (field->key) {

				// Special handling for the wildcard '*'
				if (field->key == OUTPUT_LOG_TXT_FIELD_KEY_WILDCARD) {
					struct data_item *item;
					for (item = evt_data[field->id].items; item; item = item->next) {
						value = ptype_print_val_alloc(item->value, field->ptype_format);
						if (!value) {
							pom_mutex_unlock(&file->lock);
							return POM_ERR;
						}

						if ((pom_write(file->fd, item->key, strlen(item->key)) != POM_OK) || (pom_write(file->fd, ": \"", strlen(": \"")) != POM_OK)) {
							free(value);
							goto write_err;
						}
						char *quote = NULL;
						char *tmp = value;
						while ((quote = strchr(tmp, '"'))) {
							if ((pom_write(file->fd, tmp, quote - tmp) != POM_OK) || (pom_write(file->fd, "\\\"", strlen("\\\"")) != POM_OK)) {
								free(value);
								goto write_err;
							}
							tmp = quote + 1;
						}
						if (pom_write(file->fd, tmp, strlen(tmp)) != POM_OK || (pom_write(file->fd, "\"", 1) != POM_OK)) {
							free(value);
							goto write_err;
						}

						free(value);
					}

					continue;
				}

				// Find the right item in the list
				struct data_item *item;
				for (item = evt_data[field->id].items; item; item = item->next) {
					if (!strcasecmp(item->key, field->key)) {
						value = ptype_print_val_alloc(item->value, field->ptype_format);
						if (!value) {
							pom_mutex_unlock(&file->lock);
							return POM_ERR;
						}
						break;
					}
				}
			} else if (data_is_set(evt_data[field->id]) && evt_data[field->id].value) {
				// Find the value of the field
				value = ptype_print_val_alloc(evt_data[field->id].value, field->ptype_format);
				if (!value) {
					pom_mutex_unlock(&file->lock);
					return POM_ERR;
				}
			}
		}

		if (value) {
			if (pom_write(file->fd, value, strlen(value)) != POM_OK) {
				if (allocated)
					free(value);
				goto write_err;
			}
			if (allocated)
				free(value);
		} else if (field->type != output_log_txt_dollar) {
			if (pom_write(file->fd, "-", 1) != POM_OK)
				goto write_err;
		}
	}

	// Write the last part after the last field
	if (format_pos < strlen(format)) {
		unsigned int len = strlen(format) - format_pos;
		if (pom_write(file->fd, format + format_pos, len) != POM_OK)
			goto write_err;
	}

	if (pom_write(file->fd, "\n", 1) != POM_OK)
		goto write_err;

	pom_mutex_unlock(&file->lock);

	if (log_evt->priv && log_evt->priv->perf_events)
		registry_perf_inc(log_evt->priv->perf_events, 1);

	return POM_OK;

write_err:
	pom_mutex_unlock(&file->lock);
	pomlog(POMLOG_ERR "Error while writing to log file : %s", file->path);
	return POM_ERR;

}

int addon_log_txt_init(struct addon_plugin *a) {

	struct addon_log_txt_priv *priv = malloc(sizeof(struct addon_log_txt_priv));
	if (!priv) {
		pom_oom(sizeof(struct addon_log_txt_priv));
		return POM_ERR;
	}
	memset(priv, 0, sizeof(struct addon_log_txt_priv));

	if (pthread_mutex_init(&priv->txt_file.lock, NULL)) {
		pomlog(POMLOG_ERR "Error while initializing mutex : %s", pom_strerror(errno));
		free(priv);
		return POM_ERR;
	}

	priv->p_filename = ptype_alloc("string");
	priv->p_event = ptype_alloc("string");
	priv->p_format = ptype_alloc("string");
	
	if (!priv->p_filename || !priv->p_event || !priv->p_format)
		goto err;

	addon_plugin_set_priv(a, priv);

	if (addon_plugin_add_param(a, "filename", "log.txt", priv->p_filename) != POM_OK)
		goto err;
	
	if (addon_plugin_add_param(a, "event", "", priv->p_event) != POM_OK)
		goto err;
	
	if (addon_plugin_add_param(a, "format", "", priv->p_format) != POM_OK)
		goto err;

	return POM_OK;

err:
	addon_log_txt_cleanup(priv);
	return POM_ERR;
}

int addon_log_txt_cleanup(void *addon_priv) {

	if (!addon_priv)
		return POM_OK;
	
	struct addon_log_txt_priv *priv = addon_priv;
	if (priv->p_filename)
		ptype_cleanup(priv->p_filename);
	if (priv->p_event)
		ptype_cleanup(priv->p_event);
	if (priv->p_format)
		ptype_cleanup(priv->p_format);

	pthread_mutex_destroy(&priv->txt_file.lock);

	free(priv);

	return POM_OK;
}

int addon_log_txt_open(void *addon_priv) {

	struct addon_log_txt_priv *priv = addon_priv;

	char *evt_name = PTYPE_STRING_GETVAL(priv->p_event);

	if (!strlen(evt_name)) {
		pomlog(POMLOG_ERR "You need to specify an event name");
		return POM_ERR;
	}
	struct output_log_txt_event *txt_evt = &priv->txt_evt;

	txt_evt->evt = event_find(evt_name);

	if (!txt_evt->evt) {
		pomlog(POMLOG_ERR "Event %s not found", evt_name);
		return POM_ERR;
	}

	txt_evt->fields = output_log_txt_parse_fields(txt_evt->evt, PTYPE_STRING_GETVAL(priv->p_format));

	if (!txt_evt->fields) {
		pomlog(POMLOG_ERR "No field found in format");
		return POM_ERR;
	}

	txt_evt->format = PTYPE_STRING_GETVAL(priv->p_format);

	struct output_log_txt_file *txt_file = &priv->txt_file;

	// Only the path field need to be filled
	txt_file->path = PTYPE_STRING_GETVAL(priv->p_filename);
	txt_file->fd = -1;

	txt_evt->file = txt_file;

	return POM_OK;
}

int addon_log_txt_close(void *addon_priv) {

	struct addon_log_txt_priv *priv = addon_priv;

	struct output_log_txt_event *txt_evt = &priv->txt_evt;

	int i;
	for (i = 0; txt_evt->fields[i].id != -1; i++) {
		if (txt_evt->fields[i].key)
			free(txt_evt->fields[i].key);
	}

	free(txt_evt->fields);

	struct output_log_txt_file *txt_file = &priv->txt_file;
	if (txt_file->fd != -1) {
		close(txt_file->fd);
		txt_file->fd = -1;
	}

	return POM_OK;
}

int addon_log_txt_process(struct event *evt, void *addon_priv) {
	struct addon_log_txt_priv *priv = addon_priv;
	return output_log_txt_process(evt, &priv->txt_evt);
}
