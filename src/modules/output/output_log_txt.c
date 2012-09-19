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


#include "output_log_txt.h"

#include <pom-ng/ptype_string.h>
#include <pom-ng/resource.h>

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
	o->priv = priv;

	priv->p_prefix = ptype_alloc("string");
	priv->p_template = ptype_alloc("string");
	if (!priv->p_prefix || !priv->p_template)
		goto err;

	struct registry_param *p = registry_new_param("prefix", "./", priv->p_prefix, "Log files prefix", 0);
	if (registry_instance_add_param(o->reg_instance, p) != POM_OK)
		goto err;
	
	p = registry_new_param("template", "", priv->p_template, "Log template to use", 0);
	if (registry_instance_add_param(o->reg_instance, p) != POM_OK)
		goto err;

	return POM_OK;
err:

	output_log_txt_cleanup(priv);
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

int output_log_txt_open(void *output_priv) {

	struct output_log_txt_priv *priv = output_priv;

	struct resource *r = NULL;
	struct resource_dataset *r_templates = NULL, *r_events = NULL, *r_files = NULL;

	r = resource_open(OUTPUT_LOG_TXT_RESOURCE, output_log_txt_templates);

	if (!r)
		goto err;

	// Check that the given template exists
	char *template_name = PTYPE_STRING_GETVAL(priv->p_template);
	if (!strlen(template_name)) {
		pomlog(POMLOG_ERR "You need to specify a log template");
		return POM_ERR;
	}

	r_templates = resource_dataset_open(r, "templates");
	if (!r_templates)
		goto err;

	while (1) {
		struct datavalue *v;
		int res = resource_dataset_read(r_templates, &v);
		if (res < 0)
			goto err;
		if (res == DATASET_QUERY_OK) {
			pomlog(POMLOG_ERR "Log template %s does not exists");
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
			return POM_ERR;
		}
		memset(log_evt, 0, sizeof(struct output_log_txt_event));
		log_evt->output_priv = priv;

		// Add this event to our list
		log_evt->next = priv->events;
		if (log_evt->next)
			log_evt->next->prev = log_evt;

		priv->events = log_evt;

		log_evt->evt = evt;

		// Find in which file this event will be saved
		char *file = PTYPE_STRING_GETVAL(v[3].value);
		for (log_evt->file = priv->files; log_evt->file && strcmp(log_evt->file->name, file); log_evt->file = log_evt->file->next);
		if (!log_evt->file) {
			pomlog(POMLOG_ERR "File \"%s\" has not been decladed but it's used in event \"%s\"", file, evt_name);
			goto err;
		}
		
		// Listen to the event
		if (event_listener_register(evt, log_evt, NULL, output_log_txt_process) != POM_OK)
			goto err;

		// Parse the format of this event
		char *format = PTYPE_STRING_GETVAL(v[2].value);

		log_evt->format = strdup(format);
		if (!log_evt->format)
			goto err;

		unsigned int field_count = 0;
		struct output_log_txt_event_field *fields = NULL;
		char *sep = NULL, *cur = format;
		while ((sep = strchr(cur, '$'))) {
			unsigned int start_off = sep - format;
			sep++;
			cur = sep;
			while ((*cur >= '0' && *cur <= '9') || (*cur >= 'a' && *cur <= 'z') || *cur == '_')
				cur++;
			unsigned int end_off = cur - format;
			char name[256];
			memset(name, 0, sizeof(name));
			strncpy(name, sep, end_off - start_off - 1);
			
			struct data_reg *dreg = evt->info->data_reg;
			int i;
			for (i = 0; i < dreg->data_count && strcmp(dreg->items[i].name, name); i++);

			if (!dreg->items[i].name) {
				pomlog(POMLOG_WARN "Field %s not found in event %s", name, evt_name);
				sep = cur + 1;
				continue;
			}
			// TODO add support for arrays

			field_count++;
			struct output_log_txt_event_field *old_fields = fields;
			fields = realloc(fields, sizeof(struct output_log_txt_event_field) * (field_count + 1));
			if (!fields) {
				log_evt->fields = old_fields;
				pom_oom(sizeof(struct output_log_parsed_field *) * (field_count + 1));
				goto err;
			}
			memset(&fields[field_count - 1], 0, sizeof(struct output_log_txt_event_field) * 2);
			struct output_log_txt_event_field *field = &fields[field_count - 1];
			field->id = i;
			field->start_off = start_off;
			field->end_off = end_off;

			log_evt->fields = fields;
			
		}
		log_evt->field_count = field_count;

		if (!fields) {
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

		if (evt->fields)
			free(evt->fields);

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
	struct output_log_txt_priv *priv = log_evt->output_priv;

	// Open the log file
	struct output_log_txt_file *file = log_evt->file;

	pom_mutex_lock(&file->lock);
	if (file->fd == -1) {
		// File is not open, let's do it
		char filename[FILENAME_MAX + 1] = {0};
		char *prefix = PTYPE_STRING_GETVAL(priv->p_prefix);
		strcpy(filename, prefix);
		strncat(filename, file->path, FILENAME_MAX - strlen(filename));
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
	for (i = 0; i < log_evt->field_count; i++) {
	
		struct output_log_txt_event_field *field = &log_evt->fields[i];
		if (format_pos < field->start_off) {
			unsigned int len = field->start_off - format_pos;
			if (pom_write(file->fd, format + format_pos, len) != POM_OK)
				goto write_err;
		}

		format_pos = field->end_off;

		if (evt->data[field->id].value) {
			char *value = ptype_print_val_alloc(evt->data[field->id].value);
			if (!value) {
				pom_mutex_unlock(&file->lock);
				return POM_ERR;
			}
			if (pom_write(file->fd, value, strlen(value)) != POM_OK) {
				free(value);
				goto write_err;
			}
			free(value);
		} else {
			pom_write(file->fd, "-", 1);
		}
	}

	// Write the last part after the last field
	if (i == log_evt->field_count) {
		if (format_pos < strlen(format)) {
			unsigned int len = strlen(format) - format_pos;
			if (pom_write(file->fd, format + format_pos, len) != POM_OK)
				goto write_err;
		}
	}

	if (pom_write(file->fd, "\n", 1) != POM_OK)
		goto write_err;

	pom_mutex_unlock(&file->lock);

	return POM_OK;

write_err:
	pom_mutex_unlock(&file->lock);
	pomlog(POMLOG_ERR "Error while writing to log file : %s", file->path);
	return POM_ERR;

}
