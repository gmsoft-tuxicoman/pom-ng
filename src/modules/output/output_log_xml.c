/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2011-2013 Guy Martin <gmsoft@tuxicoman.be>
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


#include "output_log_xml.h"

#include <pom-ng/ptype_string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <libxml/xmlwriter.h>

static struct output_log_xml_priv *log_xml_init() {

	
	struct output_log_xml_priv *priv = malloc(sizeof(struct output_log_xml_priv));
	if (!priv) {
		pom_oom(sizeof(struct output_log_xml_priv));
		return NULL;
	}
	memset(priv, 0, sizeof(struct output_log_xml_priv));

	priv->fd = -1;
	
	priv->p_filename = ptype_alloc("string");

	if (!priv->p_filename) {
		output_log_xml_cleanup(priv);
		return NULL;
	}
	
	return priv;
}

int addon_log_xml_init(struct addon_plugin *a) {

	struct output_log_xml_priv *priv = log_xml_init();
	if (!priv)
		return POM_ERR;

	addon_plugin_set_priv(a, priv);

	if (addon_plugin_add_param(a, "filename", "log.xml", priv->p_filename) != POM_OK)
		goto err;

	return POM_OK;

err:
	output_log_xml_cleanup(priv);
	return POM_ERR;
	
}

int output_log_xml_init(struct output *o) {

	struct output_log_xml_priv *priv = log_xml_init();
	if (!priv)
		return POM_ERR;

	priv->p_source = ptype_alloc("string");
	if (!priv->p_source)
		goto err;

	output_set_priv(o, priv);

	struct registry_instance *inst = output_get_reg_instance(o);
	priv->perf_events = registry_instance_add_perf(inst, "events", registry_perf_type_counter, "Number of events process", "events");
	if (!priv->perf_events)
		goto err;

	struct registry_param *p = registry_new_param("filename", "log.xml", priv->p_filename, "XML log file", 0);
	if (registry_instance_add_param(inst, p) != POM_OK)
		goto err;

	p = registry_new_param("source", "", priv->p_source, "Define the type of event being logged", 0);
	if (registry_instance_add_param(inst, p) != POM_OK)
		goto err;

	return POM_OK;
err:
	output_log_xml_cleanup(priv);
	return POM_ERR;
}

int output_log_xml_cleanup(void *output_priv) {
	
	struct output_log_xml_priv *priv = output_priv;
	if (priv) {
		if (priv->fd != -1)
			close(priv->fd);
		if (priv->p_filename)
			ptype_cleanup(priv->p_filename);
		if (priv->p_source)
			ptype_cleanup(priv->p_source);
		free(priv);
	}

	return POM_OK;
}

int addon_log_xml_open(void *output_priv) {

	struct output_log_xml_priv *priv = output_priv;

	if (priv->fd != -1) {
		pomlog(POMLOG_ERR "Output already started");
		return POM_ERR;
	}

	char *filename = PTYPE_STRING_GETVAL(priv->p_filename);
	if (!strlen(filename)) {
		pomlog(POMLOG_ERR "You must specify a filename where to log the output");
		return POM_ERR;
	}

	priv->fd = open(filename, O_CREAT | O_WRONLY | O_APPEND, S_IRUSR | S_IWUSR | S_IRGRP);
	if (!priv->fd == -1) {
		pomlog(POMLOG_ERR "Error while opening log file \"%s\" : %s", filename, pom_strerror(errno));
		return POM_ERR;
	}

	return POM_OK;

}

int output_log_xml_open(void *output_priv) {

	struct output_log_xml_priv *priv = output_priv;

	if (addon_log_xml_open(priv) != POM_OK)
		return POM_ERR;

	char *src_name = PTYPE_STRING_GETVAL(priv->p_source);
	if (!strlen(src_name)) {
		pomlog(POMLOG_ERR "You need to specify a source for this output");
		goto err;
	}

	priv->evt = event_find(src_name);

	if (!priv->evt) {
		pomlog(POMLOG_ERR "Source \"%s\" does not exists", src_name);
		goto err;
	}


	// Listen to the right event
	if (event_listener_register(priv->evt, priv, NULL, output_log_xml_process) != POM_OK)
		goto err;

	return POM_OK;

err:
	if (priv->fd != -1) {
		close(priv->fd);
		priv->fd = -1;
	}

	priv->evt = NULL;


	return POM_ERR;

}

int addon_log_xml_close(void *output_priv) {
	
	struct output_log_xml_priv *priv = output_priv;

	if (priv->fd == -1) {
		pomlog(POMLOG_ERR "Output already stopped");
		return POM_ERR;
	}

	if (close(priv->fd)) {
		pomlog(POMLOG_ERR "Error while closing log file : %s", pom_strerror(errno));
		return POM_ERR;
	}

	return POM_OK;
}

int output_log_xml_close(void *output_priv) {

	struct output_log_xml_priv *priv = output_priv;

	if (addon_log_xml_close(priv) != POM_OK)
		return POM_ERR;

	event_listener_unregister(priv->evt, priv);

	return POM_OK;
}

int output_log_xml_process(struct event *evt, void *obj) {

	struct output_log_xml_priv *priv = obj;
	struct event_reg_info *evt_info = event_get_info(evt);

	xmlBufferPtr buff = xmlBufferCreate();
	if (!buff) {
		pomlog(POMLOG_ERR "Error while creating the xml buffer");
		return POM_ERR;
	}

	xmlTextWriterPtr writer = xmlNewTextWriterMemory(buff, 0);
	if (!writer) {
		pomlog(POMLOG_ERR "Error while creating the xmlTextWriter");
		xmlBufferFree(buff);
		return POM_ERR;
	}

	// <event name="event_name">
	
	if (xmlTextWriterWriteString(writer, BAD_CAST "\n") < 0 ||
		xmlTextWriterStartElement(writer, BAD_CAST "event") < 0 ||
		xmlTextWriterWriteAttribute(writer, BAD_CAST "name", BAD_CAST evt_info->name) < 0)
		goto err;

	int i;
	for (i = 0; i < evt_info->data_reg->data_count; i++) {
		if (evt_info->data_reg->items[i].flags & ANALYZER_DATA_FLAG_LIST) {
			// Got a data_list
		
			if (!evt->data[i].items)
				continue;

			// <data_list name="data_name">
			if (xmlTextWriterWriteString(writer, BAD_CAST "\n\t") < 0 ||
				xmlTextWriterStartElement(writer, BAD_CAST "data_list") < 0 ||
				xmlTextWriterWriteAttribute(writer, BAD_CAST "name", BAD_CAST evt_info->data_reg->items[i].name) < 0)
				goto err;

			// <value key="key1">
			struct data_item *itm = evt->data[i].items;
			for (; itm; itm = itm->next) {
				if (xmlTextWriterWriteString(writer, BAD_CAST "\n\t\t") < 0 ||
					xmlTextWriterStartElement(writer, BAD_CAST "value") < 0 ||
					xmlTextWriterWriteAttribute(writer, BAD_CAST "key", BAD_CAST itm->key) < 0)
					goto err;

				char *value = ptype_print_val_alloc(itm->value);
				if (!value)
					goto err;

				if (xmlTextWriterWriteString(writer, BAD_CAST value) < 0) {
					free(value);
					goto err;
				}

				free(value);

				// </value>
				if (xmlTextWriterEndElement(writer) < 0)
					goto err;

			}


			// </data_list>
			if (xmlTextWriterWriteString(writer, BAD_CAST "\n\t") < 0 ||
				xmlTextWriterEndElement(writer) < 0)
				goto err;

		} else {

			// Got a single data
			
			if (!data_is_set(evt->data[i]))
				continue;

			
			// <data name="data_name">

			if (xmlTextWriterWriteString(writer, BAD_CAST "\n\t") < 0 ||
				xmlTextWriterStartElement(writer, BAD_CAST "data") < 0 ||
				xmlTextWriterWriteAttribute(writer, BAD_CAST "name", BAD_CAST evt_info->data_reg->items[i].name) < 0)
				goto err;

			if (evt->data[i].value) {
				char *value = ptype_print_val_alloc(evt->data[i].value);
				if (!value)
					goto err;

				if (xmlTextWriterWriteString(writer, BAD_CAST value) < 0) {
					free(value);
					goto err;
				}

				free(value);
			}

			// </data>
			
			if (xmlTextWriterEndElement(writer) < 0)
				goto err;
		}
	}

	// </event>
	if (xmlTextWriterWriteString(writer, BAD_CAST "\n\n") < 0 ||
		xmlTextWriterEndElement(writer) < 0)
		goto err;

	xmlFreeTextWriter(writer);
	
	if (pom_write(priv->fd, buff->content, buff->use) != POM_OK) {
		pomlog(POMLOG_ERR "Error while writing to the log file");
		xmlBufferFree(buff);
		return POM_ERR;
	}

	xmlBufferFree(buff);

	if (priv->perf_events)
		registry_perf_inc(priv->perf_events, 1);

	return POM_OK;
err:
	pomlog(POMLOG_ERR "An error occured while processing the event");
	xmlFreeTextWriter(writer);
	xmlBufferFree(buff);
	
	return POM_ERR;

}
