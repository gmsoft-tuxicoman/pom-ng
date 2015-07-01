/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2012-2015 Guy Martin <gmsoft@tuxicoman.be>
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

#include "resource.h"

struct resource *resource_open(char *resource_name, struct resource_template *template) {
	
	// Open the resource file

	char filename[FILENAME_MAX] = {0};

	strcpy(filename, RESOURCE_DIR);
	strncat(filename, resource_name, FILENAME_MAX - strlen(filename));
	strncat(filename, ".xml", FILENAME_MAX - strlen(filename));

	xmlDocPtr doc;
	xmlNodePtr root, cur;

	doc = xmlParseFile(filename);

	if (!doc) {
		pomlog(POMLOG_ERR "Error while opening resource file \"%s\"", filename);
		return NULL;
	}

	root = xmlDocGetRootElement(doc);

	if (!root) {
		pomlog(POMLOG_ERR "Resource file \"%s\" empty", resource_name);
		xmlFreeDoc(doc);
		return NULL;
	}

	if (xmlStrcmp(root->name, BAD_CAST "resource")) {
		pomlog(POMLOG_ERR "Root element <resource> not found");
		xmlFreeDoc(doc);
		return NULL;
	}

	for (cur = root->xmlChildrenNode; cur && xmlStrcmp(cur->name, BAD_CAST "datasets"); cur = cur->next);
	
	if (!cur) {
		pomlog(POMLOG_ERR "The element <datasets> wasn't found in the resource");
		xmlFreeDoc(doc);
		return NULL;
	}

	struct resource *res = malloc(sizeof(struct resource));
	if (!res) {
		xmlFreeDoc(doc);
		pom_oom(sizeof(struct resource));
		return NULL;
	}
	memset(res, 0, sizeof(struct resource));

	res->name = strdup(resource_name);
	if (!res->name) {
		free(res);
		xmlFreeDoc(doc);
		pom_oom(strlen(resource_name) + 1);
		return NULL;
	}

	res->doc = doc;
	res->ds_root = cur;
	res->tmplt = template;
	return res;
}

int resource_close(struct resource *r) {

	xmlFreeDoc(r->doc);
	free(r->name);
	free(r);

	return POM_OK;

}

struct resource_dataset *resource_dataset_open(struct resource *r, char *dset_name) {


	// Find the right dataset in the templates
	
	struct resource_template *t;
	for (t = r->tmplt; t->dataset_name && strcmp(t->dataset_name, dset_name); t++);

	if (!t->dataset_name) {
		pomlog(POMLOG_ERR "Dataset %s doesn't exists in the provided template", dset_name);
		return NULL;
	}

	// Find the right dataset in the resource file
	xmlNodePtr dset_node;

	char *name = NULL;
	for (dset_node = r->ds_root->xmlChildrenNode; dset_node; dset_node = dset_node->next) {
		name = (char *) xmlGetProp(dset_node, BAD_CAST "name");
		if (!name)
			continue;

		if (!strcmp(name, dset_name))
			break;

		xmlFree(name);
	}

	if (!dset_node) {
		pomlog(POMLOG_ERR "Dataset %s not found in resource %s", dset_name, r->name);
		return NULL;
	}
	xmlFree(name);

	// Allocate the resource dataset
	struct resource_dataset *ds = malloc(sizeof(struct resource_dataset));
	if (!ds) {
		pom_oom(sizeof(struct resource_dataset));
		return NULL;
	}
	memset(ds, 0, sizeof(struct resource_dataset));

	ds->name = strdup(dset_name);
	if (!ds->name) {
		pom_oom(strlen(dset_name) + 1);
		goto err;
	}

	ds->r = r;
	ds->dset_node = dset_node;
	ds->data_template = t->data_template;

	// Allocate the datavalue
	struct datavalue_template *dt = t->data_template;
	int count;
	for (count = 0; dt[count].name; count++);
	
	ds->values = malloc(sizeof(struct datavalue) * (count + 1));
	if (!ds->values) {
		pom_oom(sizeof(struct datavalue) * (count + 1));
		goto err;
	}
	memset(ds->values, 0, sizeof(struct datavalue) * (count + 1));

	int i;
	struct datavalue *dv = ds->values;
	dt = t->data_template;
	for (i = 0; i < count; i++) {
		dv[i].value = ptype_alloc(dt[i].type);
		if (!dv[i].value)
			goto err;
	}

	return ds;
err:

	if (ds->name)
		free(ds->name);
	
	if (ds->values) {
		for (i = 0; ds->values[i].value; i++)
			ptype_cleanup(ds->values[i].value);
		free(ds->values);
	}

	free(ds);

	return NULL;
}

int resource_dataset_close(struct resource_dataset *ds) {

	int i;
	for (i = 0; ds->values[i].value; i++)
		ptype_cleanup(ds->values[i].value);

	free(ds->values);
	free(ds->name);
	free(ds);

	return POM_OK;
}

int resource_dataset_read(struct resource_dataset *ds, struct datavalue **dvp) {

	struct datavalue *dv = ds->values;
	*dvp = dv;
	struct datavalue_template *dt = ds->data_template;

	if (!ds->cur) {
		// No current item, find the first one, start from scratch
		ds->cur = ds->dset_node->xmlChildrenNode;
	} else {
		// Advance to the next item
		ds->cur = ds->cur->next;
	}


	// Find the next item
	for (;ds->cur && xmlStrcmp(ds->cur->name, BAD_CAST "item"); ds->cur = ds->cur->next);

	if (!ds->cur) {
		// Nothing more
		return DATASET_QUERY_OK;
	}

	// Make all the values null
	int i;
	for (i = 0; dv[i].value; i++)
		dv[i].is_null = 1;

	// Parse all the values from xml
	xmlNodePtr val;
	for (val = ds->cur->xmlChildrenNode; val; val = val->next) {
		if (val->type != XML_ELEMENT_NODE)
			continue;

		// Find the value in our dataset
		char *name = (char *) val->name;
		for (i = 0; dt[i].name && strcmp(dt[i].name, name); i++);
		
		if (!dt[i].name) {
			pomlog(POMLOG_WARN "XML value \"%s\" isn't expected according the template", name);
			continue;
		}

		char *value_str = (char *) xmlNodeGetContent(val);
		if (!value_str) {
			pomlog(POMLOG_WARN "Empty value for \"%s\"", name);
			continue;
		}

		if (ptype_unserialize(dv[i].value, value_str) != POM_OK) {
			free(value_str);
			continue;
		}
		
		dv[i].is_null = 0;
		free(value_str);

	}

	return DATASET_QUERY_MORE;
}


