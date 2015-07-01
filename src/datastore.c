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


#include "common.h"
#include "registry.h"
#include "datastore.h"
#include "mod.h"
#include "main.h"

#include <pom-ng/datastore.h>
#include <pom-ng/ptype_bool.h>
#include <pom-ng/ptype_uint16.h>
#include <pom-ng/ptype_uint64.h>
#include <pom-ng/ptype_string.h>

static struct registry_class *datastore_registry_class = NULL;
static struct datastore_reg *datastore_reg_head = NULL;
static struct datastore *datastore_head = NULL;

int datastore_init() {

	datastore_registry_class = registry_add_class(DATASTORE_REGISTRY);
	if (!datastore_registry_class)
		return POM_ERR;

	datastore_registry_class->instance_add = datastore_instance_add;
	datastore_registry_class->instance_remove = datastore_instance_remove;

	return POM_OK;

}

int datastore_cleanup() {

	if (datastore_registry_class)
		registry_remove_class(datastore_registry_class);
	datastore_registry_class = NULL;

	while (datastore_reg_head) {
		struct datastore_reg *tmp = datastore_reg_head;
		datastore_reg_head = tmp->next;
		mod_refcount_dec(tmp->module);
		free(tmp);
	}


	return POM_OK;

}

int datastore_register(struct datastore_reg_info *reg_info) {

	pomlog(POMLOG_DEBUG "Registering datastore %s", reg_info->name);


	struct datastore_reg *tmp;
	for (tmp = datastore_reg_head; tmp && strcmp(tmp->info->name, reg_info->name); tmp = tmp->next);
	if (tmp) {
		pomlog(POMLOG_ERR "Datastore %s already registered", reg_info->name);
		return POM_ERR;
	}

	struct datastore_reg *reg = malloc(sizeof(struct datastore_reg));
	if (!reg) {
		pom_oom(sizeof(struct datastore_reg));
		return POM_ERR;
	}
	memset(reg, 0, sizeof(struct datastore_reg));

	reg->info = reg_info;
	mod_refcount_inc(reg_info->mod);
	reg->module = reg_info->mod;


	if (registry_add_instance_type(datastore_registry_class, reg_info->name, reg_info->description) != POM_OK) {
		free(reg);
		return POM_ERR;
	}

	reg->next = datastore_reg_head;
	datastore_reg_head = reg;
	if (reg->next)
		reg->next->prev = reg;

	return POM_OK;

}

int datastore_unregister(char *name) {
	
	struct datastore_reg *reg;

	for (reg = datastore_reg_head; reg && strcmp(reg->info->name, name); reg = reg->next);
	if (!reg)
		return POM_OK;

	registry_remove_instance_type(datastore_registry_class, name);

	if (reg->prev)
		reg->prev->next = reg->next;
	else
		datastore_reg_head = reg->next;

	if (reg->next)
		reg->next->prev = reg->prev;

	reg->next = NULL;
	reg->prev = NULL;

	mod_refcount_dec(reg->module);

	free(reg);

	return POM_OK;

}

int datastore_instance_add(char *type, char *name) {

	struct datastore_reg *reg;
	for (reg = datastore_reg_head; reg && strcmp(reg->info->name, type); reg = reg->next);

	if (!reg) {
		pomlog(POMLOG_ERR "Datastore type %s does not esists", type);
		return POM_ERR;
	}

	struct datastore *res = malloc(sizeof(struct datastore));
	if (!res) {
		pom_oom(sizeof(struct datastore));
		return POM_ERR;
	}
	memset(res, 0, sizeof(struct datastore));


	if (pom_mutex_init_type(&res->lock, PTHREAD_MUTEX_RECURSIVE) != POM_OK) {
		free(res);
		return POM_ERR;
	}

	res->reg = reg;
	res->name = strdup(name);
	if (!res->name)
		goto err;

	res->reg_instance = registry_add_instance(datastore_registry_class, name);

	if (!res->reg_instance)
		goto err;

	res->perf_read_queries = registry_instance_add_perf(res->reg_instance, "read_queries", registry_perf_type_counter, "Number of read queries issued", "queries");
	res->perf_write_queries = registry_instance_add_perf(res->reg_instance, "write_queries", registry_perf_type_counter, "Number of write queries issued", "queries");

	if (!res->perf_read_queries || !res->perf_write_queries)
		goto err;

	struct ptype *datastore_type = ptype_alloc("string");
	if (!datastore_type)
		goto err;

	struct registry_param *type_param = registry_new_param("type", type, datastore_type, "Type of the datastore", REGISTRY_PARAM_FLAG_CLEANUP_VAL | REGISTRY_PARAM_FLAG_IMMUTABLE);
	if (!type_param) {
		ptype_cleanup(datastore_type);
		goto err;
	}

	if (registry_instance_add_param(res->reg_instance, type_param) != POM_OK) {
		registry_cleanup_param(type_param);
		ptype_cleanup(datastore_type);
		goto err;
	}

	res->reg_instance->priv = res;

	if (registry_uid_create(res->reg_instance) != POM_OK)
		goto err;

	if (reg->info->init) {
		if (reg->info->init(res) != POM_OK) {
			pomlog(POMLOG_ERR "Error while initializing the datastore %s", name);
			goto err;
		}
	}

	res->next = datastore_head;
	if (res->next)
		res->next->prev = res;

	datastore_head = res;

	return POM_OK;

err:

	pthread_mutex_destroy(&res->lock);

	if (res->name)
		free(res->name);

	if (res->reg_instance)
		registry_remove_instance(res->reg_instance);

	free(res);

	return POM_ERR;

}


int datastore_instance_remove(struct registry_instance *ri) {
	
	struct datastore *d = ri->priv;

	if (!d)
		return POM_OK;

	if (d == system_datastore()) {
		system_datastore_close();
		pomlog(POMLOG_WARN "The system datastore is being removed");
	}

	if (d->reg->info->cleanup) {
		if (d->reg->info->cleanup(d) != POM_OK) {
			pomlog(POMLOG_ERR "Error while cleaning up the datastore");
			return POM_ERR;
		}
	}

	pthread_mutex_destroy(&d->lock);

	free(d->name);
	
	if (d->prev)
		d->prev->next = d->next;
	else
		datastore_head = d->next;

	if (d->next)
		d->next->prev = d->prev;

	free(d);

	return POM_OK;
}

int datastore_open(struct datastore *d) {

	if (!d)
		return POM_ERR;

	pom_mutex_lock(&d->lock);

	if (d->con_main) {
		pom_mutex_unlock(&d->lock);
		return POM_OK;
	}

	d->con_main = malloc(sizeof(struct datastore_connection));
	if (!d->con_main) {
		pom_mutex_unlock(&d->lock);
		pom_oom(sizeof(struct datastore_connection));
		return POM_ERR;
	}
	memset(d->con_main, 0, sizeof(struct datastore_connection));
	d->con_main->d = d;

	if (d->reg->info->connect(d->con_main) != POM_OK) {
		pom_mutex_unlock(&d->lock);
		pomlog(POMLOG_ERR "Error while connecting to datastore %s", d->reg->info->name);
		return POM_ERR;
	}


	struct datavalue_template *ds_template = NULL;

	// Allocate the dataset_db

	static struct datavalue_template dataset_db_template[] = {
		{ .name = "name", .type = "string" }, // Name of the dataset
		{ .name = "description", .type = "string" }, // Description of the dataset
		{ 0 }
	};


	struct dataset_query *dataset_db_query = NULL, *dataset_schema_query = NULL;

	d->dataset_db = datastore_dataset_alloc(d, dataset_db_template, DATASTORE_DATASET_TABLE);
	if (!d->dataset_db)
		goto err;

	// Add this dataset to the global list
	d->dataset_db->next = d->datasets;
	d->datasets = d->dataset_db;


	// Allocate the dataset_schema
	
	static struct datavalue_template dataset_schema_template[] = {
		{ .name = "dataset_id", .type = "uint64" },
		{ .name = "name", .type = "string" },
		{ .name = "type", .type = "string" },
		{ .name = "field_id", .type = "uint16" },
		{ 0 }
	};

	d->dataset_schema = datastore_dataset_alloc(d, dataset_schema_template, DATASTORE_DATASET_SCHEMA_TABLE);
	if (!d->dataset_schema)
		goto err;

	// Add the dsschema datasets to the list of datasets
	
	d->datasets->prev = d->dataset_schema;
	d->dataset_schema->next = d->datasets;
	d->datasets = d->dataset_schema;

	dataset_db_query = datastore_dataset_query_alloc(d->dataset_db, NULL);
	if (!dataset_db_query)
		goto err;

	dataset_schema_query = datastore_dataset_query_alloc(d->dataset_schema, NULL);
	if (!dataset_schema_query)
		goto err;

	// Fetch the existings datasets

	int found = 0;

	while (1) {
		int res = datastore_dataset_read(dataset_db_query);
		if (res == DATASET_QUERY_OK) {
			found = 1;
			break;
		} else if (res == DATASET_QUERY_ERR) {
			break;
		} else if (res == DATASET_QUERY_DATASTORE_ERR) {
			goto err;
		}

		if (dataset_db_query->values[0].is_null) {
			pomlog(POMLOG_ERR "Dataset name is NULL");
			goto err;
		}

	

		// Set read condition
		struct ptype *dsid = NULL;
		dsid = ptype_alloc("uint64");
		if (!dsid)
			goto err;
		PTYPE_UINT64_SETVAL(dsid, dataset_db_query->data_id);
		datastore_dataset_query_set_condition(dataset_schema_query, 0, PTYPE_OP_EQ, dsid);

		unsigned int datacount = 0;

		while (1) {
			res = datastore_dataset_read(dataset_schema_query);
			if (res == DATASET_QUERY_OK) {
				found = 1;
				break;
			} else if (res == DATASET_QUERY_ERR) {
				goto err;
			} else if (res == DATASET_QUERY_DATASTORE_ERR) {
				goto err;
			}
			struct datavalue_template *tmp_template = realloc(ds_template, sizeof(struct datavalue_template) * (datacount + 2));
			if (!tmp_template) {
				pom_oom(sizeof(struct datavalue_template) * (datacount + 2));
				goto err;
			}
			ds_template = tmp_template;
			memset(&tmp_template[datacount], 0, sizeof(struct datavalue_template) * 2);

			char *name = PTYPE_STRING_GETVAL(dataset_schema_query->values[1].value);
			if (dataset_schema_query->values[1].is_null) {
				pomlog(POMLOG_ERR "NULL value for template entry name");
				goto err;
			}
			ds_template[datacount].name = strdup(name);
			if (!ds_template[datacount].name) {
				pom_oom(strlen(name) + 1);
				goto err;
			}

			char *type = PTYPE_STRING_GETVAL(dataset_schema_query->values[2].value);
			if (dataset_schema_query->values[2].is_null) {
				pomlog(POMLOG_ERR "NULL value for template entry type");
				goto err;
			}
			ds_template[datacount].type = strdup(type);
			if (!ds_template[datacount].type)
				goto err;

			datacount++;

		}


		struct dataset *ds = datastore_dataset_alloc(d, ds_template, PTYPE_STRING_GETVAL(dataset_db_query->values[0].value));
		if (!ds)
			goto err;

		ds->next = d->datasets;
		if (ds->next)
			ds->next->prev = ds;

		d->datasets = ds;

		ds_template = NULL;

	}

	datastore_dataset_query_cleanup(dataset_db_query);
	dataset_db_query = NULL;
	datastore_dataset_query_cleanup(dataset_schema_query);
	dataset_schema_query = NULL;


	ds_template = NULL;

	if (!found) {
		
		if (datastore_transaction_begin(d->con_main) != POM_OK)
			goto err;

		if (datastore_dataset_create(d->dataset_db, d->con_main) != POM_OK) {
			datastore_transaction_rollback(d->con_main);
			goto err;
		}

		if (datastore_dataset_create(d->dataset_schema, d->con_main) != POM_OK) {
			datastore_transaction_rollback(d->con_main);
			goto err;
		}

		if (datastore_transaction_commit(d->con_main) != POM_OK) {
			datastore_transaction_rollback(d->con_main);
			goto err;
		}

	}

	pom_mutex_unlock(&d->lock);



	pomlog(POMLOG_DEBUG "Datastore %s opened", d->reg->info->name);

	return POM_OK;

err:


	if (dataset_db_query)
		datastore_dataset_query_cleanup(dataset_db_query);

	if (dataset_schema_query)
		datastore_dataset_query_cleanup(dataset_schema_query);

	struct dataset *dset = NULL;
	for (dset = d->datasets; d->datasets; dset = d->datasets) {
		if (d->reg->info->dataset_cleanup && d->reg->info->dataset_cleanup(dset) != POM_OK)
			pomlog(POMLOG_WARN "Warning : error while cleaning up the dataset %s from datastore %s", dset->name, d->name);
		
		d->datasets = dset->next;

		if (dset != d->dataset_db && dset != d->dataset_schema) { // Those two have a static template
			int i;
			for (i = 0; dset->data_template[i].name; i++) {
				free(dset->data_template[i].name);
				free(dset->data_template[i].type);
			}

			free(dset->data_template);
		}

		free(dset->name);
		free(dset);
	}

	d->reg->info->disconnect(d->con_main);
	free(d->con_main);

	if (ds_template) {
		int i;
		for (i = 0; ds_template[i].name || ds_template[i].type; i++) {
			if (ds_template[i].name)
				free(ds_template[i].name);

			if (ds_template[i].type)
				free(ds_template[i].type);

		}

		free(ds_template);
	}

	pom_mutex_unlock(&d->lock);

	return POM_ERR;
}

int datastore_close(struct datastore *d) {

	if (!d)
		return POM_ERR;

	pom_mutex_lock(&d->lock);

	if (!d->con_main) {
		pom_mutex_unlock(&d->lock);
		return POM_OK;
	}

	if (d->cons) {
		pomlog(POMLOG_ERR "Cannot close datastore, some connections are still active");
		pom_mutex_unlock(&d->lock);
		return POM_ERR;
	}

	struct dataset* dset = d->datasets;

	// Check if all datasets are unused
	while (dset) {

		if (dset->refcount) {
			pomlog(POMLOG_ERR "Cannot close datastore %s as the dataset %s is still in use", d->name, dset->name);
			pom_mutex_unlock(&d->lock);
			return POM_ERR;
		}
		dset = dset->next;
	}

	dset = d->datasets;

	// Cleanup all the datasets
	
	for (dset = d->datasets; d->datasets; dset = d->datasets) {
		if (d->reg->info->dataset_cleanup && d->reg->info->dataset_cleanup(dset) != POM_OK)
			pomlog(POMLOG_WARN "Warning : error while cleaning up the dataset %s from datastore %s", dset->name, d->name);
		
		d->datasets = dset->next;

		if (dset != d->dataset_db && dset != d->dataset_schema) { // Those two have a static template
			int i;
			for (i = 0; dset->data_template[i].name; i++) {
				free(dset->data_template[i].name);
				free(dset->data_template[i].type);
			}

			free(dset->data_template);
		}

		free(dset->name);
		free(dset);
	}

	d->dataset_db = NULL;
	d->dataset_schema = NULL;

	// Close the datastore

	while (d->cons_unused) {
		struct datastore_connection *tmp = d->cons_unused;
		d->cons_unused = tmp->next;
		if (d->reg->info->disconnect(tmp) != POM_OK)
			pomlog(POMLOG_WARN "Warning: error while closing a datastore connection");
		free(tmp);
	}
	
	if (d->reg->info->disconnect(d->con_main) != POM_OK)
		pomlog(POMLOG_WARN "Warning : error while closing the main datastore connection");
	free(d->con_main);
	d->con_main = NULL;

	pom_mutex_unlock(&d->lock);

	return POM_OK;
}

struct datastore_connection *datastore_connection_new(struct datastore *d) {

	if (!d)
		return NULL;

	pom_mutex_lock(&d->lock);
	struct datastore_connection *res = d->cons_unused;

	if (!res) {
		res = malloc(sizeof(struct datastore_connection));
		if (!res) {
			pom_mutex_unlock(&d->lock);
			pom_oom(sizeof(struct datastore_connection));
			return NULL;
		}
		memset(res, 0, sizeof(struct datastore_connection));
		res->d = d;

		if (d->reg->info->connect(res) != POM_OK) {
			pom_mutex_unlock(&d->lock);
			pomlog(POMLOG_ERR "Error while creating new connection to datastore %s", d->name);
			free(res);
			return NULL;
		}

		res->next = d->cons;
		if (res->next)
			res->next->prev = res;

		d->cons = res;
	} else {
		d->cons_unused = res->next;
		if (d->cons_unused && d->cons_unused->prev)
			d->cons_unused->prev = NULL;

		res->next = NULL;
		res->prev = NULL;

	}

	pom_mutex_unlock(&d->lock);

	
	return res;
}

int datastore_connection_release(struct datastore_connection *dc) {
	
	struct datastore *d = dc->d;

	pom_mutex_lock(&d->lock);
	
	if (dc->prev)
		dc->prev->next = dc->next;
	else
		d->cons = dc->next;

	if (dc->next)
		dc->next->prev = dc->prev;

	dc->next = d->cons_unused;
	
	if (dc->next)
		dc->next->prev = dc;

	d->cons_unused = dc;

	pom_mutex_unlock(&d->lock);

	return POM_OK;
}

int datastore_transaction_begin(struct datastore_connection *dc) {

	return dc->d->reg->info->transaction_begin(dc);
}

int datastore_transaction_commit(struct datastore_connection *dc) {

	return dc->d->reg->info->transaction_commit(dc);
}

int datastore_transaction_rollback(struct datastore_connection *dc) {

	return dc->d->reg->info->transaction_rollback(dc);
}

struct datastore *datastore_instance_get(char *datastore_name) {
	struct datastore *res;
	for (res = datastore_head; res && strcmp(res->name, datastore_name); res = res->next);

	return res;
}

struct dataset *datastore_dataset_open(struct datastore *d, char *name, struct datavalue_template *dt, struct datastore_connection *dc) {

	struct dataset *res = NULL;

	struct datavalue_template *new_dt = NULL;
	int i;

	struct datastore_connection *tmp_dc = dc;
	struct dataset_query *dataset_db_query = NULL, *dataset_schema_query = NULL;

	pom_mutex_lock(&d->lock);

	if (!d->con_main) {
		if (datastore_open(d) != POM_OK) {
			pom_mutex_unlock(&d->lock);
			return NULL;
		}
	}

	for (res = d->datasets; res && strcmp(res->name, name); res = res->next);
	
	if (res) {
		if (res->refcount) { // Datastore found and already open
			pom_mutex_unlock(&d->lock);
			return res;
		}
		
		struct datavalue_template *flds = res->data_template;
		int i;

		for (i = 0; dt[i].name; i++) {
			if (!flds->name || strcmp(dt[i].name, flds[i].name) || strcmp(dt[i].type, flds[i].type)) {
				pom_mutex_unlock(&d->lock);
				pomlog(POMLOG_ERR "Cannot open dataset %s. Missmatch in provided vs existing fields", name);
				return NULL;
			}
		}

	} else {
		pomlog("Dataset %s doesn't exists in datastore %s. Creating it ...", name, d->name);

		// Copy the template
		for (i = 0; dt[i].name; i++);
		i++;

		size_t size = sizeof(struct datavalue_template) * i;
		new_dt = malloc(size);
		if (!new_dt) {
			pom_mutex_unlock(&d->lock);
			pom_oom(size);
			return NULL;
		}
		memset(new_dt, 0, size);
		
		for (i = 0; dt[i].name; i++) {

			new_dt[i].name = strdup(dt[i].name);
			if (!new_dt[i].name) {
				pom_oom(strlen(dt[i].name) + 1);
				goto err;
			}

			new_dt[i].type = strdup(dt[i].type);
			if (!new_dt[i].type) {
				pom_oom(strlen(dt[i].type) + 1);
				goto err;
			}
		}

		// Allocate the new dataset
		res = datastore_dataset_alloc(d, new_dt, name);
		if (!res)
			goto err;

		if (!tmp_dc) {
			// No connection provided. Create a new one to isolate this creation
			tmp_dc = datastore_connection_new(d);
			if (!tmp_dc)
				goto err;
			if (datastore_transaction_begin(tmp_dc) != POM_OK)
				goto err;
		}


		if (datastore_dataset_create(res, tmp_dc) != POM_OK)
			goto err;

		dataset_db_query = datastore_dataset_query_alloc(d->dataset_db, tmp_dc);
		if (!dataset_db_query)
			goto err;

		// Add it in the database
		PTYPE_STRING_SETVAL(dataset_db_query->values[0].value, name);
		dataset_db_query->values[0].is_null = 0;
		dataset_db_query->values[1].is_null = 1;
		if (datastore_dataset_write(dataset_db_query) != POM_OK)
			goto err;

		res->dataset_id = dataset_db_query->data_id;

		dataset_schema_query = datastore_dataset_query_alloc(d->dataset_schema, tmp_dc);
		if (!dataset_schema_query)
			goto err;

		for (i = 0; dt[i].name; i++) {
			PTYPE_UINT64_SETVAL(dataset_schema_query->values[0].value, res->dataset_id);
			dataset_schema_query->values[0].is_null = 0;
			PTYPE_STRING_SETVAL(dataset_schema_query->values[1].value, dt[i].name);
			dataset_schema_query->values[1].is_null = 0;
			PTYPE_STRING_SETVAL(dataset_schema_query->values[2].value, dt[i].type);
			dataset_schema_query->values[2].is_null = 0;
			PTYPE_UINT16_SETVAL(dataset_schema_query->values[3].value, i);
			dataset_schema_query->values[3].is_null = 0;


			if (datastore_dataset_write(dataset_schema_query) != POM_OK)
				goto err;

		}

		if (!dc) {
			if (datastore_transaction_commit(tmp_dc) != POM_OK)
				goto err;

			datastore_connection_release(tmp_dc);
		}

		datastore_dataset_query_cleanup(dataset_db_query);
		datastore_dataset_query_cleanup(dataset_schema_query);

		// Add it in the list of datasets
		res->next = d->datasets;
		if (res->next)
			res->next->prev = res;
		d->datasets = res;

	}

	pom_mutex_unlock(&d->lock);

	return res;

err:

	pom_mutex_unlock(&d->lock);

	if (!dc && tmp_dc) {
		datastore_transaction_rollback(tmp_dc);
		datastore_connection_release(tmp_dc);
	}

	if (dataset_db_query)
		datastore_dataset_query_cleanup(dataset_db_query);
	
	if (dataset_schema_query)
		datastore_dataset_query_cleanup(dataset_schema_query);

	if (new_dt) {
		for (i = 0; new_dt[i].name || new_dt[i].type; i++) {
			if (new_dt[i].name)
				free(new_dt[i].name);
			if (new_dt[i].type)
				free(new_dt[i].type);
		}
		free(new_dt);
	}

	if (!res)
		return NULL;

	datastore_dataset_cleanup(res);

	return NULL;

}

struct dataset *datastore_dataset_alloc(struct datastore *d, struct datavalue_template *dt, char *name) {

	struct dataset *ds = malloc(sizeof(struct dataset));
	if (!ds) {
		pom_oom(sizeof(struct dataset));
		return NULL;
	}
	memset(ds, 0, sizeof(struct dataset));

	ds->data_template = dt;
	
	ds->name = strdup(name);
	if (!ds->name) {
		pom_oom(strlen(name) + 1);
		goto err;
	}

	ds->dstore = d;

	if (d->reg->info->dataset_alloc) {
		if (d->reg->info->dataset_alloc(ds) != POM_OK)
			goto err;
	}

	return ds;

err:
	if (ds->name)
		free(ds->name);

	free(ds);

	return NULL;
}

int datastore_dataset_cleanup(struct dataset *ds) {

	struct datastore *d = ds->dstore;
	
	if (d->reg->info->dataset_cleanup) {
		if (d->reg->info->dataset_cleanup(ds) != POM_OK)
			return POM_ERR;
	}

	free(ds->name);
	free(ds);

	return POM_OK;

}

int datastore_dataset_create(struct dataset *ds, struct datastore_connection *dc) {

	struct datastore *d = ds->dstore;

	int res = DATASET_QUERY_OK;

	res = d->reg->info->dataset_create(ds, dc);

	if (res != DATASET_QUERY_OK) {
		// TODO error notify
		return POM_ERR;
	}

	return POM_OK;

}

int datastore_dataset_read(struct dataset_query *dsq) {

	struct datastore *d = dsq->ds->dstore;

	if (!dsq->prepared) {
		if (d->reg->info->dataset_query_prepare) {
			int res = d->reg->info->dataset_query_prepare(dsq);
			if (res != DATASET_QUERY_OK)
				return res;
		}
		
		dsq->prepared = 1;
	}

	// FIXME handle error

	registry_perf_inc(d->perf_read_queries, 1);
	return d->reg->info->dataset_read(dsq);

}

int datastore_dataset_read_single(struct dataset_query *dsq) {
	
	int res = datastore_dataset_read(dsq);

	if (res == DATASET_QUERY_OK) // If nothing found
		return DATASET_QUERY_OK;
	
	if (res == DATASET_QUERY_MORE) {
		// Got one output
		res = datastore_dataset_read(dsq);
		if (res == DATASET_QUERY_OK)
			return DATASET_QUERY_MORE; // Found exactly one match, good

		if (res == DATASET_QUERY_MORE) { // more than one match :-(
			while (datastore_dataset_read(dsq) == DATASET_QUERY_MORE);
			return DATASET_QUERY_ERR;
		}

	}
		
	return res;

}

int datastore_dataset_write(struct dataset_query *dsq) {

	struct datastore *d = dsq->ds->dstore;

	if (!dsq->prepared) {
		if (d->reg->info->dataset_query_prepare) {
			int res = d->reg->info->dataset_query_prepare(dsq);
			if (res != DATASET_QUERY_OK)
				return res;
		}
		
		dsq->prepared = 1;
	}
	
	// FIXME handle error
	
	registry_perf_inc(d->perf_write_queries, 1);
	return d->reg->info->dataset_write(dsq);

}

int datastore_dataset_delete(struct dataset_query *dsq) {

	struct datastore *d = dsq->ds->dstore;

	if (!dsq->prepared) {
		if (d->reg->info->dataset_query_prepare) {
			int res = d->reg->info->dataset_query_prepare(dsq);
			if (res != DATASET_QUERY_OK)
				return res;
		}
		
		dsq->prepared = 1;
	}
	
	// FIXME handle error
	
	return d->reg->info->dataset_delete(dsq);

}

struct dataset_query *datastore_dataset_query_alloc(struct dataset *ds, struct datastore_connection *dc) {

	struct datastore *d = ds->dstore;
	struct dataset_query *query = malloc(sizeof(struct dataset_query));
	if (!query) {
		pom_oom(sizeof(struct dataset_query));
		return NULL;
	}
	memset(query, 0, sizeof(struct dataset_query));
	query->ds = ds;

	if (dc)
		query->con = dc;
	else
		query->con = d->con_main;

	int datacount;
	for (datacount = 0; ds->data_template[datacount].name; datacount++);

	query->values = malloc(sizeof(struct datavalue) * datacount);
	if (!query->values) {
		free(query);
		pom_oom(sizeof(struct datavalue) * datacount);
		return NULL;
	}
	memset(query->values, 0, sizeof(struct datavalue) * datacount);

	int i;
	for (i = 0; i < datacount; i++) {
		query->values[i].value = ptype_alloc(ds->data_template[i].type);
		if (!query->values[i].value)
			goto err;
	}


	if (d->reg->info->dataset_query_alloc) {
		if (d->reg->info->dataset_query_alloc(query) != POM_OK)
			goto err;
	}

	pom_mutex_lock(&ds->dstore->lock);
	ds->refcount++;
	pom_mutex_unlock(&ds->dstore->lock);

	return query;

err:
	
	for (i = 0; i < datacount; i++) {
		if (query->values[i].value)
			ptype_cleanup(query->values[i].value);
	}

	free(query->values);

	free(query);
	return NULL;

}

struct dataset_query *datastore_dataset_query_open(struct datastore *d, char *name, struct datavalue_template *dt, struct datastore_connection *dc) {

	struct dataset *ds = datastore_dataset_open(d, name, dt, dc);
	if (!ds)
		return NULL;

	struct dataset_query *dsq = datastore_dataset_query_alloc(ds, dc);

	return dsq;
}

int datastore_dataset_query_cleanup(struct dataset_query *dsq) {

	struct datastore *d = dsq->ds->dstore;
	if (d->reg->info->dataset_query_cleanup)
		d->reg->info->dataset_query_cleanup(dsq);

	int i;
	for (i = 0; dsq->ds->data_template[i].name; i++)
		ptype_cleanup(dsq->values[i].value);
	
	free(dsq->values);

	if (dsq->cond) {
		if (dsq->cond->value)
			ptype_cleanup(dsq->cond->value);
		free(dsq->cond);
	}

	if (dsq->read_order)
		free(dsq->read_order);

	pom_mutex_lock(&dsq->ds->dstore->lock);
	dsq->ds->refcount--;
	pom_mutex_unlock(&dsq->ds->dstore->lock);

	free(dsq);

	return POM_OK;
}

int datastore_dataset_query_set_condition(struct dataset_query *dsq, short field_id, int ptype_op, struct ptype *value) {

	dsq->prepared = 0;
	
	if (!dsq->cond) {
		dsq->cond = malloc(sizeof(struct datavalue_condition));
		if (!dsq->cond) {
			pom_oom(sizeof(struct datavalue_condition));
			return POM_ERR;
		}
		memset(dsq->cond, 0, sizeof(struct datavalue_condition));
	}

	struct datavalue_condition *cond = dsq->cond;

	cond->field_id = field_id;
	cond->op = ptype_op;

	if (cond->value)
		ptype_cleanup(cond->value);
	cond->value = value;

	return POM_OK;
}

int datastore_dataset_query_set_condition_copy(struct dataset_query *dsq, short field_id, int ptype_op, struct ptype *value) {

	struct ptype *new_val = ptype_alloc_from(value);
	if (!new_val)
		return POM_ERR;
	if (datastore_dataset_query_set_condition(dsq, field_id, ptype_op, new_val) != POM_OK) {
		ptype_cleanup(new_val);
		return POM_ERR;
	}

	return POM_OK;
}

int datastore_dataset_query_set_string_condition(struct dataset_query *dsq, short field_id, int ptype_op, char *value) {
	
	struct ptype *str = ptype_alloc("string");
	if (!str)
		return POM_ERR;

	PTYPE_STRING_SETVAL(str, value);

	if (datastore_dataset_query_set_condition(dsq, field_id, ptype_op, str) != POM_OK) {
		ptype_cleanup(str);
		return POM_ERR;
	}

	return POM_OK;
}

int datastore_dataset_query_set_uint64_condition(struct dataset_query *dsq, short field_id, int ptype_op, uint64_t value) {
	
	struct ptype *uint64 = ptype_alloc("uint64");
	if (!uint64)
		return POM_ERR;

	PTYPE_UINT64_SETVAL(uint64, value);

	if (datastore_dataset_query_set_condition(dsq, field_id, ptype_op, uint64) != POM_OK) {
		ptype_cleanup(uint64);
		return POM_ERR;
	}

	return POM_OK;

}

int datastore_dataset_query_unset_condition(struct dataset_query *dsq) {

	if (!dsq->cond)
		return POM_OK;

	if (dsq->cond->value)
		ptype_cleanup(dsq->cond->value);
	free(dsq->cond);
	dsq->cond = NULL;

	dsq->prepared = 0;

	return POM_OK;
}

int datastore_dataset_query_set_order(struct dataset_query *dsq, short field_id, int direction) {


	if (!dsq->read_order) {
		dsq->read_order = malloc(sizeof(struct datavalue_read_order));
		if (!dsq->read_order) {
			pom_oom(sizeof(struct datavalue_read_order));
			return POM_ERR;
		}
		memset(dsq->read_order, 0, sizeof(struct datavalue_read_order));
	}

	dsq->read_order->field_id = field_id;
	dsq->read_order->direction = direction;

	dsq->prepared = 0;

	return POM_OK;
}

int datastore_dataset_query_unset_order(struct dataset_query *dsq) {

	if (!dsq->read_order)
		return POM_OK;

	free(dsq->read_order);
	dsq->read_order = NULL;

	dsq->prepared = 0;

	return POM_OK;
}


int datastore_add_param(struct datastore *d, struct registry_param *p) {

	if (!(p->flags & (REGISTRY_PARAM_FLAG_NOT_LOCKED_WHILE_RUNNING | REGISTRY_PARAM_FLAG_IMMUTABLE)))
		registry_param_set_callbacks(p, d, datastore_param_locked_while_connected, NULL);

	 return registry_instance_add_param(d->reg_instance, p);
}

int datastore_param_locked_while_connected(void *datastore, struct registry_param *p, char *param) {

	struct datastore *d = datastore;

	int res = POM_ERR;
	pom_mutex_lock(&d->lock);
	if (!d->cons) {
		if (datastore_close(d) != POM_OK) {
			pom_mutex_unlock(&d->lock);
			return POM_ERR;
		}
		res = POM_OK;
	} else {
		pomlog("Cannot change parameter '%s' of datastore %s while it's in use", d->name, p->name);
	}
	pom_mutex_unlock(&d->lock);

	return res;
}
