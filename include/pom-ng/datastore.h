/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2012-2014 Guy Martin <gmsoft@tuxicoman.be>
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

#ifndef __POM_NG_DATASTORE_H__
#define __POM_NG_DATASTORE_H__

#include <pom-ng/base.h>
#include <pom-ng/registry.h>

/// Name of the table of the datasets
#define DATASTORE_DATASET_TABLE_NAME "dataset_db"

/// Name of the type dataset
#define DATASTORE_DATASET_SCHEMA_TABLE_NAME "dataset_schema"


#define DATASET_QUERY_OK		POM_OK
#define DATASET_QUERY_MORE		1
#define DATASET_QUERY_ERR		POM_ERR
#define DATASET_QUERY_DATASTORE_ERR	-2

/// Possible read directions
#define DATASET_READ_ORDER_ASC 0
#define DATASET_READ_ORDER_DESC 1

/// Condition flags
#define DATASET_COND_CLEANUP_VAL	1

// Private decl
struct datastore_reg;

/// Data value template
struct datavalue_template {
	char *name;
	char *type;
	unsigned int native_type; // Filled by the datastore
};

/// A data value
struct datavalue {
	struct ptype *value;
	unsigned int is_null;
};


/// Condition used in read and delete query
struct datavalue_condition {
	int op; ///< Ptype operation
	struct ptype *value; ///< Value to compare with
	short field_id; ///< Field to compare against
	int flags; ///< Condition flags
};

struct datavalue_read_order {
	short field_id; ///< Field to sort
	int direction; ///< False for ascending, true for descending
};

struct dataset_query {
	
	void *priv;

	struct datastore_connection *con;

	struct dataset *ds;

	struct datavalue *values;

	unsigned int prepared;
	uint64_t data_id; ///< id of the data in the dataset
	struct datavalue_condition *cond;
	struct datavalue_read_order *read_order;

};

/// A dataset
struct dataset {

	char *name;
	uint64_t dataset_id; // Used internaly
	unsigned int refcount;

	struct datavalue_template *data_template;

	void *priv; ///< Private data of the dataset

	int (*error_notify) (struct dataset *dset);

	struct datastore *dstore;

	struct dataset *next, *prev;

};

struct datastore_connection {
	void *priv;
	struct datastore *d;
	struct datastore_connection *prev, *next;
};

struct datastore {
	char *name; ///< Name of the datastore
	void *priv; ///< Private data of the datastore

	pthread_mutex_t lock;

	struct datastore_connection *con_main, *cons, *cons_unused;

	struct datastore_reg *reg;

	struct registry_instance *reg_instance;
	struct registry_param *reg_param_running;

	struct registry_perf *perf_read_queries;
	struct registry_perf *perf_write_queries;

	struct dataset *datasets; ///< List of all the datasets
	struct dataset *dataset_db; ///< Dataset containing the lists of dataset
	struct dataset *dataset_schema; ///< Dataset containing the schema of the datasets

	struct datastore *next;
	struct datastore *prev;

};

/// Saves infos about a registered datastore
struct datastore_reg_info {

	char *name; ///< Name of the datastore
	char *description; ///< Description of the datastore
	struct mod_reg *mod; ///< Module from which this datastore comes from

	int (*init) (struct datastore *d);
	int (*cleanup) (struct datastore *t);
	int (*connect) (struct datastore_connection *dc);
	int (*disconnect) (struct datastore_connection *dc);

	int (*transaction_begin) (struct datastore_connection *dc);
	int (*transaction_commit) (struct datastore_connection *dc);
	int (*transaction_rollback) (struct datastore_connection *dc);

	int (*dataset_alloc) (struct dataset *ds);
	int (*dataset_cleanup) (struct dataset *ds);
	int (*dataset_destroy) (struct dataset *ds);
	int (*dataset_create) (struct dataset *ds, struct datastore_connection *dc);
	int (*dataset_read) (struct dataset_query *dsq);
	int (*dataset_write) (struct dataset_query *dsq);
	int (*dataset_delete) (struct dataset_query *dsq);

	int (*dataset_query_alloc) (struct dataset_query *dsq);
	int (*dataset_query_prepare) (struct dataset_query *dsq);
	int (*dataset_query_cleanup) (struct dataset_query *dsq);

};


int datastore_register(struct datastore_reg_info *reg_info);
int datastore_unregister(char *name);

struct datastore *datastore_instance_get(char *datastore_name);

struct datastore_connection *datastore_connection_new(struct datastore *d);
int datastore_connection_release(struct datastore_connection *dc);
int datastore_transaction_begin(struct datastore_connection *dc);
int datastore_transaction_commit(struct datastore_connection *dc);
int datastore_transaction_rollback(struct datastore_connection *dc);

int datastore_dataset_close(struct dataset *ds);
int datastore_dataset_read(struct dataset_query *dsq);
int datastore_dataset_read_single(struct dataset_query *dsq);
int datastore_dataset_write(struct dataset_query *dsq);
int datastore_dataset_delete(struct dataset_query *dsq);

struct dataset_query *datastore_dataset_query_alloc(struct dataset *ds, struct datastore_connection *dc);
struct dataset_query *datastore_dataset_query_open(struct datastore *d, char *name, struct datavalue_template *dt, struct datastore_connection *dc);
int datastore_dataset_query_cleanup(struct dataset_query *dsq);
int datastore_dataset_query_set_condition(struct dataset_query *dsq, short field_id, int ptype_op, struct ptype *value);
int datastore_dataset_query_set_condition_copy(struct dataset_query *dsq, short field_id, int ptype_op, struct ptype *value);
int datastore_dataset_query_set_string_condition(struct dataset_query *dsq, short field_id, int ptype_op, char *value);
int datastore_dataset_query_set_uint64_condition(struct dataset_query *dsq, short field_id, int ptype_op, uint64_t value);
int datastore_dataset_query_unset_condition(struct dataset_query *dsq);

int datastore_dataset_query_set_order(struct dataset_query *dsq, short field_id, int direction);
int datastore_dataset_query_unset_order(struct dataset_query *dsq);

int datastore_add_param(struct datastore *d, struct registry_param *p);

#endif
