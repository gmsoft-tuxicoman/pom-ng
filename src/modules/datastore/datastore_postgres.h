/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2013 Guy Martin <gmsoft@tuxicoman.be>
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


#ifndef __DATASTORE_POSTGRES_H__
#define __DATASTORE_POSTGRES_H__

#include <pom-ng/datastore.h>

#include <libpq-fe.h>

#define DATASTORE_POSTGRES_QUERY_BUFF_LEN 512

#define DATASTORE_POSTGRES_TRANSACTION_NONE	0x0
#define DATASTORE_POSTGRES_TRANSACTION_USER	0x1
#define DATASTORE_POSTGRES_TRANSACTION_TEMP	0x2

struct datastore_postgres_priv {

	struct ptype *p_dbname;
	struct ptype *p_host;
	struct ptype *p_port;
	struct ptype *p_user;
	struct ptype *p_password;
	struct ptype *p_async_commit;

	char *conninfo; // Connection string

	int integer_datetimes; // True if postgres server has timestamps as int64
};

struct datastore_postgres_connection_priv {

	PGconn *db;
	int transaction;
	pthread_mutex_t lock;
};

struct dataset_postgres_priv {
	char *query_read_start;
	char *query_read;
	char *query_read_end;
	char *query_write;
	char *query_write_get_id;
	int num_fields;
};

union datastore_postgres_data {
	
	uint8_t uint8;
	uint16_t uint16;
	uint32_t uint32;
	uint64_t uint64;
	int64_t int64;
	double dfloat;
	char *str;
	void *ptr;

};

struct dataset_postgres_query_priv {
	PGresult *read_res;
	char *query_read_start;
	unsigned int read_query_cur;
	unsigned int read_query_tot;
	union datastore_postgres_data *write_data_buff;
	char **write_query_param_val;
	int *write_query_param_len;
	int *write_query_param_format;

};

static int datastore_postgres_mod_register(struct mod_reg *mod);
static int datastore_postgres_mod_unregister();

static int datastore_postgres_init(struct datastore *d);
static int datastore_postgres_cleanup(struct datastore *d);

static int datastore_postgres_connect(struct datastore_connection *dc);
static int datastore_postgres_disconnect(struct datastore_connection *dc);

static int datastore_postgres_transaction_begin(struct datastore_connection *dc);
static int datastore_postgres_transaction_commit(struct datastore_connection *dc);
static int datastore_postgres_transaction_rollback(struct datastore_connection *dc);

static int datastore_postgres_dataset_alloc(struct dataset *ds);
static int datastore_postgres_dataset_cleanup(struct dataset *ds);
static int datastore_postgres_dataset_create(struct dataset *ds, struct datastore_connection *dc);
static int datastore_postgres_dataset_read(struct dataset_query *dsq);
static int datastore_postgres_dataset_write(struct dataset_query *dsq);
static int datastore_postgres_dataset_delete(struct dataset_query *dsq);

static int datastore_postgres_dataset_query_alloc(struct dataset_query *dsq);
static int datastore_postgres_dataset_query_prepare(struct dataset_query *dsq);
static int datastore_postgres_dataset_query_cleanup(struct dataset_query *dsq);


#endif


