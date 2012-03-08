/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2012 Guy Martin <gmsoft@tuxicoman.be>
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


#ifndef __DATASTORE_SQLITE_H__
#define __DATASTORE_SQLITE_H__

#include <pom-ng/datastore.h>

#include <sqlite3.h>

#define DATASTORE_SQLITE_QUERY_BUFF_LEN 512

struct datastore_sqlite_priv {

	struct ptype *p_dbfile;
};

struct datastore_sqlite_connection_priv {

	sqlite3 *db;
};

struct dataset_sqlite_priv {
	char *read_query;
	char *write_query;
	char *delete_query;
};

struct dataset_sqlite_query_priv {
	sqlite3_stmt *read_stmt;
	sqlite3_stmt *write_stmt;
	sqlite3_stmt *delete_stmt;
};

static int datastore_sqlite_mod_register(struct mod_reg *mod);
static int datastore_sqlite_mod_unregister();

static int datastore_sqlite_init(struct datastore *d);
static int datastore_sqlite_cleanup(struct datastore *d);

static int datastore_sqlite_connect(struct datastore_connection *dc);
static int datastore_sqlite_disconnect(struct datastore_connection *dc);

static int datastore_sqlite_transaction_begin(struct datastore_connection *dc);
static int datastore_sqlite_transaction_commit(struct datastore_connection *dc);
static int datastore_sqlite_transaction_rollback(struct datastore_connection *dc);

static int datastore_sqlite_dataset_alloc(struct dataset *ds);
static int datastore_sqlite_dataset_cleanup(struct dataset *ds);
static int datastore_sqlite_dataset_create(struct dataset *ds, struct datastore_connection *dc);
static int datastore_sqlite_dataset_read(struct dataset_query *dsq);
static int datastore_sqlite_dataset_write(struct dataset_query *dsq);
static int datastore_sqlite_dataset_delete(struct dataset_query *dsq);

static int datastore_sqlite_dataset_query_alloc(struct dataset_query *dsq);
static int datastore_sqlite_dataset_query_prepare(struct dataset_query *dsq);
static int datastore_sqlite_dataset_query_cleanup(struct dataset_query *dsq);

static int datastore_sqlite_busy_callback(void *priv, int retries);
static int datastore_sqlite_get_ds_state_error(int errnum);
static size_t datastore_sqlite_escape_string(char *to, char *from, size_t len);

#endif


