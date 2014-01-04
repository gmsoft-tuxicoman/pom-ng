/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2013-2014 Guy Martin <gmsoft@tuxicoman.be>
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


#include "datastore_postgres.h"

#include <pom-ng/ptype_bool.h>
#include <pom-ng/ptype_uint8.h>
#include <pom-ng/ptype_uint16.h>
#include <pom-ng/ptype_uint32.h>
#include <pom-ng/ptype_uint64.h>
#include <pom-ng/ptype_string.h>
#include <pom-ng/ptype_timestamp.h>

#include <stdio.h>
#include <arpa/inet.h>

#define DATASTORE_POSTGRES_PKID "pkid"

#define DATASTORE_POSTGRES_PTYPE_OTHER		0
#define DATASTORE_POSTGRES_PTYPE_BOOL		1
#define DATASTORE_POSTGRES_PTYPE_UINT8		2
#define DATASTORE_POSTGRES_PTYPE_UINT16		3
#define DATASTORE_POSTGRES_PTYPE_UINT32		4
#define DATASTORE_POSTGRES_PTYPE_UINT64		5
#define DATASTORE_POSTGRES_PTYPE_STRING		6
#define DATASTORE_POSTGRES_PTYPE_TIMESTAMP	7


// A few defines for timestamps
#define POSTGRES_EPOCH_JDATE	2451545
#define UNIX_EPOCH_JDATE	2440588
#define SECS_PER_DAY		86400


struct mod_reg_info *datastore_postgres_reg_info() {

	static struct mod_reg_info reg_info;
	memset(&reg_info, 0, sizeof(struct mod_reg_info));
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = datastore_postgres_mod_register;
	reg_info.unregister_func = datastore_postgres_mod_unregister;
	reg_info.dependencies = "ptype_bool, ptype_string, ptype_uint8, ptype_uint16, ptype_uint32, ptype_uint64, ptype_timestamp";
	
	return &reg_info;
}

static int datastore_postgres_mod_register(struct mod_reg *mod) {

	static struct datastore_reg_info datastore_postgres = {0};
	datastore_postgres.name = "postgres";
	datastore_postgres.description = "Connect to a PostgreSQL server";
	datastore_postgres.mod = mod;
	datastore_postgres.init = datastore_postgres_init;
	datastore_postgres.cleanup = datastore_postgres_cleanup;
	datastore_postgres.connect = datastore_postgres_connect;
	datastore_postgres.disconnect = datastore_postgres_disconnect;
	datastore_postgres.transaction_begin = datastore_postgres_transaction_begin;
	datastore_postgres.transaction_commit = datastore_postgres_transaction_commit;
	datastore_postgres.transaction_rollback = datastore_postgres_transaction_rollback;
	datastore_postgres.dataset_alloc = datastore_postgres_dataset_alloc;
	datastore_postgres.dataset_cleanup = datastore_postgres_dataset_cleanup;
	datastore_postgres.dataset_create = datastore_postgres_dataset_create;
	datastore_postgres.dataset_read = datastore_postgres_dataset_read;
	datastore_postgres.dataset_write = datastore_postgres_dataset_write;
	datastore_postgres.dataset_delete = datastore_postgres_dataset_delete;
	datastore_postgres.dataset_query_alloc = datastore_postgres_dataset_query_alloc;
	datastore_postgres.dataset_query_prepare = datastore_postgres_dataset_query_prepare;
	datastore_postgres.dataset_query_cleanup = datastore_postgres_dataset_query_cleanup;

	return datastore_register(&datastore_postgres);

}

static int datastore_postgres_mod_unregister() {

	return datastore_unregister("postgres");
}

static int datastore_postgres_init(struct datastore *d) {

	struct datastore_postgres_priv *priv = malloc(sizeof(struct datastore_postgres_priv));
	if (!priv) {
		pom_oom(sizeof(struct datastore_postgres_priv));
		return POM_ERR;
	}
	memset(priv, 0, sizeof(struct datastore_postgres_priv));

	d->priv = priv;

	struct registry_param *p = NULL;

	priv->p_dbname = ptype_alloc("string");
	priv->p_host = ptype_alloc("string");
	priv->p_port = ptype_alloc("string");
	priv->p_user = ptype_alloc("string");
	priv->p_password = ptype_alloc("string");
	priv->p_async_commit = ptype_alloc("bool");

	if (!priv->p_dbname || !priv->p_host || !priv->p_port || !priv->p_user || !priv->p_password || !priv->p_async_commit) {
		datastore_postgres_cleanup(d);
		return POM_ERR;
	}

	p = registry_new_param("dbname", "pom-ng", priv->p_dbname, "Database name", 0);
	if (registry_instance_add_param(d->reg_instance, p) != POM_OK) {
		registry_cleanup_param(p);
		goto err;
	}

	p = registry_new_param("host", "localhost", priv->p_host, "Server hostname", 0);
	if (registry_instance_add_param(d->reg_instance, p) != POM_OK) {
		registry_cleanup_param(p);
		goto err;
	}

	p = registry_new_param("port", "", priv->p_port, "Server port", 0);
	if (registry_instance_add_param(d->reg_instance, p) != POM_OK) {
		registry_cleanup_param(p);
		goto err;
	}

	p = registry_new_param("user", "", priv->p_user, "Username", 0);
	if (registry_instance_add_param(d->reg_instance, p) != POM_OK) {
		registry_cleanup_param(p);
		goto err;
	}

	p = registry_new_param("password", "", priv->p_password, "Password", 0);
	if (registry_instance_add_param(d->reg_instance, p) != POM_OK) {
		registry_cleanup_param(p);
		goto err;
	}

	p = registry_new_param("async_commit", "yes", priv->p_async_commit, "Perform asynchronous commit", 0);
	if (registry_instance_add_param(d->reg_instance, p) != POM_OK) {
		registry_cleanup_param(p);
		goto err;
	}


	// Init timezone and daylight variable
	tzset();

	return POM_OK;
err:

	if (p)
		registry_cleanup_param(p);

	datastore_postgres_cleanup(d);

	return POM_ERR;
}

static int datastore_postgres_cleanup(struct datastore *d) {

	struct datastore_postgres_priv *priv = d->priv;

	if (!priv)
		return POM_OK;

	if (priv->p_dbname)
		ptype_cleanup(priv->p_dbname);
	if (priv->p_host)
		ptype_cleanup(priv->p_host);
	if (priv->p_port)
		ptype_cleanup(priv->p_port);
	if (priv->p_user)
		ptype_cleanup(priv->p_user);
	if (priv->p_password)
		ptype_cleanup(priv->p_password);
	if (priv->p_async_commit)
		ptype_cleanup(priv->p_async_commit);

	free(priv);

	return POM_OK;
}

static int datastore_postgres_create_conninfo(struct datastore_postgres_priv *priv) {

	char *conninfo = NULL;

	char *dbname = malloc((strlen(PTYPE_STRING_GETVAL(priv->p_dbname)) * 2) + 1);
	PQescapeString(dbname, PTYPE_STRING_GETVAL(priv->p_dbname), strlen(PTYPE_STRING_GETVAL(priv->p_dbname)));
	
	unsigned int len = strlen("dbname='") + strlen(dbname) + strlen("'");
	conninfo = malloc(len + 1);
	memset(conninfo, 0, len + 1);

	// DB name
	strcpy(conninfo, "dbname='");
	strcat(conninfo, dbname);
	strcat(conninfo, "'");
	free(dbname);

	char *host = PTYPE_STRING_GETVAL(priv->p_host);
	if (host && *host) {
		char *ehost = malloc((strlen(host) * 2) + 1);
		PQescapeString(ehost, host, strlen(host));
		len += strlen(" host='") + strlen(ehost) + strlen("'");
		conninfo = realloc(conninfo, len + 1);
		strcat(conninfo, " host='");
		strcat(conninfo, ehost);
		strcat(conninfo, "'");
		free(ehost);
	}

	char *port = PTYPE_STRING_GETVAL(priv->p_port);
	if (port && *port) {
		char *eport = malloc((strlen(port) * 2) + 1);
		PQescapeString(eport, port, strlen(port));
		len += strlen(" port='") + strlen(eport) + strlen("'");
		conninfo = realloc(conninfo, len + 1);
		strcat(conninfo, " port='");
		strcat(conninfo, eport);
		strcat(conninfo, "'");
		free(eport);
	}


	char *user = PTYPE_STRING_GETVAL(priv->p_user);
	if (user && *user) {
		char *euser = malloc((strlen(user) * 2) + 1);
		PQescapeString(euser, user, strlen(user));
		len += strlen(" user='") + strlen(euser) + strlen("'");
		conninfo = realloc(conninfo, len + 1);
		strcat(conninfo, " user='");
		strcat(conninfo, euser);
		strcat(conninfo, "'");
		free(euser);
	}

	char *pass = PTYPE_STRING_GETVAL(priv->p_password);
	if (pass && *pass) {
		char *epass = malloc((strlen(pass) * 2) + 1);
		PQescapeString(epass, pass, strlen(pass));
		len += strlen(" password='") + strlen(epass) + strlen("'");
		conninfo = realloc(conninfo, len + 1);
		strcat(conninfo, " password='");
		strcat(conninfo, epass);
		strcat(conninfo, "'");
		free(epass);
	}

	priv->conninfo = conninfo;

	return POM_OK;
}

static void datastore_postgres_notice_processor(void *arg, const char *message) {

	if (!message)
		return;

	char *msg = strdup(message);

	if (!msg) {
		pom_oom(strlen(message));
		return;
	}

	do {
		size_t len = strlen(msg);
		if (len < 1)
			break;
		if (msg[len - 1] == '\r' || msg[len - 1] == '\n') {
			msg[len - 1] = 0;
		} else {
			break;
		}
	} while (1);

	pomlog(POMLOG_DEBUG "%s", msg);

	free(msg);
}

static int datastore_postgres_connect(struct datastore_connection *dc) {

	struct datastore_postgres_priv *priv = dc->d->priv;

	// Create the connection string
	if (!priv->conninfo && datastore_postgres_create_conninfo(priv) != POM_OK) {
		return POM_ERR;
	}

	int allocated = 0;
	struct datastore_postgres_connection_priv *cpriv = dc->priv;
	if (!cpriv) {
		cpriv = malloc(sizeof(struct datastore_postgres_connection_priv));
		if (!cpriv) {
			pom_oom(sizeof(struct datastore_postgres_connection_priv));
			return POM_ERR;
		}
		memset(cpriv, 0, sizeof(struct datastore_postgres_connection_priv));

		if (pthread_mutex_init(&cpriv->lock, NULL)) {
			pomlog(POMLOG_ERR "Error while initializing the mutex lock : %s", pom_strerror(errno));
			free(cpriv);
			return POM_ERR;
		}

		allocated = 1;
	}

	if (cpriv->db && PQstatus(cpriv->db) == CONNECTION_OK)
		return POM_OK;

	pomlog(POMLOG_DEBUG "Connecting using \"%s\"", priv->conninfo);

	cpriv->db = PQconnectdb(priv->conninfo);

	if (PQstatus(cpriv->db) != CONNECTION_OK) {
		char *error = PQerrorMessage(cpriv->db);
		char *br = strchr(error, '\n');
		if (br)
			*br = 0;
		pomlog(POMLOG_ERR "Unable to connect : %s", error);
		goto err;
	}

	PQsetNoticeProcessor(cpriv->db, datastore_postgres_notice_processor, NULL);

	// Find out how to deal with timestamps
	const char *integer_datetimes = PQparameterStatus(cpriv->db, "integer_datetimes");
	if (!integer_datetimes) {
		pomlog(POMLOG_ERR "Unable to determine binary format for TIMESTAMP fields");
		goto err;
	}

	if (!strcmp(integer_datetimes, "on"))
		priv->integer_datetimes = 1;
	else
		priv->integer_datetimes = 0;

	// Set client encoding to UTF-8
	PGresult *res = PQexec(cpriv->db, "SET client_encoding TO \"UTF-8\";");
	if (PQresultStatus(res) != PGRES_COMMAND_OK) {
		pomlog(POMLOG_ERR "Unable to set client encoding to UTF-8");
		PQclear(res);
		goto err;
	}
	PQclear(res);

	// Enable or disable asynchronous commit
	char *async_commit_query = "SET synchronous_commit TO OFF;";
	if (!PTYPE_BOOL_GETVAL(priv->p_async_commit))
		async_commit_query = "SET synchronous_commit TO ON;";

	res = PQexec(cpriv->db, async_commit_query);
	if (PQresultStatus(res) != PGRES_COMMAND_OK) {
		pomlog(POMLOG_ERR "Unable to set synchronous_commit parameter");
		PQclear(res);
		goto err;
	}
	PQclear(res);

	pomlog(POMLOG_DEBUG "New connection to database %s on %s", PTYPE_STRING_GETVAL(priv->p_dbname), PTYPE_STRING_GETVAL(priv->p_host));

	dc->priv = cpriv;

	return POM_OK;

err:

	if (cpriv->db) {
		PQfinish(cpriv->db);
		cpriv->db = NULL;
	}

	if (allocated) {
		pthread_mutex_destroy(&cpriv->lock);
		free(cpriv);
	}

	return POM_ERR;
}

static int datastore_postgres_get_ds_state_error(PGresult *res) {

	char *errcode = PQresultErrorField(res, PG_DIAG_SQLSTATE);

	switch (*errcode) { // Select correct state depending on error class
		case '2':
		case '3':
		case '4':
			// Likely to be a dataset specific error
			return DATASET_QUERY_ERR;
	}

	return DATASET_QUERY_DATASTORE_ERR;

}

static int datastore_postgres_exec(struct datastore_connection *dc, const char *query) {

	struct datastore_postgres_connection_priv *cpriv = dc->priv;
	struct datastore_postgres_priv *priv = dc->d->priv;

	PGresult *pgres = PQexec(cpriv->db, query);

	if (PQresultStatus(pgres) != PGRES_COMMAND_OK) {
		if (PQstatus(cpriv->db) == CONNECTION_BAD) { // Try to reconnect

			PQclear(pgres);
			pomlog(POMLOG_WARN "Connection to database %s on %s lost. Reconnecting", PTYPE_STRING_GETVAL(priv->p_dbname), PTYPE_STRING_GETVAL(priv->p_host));
			PQfinish(cpriv->db);

			if (datastore_postgres_connect(dc) == POM_ERR) {
				return DATASET_QUERY_DATASTORE_ERR;
			}

			if (cpriv->transaction != DATASTORE_POSTGRES_TRANSACTION_NONE) {
				cpriv->transaction = DATASTORE_POSTGRES_TRANSACTION_NONE;
				return DATASET_QUERY_ERR;
			}

			// We should be reconnected now
			pgres = PQexec(cpriv->db, query);
			if (PQresultStatus(pgres) == PGRES_COMMAND_OK) {
				PQclear(pgres);
				return DATASET_QUERY_OK;
			}
		}

		pomlog(POMLOG_ERR "Failed to execute query : %s", PQresultErrorMessage(pgres));
		
		int res = datastore_postgres_get_ds_state_error(pgres);
		PQclear(pgres);
		return res;


	}

	PQclear(pgres);
	return DATASET_QUERY_OK;

}

static int datastore_postgres_disconnect(struct datastore_connection *dc) {

	struct datastore_postgres_connection_priv *cpriv = dc->priv;

	if (pthread_mutex_destroy(&cpriv->lock)) {
		pomlog(POMLOG_ERR "Error while cleaning up the transaction lock");
	}
	PQfinish(cpriv->db);
	free(cpriv);

	pomlog(POMLOG_DEBUG "Connection to the database closed");

	return POM_OK;
}

static int datastore_postgres_transaction_begin(struct datastore_connection *dc) {
	
	struct datastore_postgres_connection_priv *cpriv = dc->priv;

	pom_mutex_lock(&cpriv->lock);

	if (cpriv->transaction != DATASTORE_POSTGRES_TRANSACTION_NONE) {
		pomlog(POMLOG_ERR "Temporary transactions are already in progress, complete your queries first");
		pom_mutex_unlock(&cpriv->lock);
		return DATASET_QUERY_ERR;
	}

	int res = datastore_postgres_exec(dc, "BEGIN");

	if (res != DATASET_QUERY_OK) {
		pomlog(POMLOG_ERR "Failed to begin transaction on datastore \"%s\" : %s", dc->d->name, PQerrorMessage(cpriv->db));
		res = POM_ERR;
	} else {
		cpriv->transaction = DATASTORE_POSTGRES_TRANSACTION_USER;
		res = POM_OK;
	}
	pom_mutex_unlock(&cpriv->lock);

	return res;
}

static int datastore_postgres_transaction_commit(struct datastore_connection *dc) {

	struct datastore_postgres_connection_priv *cpriv = dc->priv;

	pom_mutex_lock(&cpriv->lock);

	if (cpriv->transaction != DATASTORE_POSTGRES_TRANSACTION_USER) {
		if (cpriv->transaction == DATASTORE_POSTGRES_TRANSACTION_NONE)
			pomlog(POMLOG_ERR "No transaction in progress");
		else
			pomlog(POMLOG_ERR "Cannot finish temporary transactions");
		pom_mutex_unlock(&cpriv->lock);
		return DATASET_QUERY_ERR;
	}

	int res = datastore_postgres_exec(dc, "COMMIT");
	if (res != DATASET_QUERY_OK) {
		pomlog(POMLOG_ERR "Failed to commit transaction on datastore \"%s\" : %s", dc->d->name, PQerrorMessage(cpriv->db));
		res = POM_ERR;
	} else {
		cpriv->transaction = DATASTORE_POSTGRES_TRANSACTION_NONE;
		res = POM_OK;
	}
	pom_mutex_unlock(&cpriv->lock);

	return res;
}

static int datastore_postgres_transaction_rollback(struct datastore_connection *dc) {
	
	struct datastore_postgres_connection_priv *cpriv = dc->priv;
	pom_mutex_lock(&cpriv->lock);
	if (cpriv->transaction != DATASTORE_POSTGRES_TRANSACTION_USER) {
		if (cpriv->transaction == DATASTORE_POSTGRES_TRANSACTION_NONE)
			pomlog(POMLOG_ERR "No transaction in progress");
		else
			pomlog(POMLOG_ERR "Cannot finish temporary transactions");
		pom_mutex_unlock(&cpriv->lock);
		return DATASET_QUERY_ERR;
	}

	int res = datastore_postgres_exec(dc, "ROLLBACK");
	if (res != DATASET_QUERY_OK) {
		pomlog(POMLOG_ERR "Failed to rollback transaction on datastore \"%s\" : %s", dc->d->name, PQerrorMessage(cpriv->db));
		res = POM_ERR;
	} else {
		cpriv->transaction = DATASTORE_POSTGRES_TRANSACTION_NONE;;
		res = POM_OK;
	}
	pom_mutex_unlock(&cpriv->lock);

	return res;

}


static int datastore_postgres_dataset_alloc(struct dataset *ds) {

	// Binary cursor query
	char query_read_start[DATASTORE_POSTGRES_QUERY_BUFF_LEN] = { 0 };
	snprintf(query_read_start, sizeof(query_read_start) - strlen(query_read_start), "DECLARE %s_cur BINARY CURSOR FOR SELECT " DATASTORE_POSTGRES_PKID ", ", ds->name);

	int i;
	struct datavalue_template *dt = ds->data_template;
	for (i = 0; dt[i].name; i++) {
		if (!strcmp(dt[i].type, "bool"))
			dt[i].native_type = DATASTORE_POSTGRES_PTYPE_BOOL;
		else if (!strcmp(dt[i].type, "uint8"))
			dt[i].native_type = DATASTORE_POSTGRES_PTYPE_UINT8;
		else if (!strcmp(dt[i].type, "uint16"))
			dt[i].native_type = DATASTORE_POSTGRES_PTYPE_UINT16;
		else if (!strcmp(dt[i].type, "uint32"))
			dt[i].native_type = DATASTORE_POSTGRES_PTYPE_UINT32;
		else if (!strcmp(dt[i].type, "uint64"))
			dt[i].native_type = DATASTORE_POSTGRES_PTYPE_UINT64;
		else if (!strcmp(dt[i].type, "string"))
			dt[i].native_type = DATASTORE_POSTGRES_PTYPE_STRING;
		else if (!strcmp(dt[i].type, "timestamp"))
			dt[i].native_type = DATASTORE_POSTGRES_PTYPE_TIMESTAMP;
		else
			dt[i].native_type = DATASTORE_POSTGRES_PTYPE_OTHER;

		strncat(query_read_start, dt[i].name, sizeof(query_read_start) - strlen(query_read_start) - 2);
		if (dt[i + 1].name)
			strncat(query_read_start, ", ", sizeof(query_read_start) - strlen(query_read_start));
	}

	strncat(query_read_start, " FROM ", sizeof(query_read_start) - strlen(query_read_start));
	strncat(query_read_start, ds->name, sizeof(query_read_start) - strlen(query_read_start));

	if (strlen(query_read_start) >= sizeof(query_read_start) - 2) {
		pomlog(POMLOG_ERR "Read query_read_start is too long");
		return POM_ERR;
	}

	pomlog(POMLOG_DEBUG "Read start query : %s", query_read_start);
	
	// Fetch query
	char query_read[DATASTORE_POSTGRES_QUERY_BUFF_LEN] = { 0 };
	snprintf(query_read, sizeof(query_read), "FETCH ALL IN %s_cur", ds->name);

	pomlog(POMLOG_DEBUG "Read query : %s", query_read);

	// End query	
	char query_read_end[DATASTORE_POSTGRES_QUERY_BUFF_LEN] = { 0 };
	snprintf(query_read_end, sizeof(query_read_end), "CLOSE %s_cur", ds->name);
	pomlog(POMLOG_DEBUG "Read end query : %s", query_read_end);

	// Write query
	char query_write[DATASTORE_POSTGRES_QUERY_BUFF_LEN] = { 0 };
	snprintf(query_write, sizeof(query_write), "INSERT INTO %s ( " DATASTORE_POSTGRES_PKID ", ", ds->name);

	for (i = 0; dt[i].name; i++) {
		strncat(query_write, dt[i].name, sizeof(query_write) - strlen(query_write));
		if (dt[i + 1].name)
			strncat(query_write, ", ", sizeof(query_write) - strlen(query_write));
	}

	strncat(query_write, ") VALUES ( nextval('", sizeof(query_write) - strlen(query_write));
	strncat(query_write, ds->name, sizeof(query_write) - strlen(query_write));
	strncat(query_write, "_seq'), ", sizeof(query_write) - strlen(query_write));

	for (i = 0; dt[i].name; i++) {
		switch (dt[i].native_type) {
			case DATASTORE_POSTGRES_PTYPE_BOOL:
				snprintf(query_write + strlen(query_write), sizeof(query_write) - strlen(query_write), "$%u::boolean", i + 1);
				break;
			case DATASTORE_POSTGRES_PTYPE_UINT8:
			case DATASTORE_POSTGRES_PTYPE_UINT16:
				snprintf(query_write + strlen(query_write), sizeof(query_write) - strlen(query_write), "$%u::smallint", i + 1);
				break;
			case DATASTORE_POSTGRES_PTYPE_UINT32:
				snprintf(query_write + strlen(query_write), sizeof(query_write) - strlen(query_write), "$%u::integer", i + 1);
				break;
			case DATASTORE_POSTGRES_PTYPE_UINT64:
				snprintf(query_write + strlen(query_write), sizeof(query_write) - strlen(query_write), "$%u::bigint", i + 1);
				break;
			case DATASTORE_POSTGRES_PTYPE_TIMESTAMP:
				snprintf(query_write + strlen(query_write), sizeof(query_write) - strlen(query_write), "$%u::timestamp", i + 1);
				break;
			default:
				snprintf(query_write + strlen(query_write), sizeof(query_write) - strlen(query_write), "$%u::bytea", i + 1);
				break;
		}
		if (dt[i + 1].name)
			strncat(query_write, ", ", sizeof(query_write) - strlen(query_write));
	}
	strncat(query_write, ");", sizeof(query_write) - strlen(query_write));
	pomlog(POMLOG_DEBUG "Write query : %s", query_write);
	
	if (strlen(query_write) >= sizeof(query_write) - 2) {
		pomlog(POMLOG_ERR "Read query_write is too long");
		return POM_ERR;
	}

	char query_write_get_id[DATASTORE_POSTGRES_QUERY_BUFF_LEN] = { 0 };
	snprintf(query_write_get_id, sizeof(query_write_get_id), "SELECT currval('%s_seq');", ds->name);


	struct dataset_postgres_priv *priv = malloc(sizeof(struct dataset_postgres_priv));
	if (!priv) {
		pom_oom(sizeof(struct dataset_postgres_priv));
		return POM_ERR;
	}
	memset(priv, 0, sizeof(struct dataset_postgres_priv));

	ds->priv = priv;

	priv->query_read_start = strdup(query_read_start);
	priv->query_read = strdup(query_read);
	priv->query_read_end = strdup(query_read_end);
	priv->query_write = strdup(query_write);
	priv->query_write_get_id = strdup(query_write_get_id);

	if (!priv->query_read_start ||
		!priv->query_read ||
		!priv->query_read_end ||
		!priv->query_write ||
		!priv->query_write_get_id) {

		pom_oom(strlen(query_read));
		datastore_postgres_dataset_cleanup(ds);

		return POM_ERR;
	}

	priv->num_fields = i;

	return POM_OK;

}

static int datastore_postgres_dataset_cleanup(struct dataset *ds) {

	struct dataset_postgres_priv *priv = ds->priv;
	if (priv->query_read_start)
		free(priv->query_read_start);
	if (priv->query_read)
		free(priv->query_read);
	if (priv->query_read_end)
		free(priv->query_read_end);
	if (priv->query_write)
		free(priv->query_write);
	if (priv->query_write_get_id)
		free(priv->query_write_get_id);
	free(priv);

	return POM_OK;

}

static int datastore_postgres_dataset_create(struct dataset *ds, struct datastore_connection *dc) {

	char query_create[DATASTORE_POSTGRES_QUERY_BUFF_LEN];
	snprintf(query_create, sizeof(query_create), "CREATE SEQUENCE %s_seq; CREATE TABLE %s (" DATASTORE_POSTGRES_PKID " bigint NOT NULL PRIMARY KEY, ", ds->name, ds->name);

	struct datavalue_template *dt = ds->data_template;
	int i;
	for (i = 0; dt[i].name; i++) {
		char *type = " bytea";
		switch (dt[i].native_type) {
			case DATASTORE_POSTGRES_PTYPE_BOOL:
				type = " boolean";
				break;
			case DATASTORE_POSTGRES_PTYPE_UINT8:
			case DATASTORE_POSTGRES_PTYPE_UINT16:
				type = " smallint";
				break;
			case DATASTORE_POSTGRES_PTYPE_UINT32:
				type = " integer";
				break;
			case DATASTORE_POSTGRES_PTYPE_UINT64:
				type = " bigint";
				break;
			case DATASTORE_POSTGRES_PTYPE_TIMESTAMP:
				type = " timestamp";
				break;
		}
		strncat(query_create, dt[i].name, sizeof(query_create) - strlen(query_create));
		strncat(query_create, type, sizeof(query_create) - strlen(query_create));
		if (dt[i + 1].name)
			strncat(query_create, ", ", sizeof(query_create) - strlen(query_create));
	}
	strncat(query_create, " );", sizeof(query_create) - strlen(query_create));

	if (strlen(query_create) >= DATASTORE_POSTGRES_QUERY_BUFF_LEN - 2) {
		pomlog(POMLOG_ERR "Create query too long");
		return POM_ERR;
	}

	pomlog(POMLOG_DEBUG "CREATE QUERY : %s", query_create);

	struct datastore_postgres_connection_priv *cpriv = dc->priv;

	int res = datastore_postgres_exec(dc, query_create);

	if (res != DATASET_QUERY_OK) {
		pomlog(POMLOG_ERR "Failed to create dataset \"%s\" : %s", ds->name, PQerrorMessage(cpriv->db));
		return POM_ERR;
	}
	return POM_OK;

}

static int datastore_postgres_dataset_query_alloc(struct dataset_query *dsq) {
	
	struct dataset_postgres_query_priv *priv = malloc(sizeof(struct dataset_postgres_query_priv));
	if (!priv) {
		pom_oom(sizeof(struct dataset_postgres_query_priv));
		return POM_ERR;
	}
	memset(priv, 0, sizeof(struct dataset_postgres_query_priv));
	dsq->priv = priv;

	struct dataset_postgres_priv *dpriv = dsq->ds->priv;

	priv->write_data_buff = malloc(sizeof(union datastore_postgres_data) * dpriv->num_fields);
	priv->write_query_param_val = malloc(sizeof(char *) * dpriv->num_fields);
	priv->write_query_param_len = malloc(sizeof(int *) * dpriv->num_fields);
	priv->write_query_param_format = malloc(sizeof(int) * dpriv->num_fields);
	
	if (!priv->write_data_buff ||
		!priv->write_query_param_val ||
		!priv->write_query_param_len ||
		!priv->write_query_param_format) {
		pom_oom(sizeof(union datastore_postgres_data) * dpriv->num_fields);
		datastore_postgres_dataset_query_cleanup(dsq);
		return POM_ERR;
	}

	int i;
	for (i = 0; i < dpriv->num_fields; i++) // We use binary format only
		priv->write_query_param_format[i] = 1;

	return POM_OK;

}

static int datastore_postgres_dataset_query_prepare(struct dataset_query *dsq) {


	char cond_query[DATASTORE_POSTGRES_QUERY_BUFF_LEN] = { 0 };
	char order_query[DATASTORE_POSTGRES_QUERY_BUFF_LEN] = { 0 };


	struct dataset_postgres_priv *priv = dsq->ds->priv;
	struct datastore_postgres_connection_priv *cpriv = dsq->con->priv;
	struct datavalue_condition *qc = dsq->cond;
	struct datavalue_read_order *qro = dsq->read_order;

	char read_query[DATASTORE_POSTGRES_QUERY_BUFF_LEN] = { 0 };
	strncpy(read_query, priv->query_read_start, DATASTORE_POSTGRES_QUERY_BUFF_LEN - 1);

	if (qc) {
		struct datavalue_template *dt = dsq->ds->data_template;


		char *op = NULL;
		switch (qc->op) {
			case PTYPE_OP_EQ:
				op = "=";
				break;
			default:
				op = ptype_get_op_sign(qc->op);
		}

		if (!op) {
			pomlog(POMLOG_ERR "Unsupported operation in read condition");
			return DATASET_QUERY_ERR;
		}

		switch (dt[qc->field_id].native_type) {
			case DATASTORE_POSTGRES_PTYPE_BOOL:
				snprintf(cond_query + strlen(cond_query), DATASTORE_POSTGRES_QUERY_BUFF_LEN - strlen(cond_query), " WHERE %s %s %hhu", dt[qc->field_id].name, op, *PTYPE_BOOL_GETVAL(qc->value));
				break;
			case DATASTORE_POSTGRES_PTYPE_UINT8:
				snprintf(cond_query + strlen(cond_query), DATASTORE_POSTGRES_QUERY_BUFF_LEN - strlen(cond_query), " WHERE %s %s %hhu", dt[qc->field_id].name, op, *PTYPE_UINT8_GETVAL(qc->value));
				break;
			case DATASTORE_POSTGRES_PTYPE_UINT16:
				snprintf(cond_query + strlen(cond_query), DATASTORE_POSTGRES_QUERY_BUFF_LEN - strlen(cond_query), " WHERE %s %s %hu", dt[qc->field_id].name, op, *PTYPE_UINT16_GETVAL(qc->value));
				break;
			case DATASTORE_POSTGRES_PTYPE_UINT32:
				snprintf(cond_query + strlen(cond_query), DATASTORE_POSTGRES_QUERY_BUFF_LEN - strlen(cond_query), " WHERE %s %s %u", dt[qc->field_id].name, op, *PTYPE_UINT32_GETVAL(qc->value));
				break;
			case DATASTORE_POSTGRES_PTYPE_UINT64:
				snprintf(cond_query + strlen(cond_query), DATASTORE_POSTGRES_QUERY_BUFF_LEN - strlen(cond_query), " WHERE %s %s %"PRIu64, dt[qc->field_id].name, op, *PTYPE_UINT64_GETVAL(qc->value));
				break;
			case DATASTORE_POSTGRES_PTYPE_STRING: {
				int err;
				snprintf(cond_query + strlen(cond_query), DATASTORE_POSTGRES_QUERY_BUFF_LEN - strlen(cond_query), " WHERE %s %s '", dt[qc->field_id].name, op);
				PQescapeStringConn(cpriv->db, cond_query + strlen(cond_query), PTYPE_STRING_GETVAL(qc->value), (DATASTORE_POSTGRES_QUERY_BUFF_LEN - strlen(cond_query)) / 2, &err);
				if (err) {
					pomlog(POMLOG_ERR "Error while escaping string : %s", PQerrorMessage(cpriv->db));
					return DATASET_QUERY_ERR;
				}
				strncat(cond_query, "'", DATASTORE_POSTGRES_QUERY_BUFF_LEN - strlen(cond_query));
				break;
			}
			default:
				pomlog(POMLOG_ERR "Unsupported ptype in read condition");
				return DATASET_QUERY_ERR;
		}

		if (strlen(cond_query) >= DATASTORE_POSTGRES_QUERY_BUFF_LEN) {
			pomlog(POMLOG_ERR "Query conditions too long");
			return DATASET_QUERY_ERR;
		}




	}
	
	if (qro) {
		strncat(order_query, " ORDER BY ", DATASTORE_POSTGRES_QUERY_BUFF_LEN - strlen(order_query));
		strncat(order_query, dsq->ds->data_template[qro->field_id].name, DATASTORE_POSTGRES_QUERY_BUFF_LEN - strlen(order_query));
		if (qro->direction == DATASET_READ_ORDER_DESC)
			strncat(order_query, " DESC", DATASTORE_POSTGRES_QUERY_BUFF_LEN - strlen(order_query));

		if (strlen(order_query) >= DATASTORE_POSTGRES_QUERY_BUFF_LEN) {
			pomlog(POMLOG_ERR "Query order too long");
			return DATASET_QUERY_ERR;
		}
	}

	char delete_query[DATASTORE_POSTGRES_QUERY_BUFF_LEN] = { 0 };
	snprintf(delete_query, sizeof(delete_query), "DELETE FROM %s", dsq->ds->name);

	if (qc) {
		strncat(read_query, cond_query, DATASTORE_POSTGRES_QUERY_BUFF_LEN - strlen(read_query));
		strncat(delete_query, cond_query, DATASTORE_POSTGRES_QUERY_BUFF_LEN - strlen(delete_query));
	}

	if (qro) {
		strncat(read_query, order_query, DATASTORE_POSTGRES_QUERY_BUFF_LEN - strlen(read_query));
		strncat(delete_query, order_query, DATASTORE_POSTGRES_QUERY_BUFF_LEN - strlen(delete_query));
	}

	struct dataset_postgres_query_priv *dsqpriv = dsq->priv;

	pomlog(POMLOG_DEBUG "Prepared read query : %s", read_query);
	if (dsqpriv->query_read_start)
		free(dsqpriv->query_read_start);
	dsqpriv->query_read_start = strdup(read_query);
	if (!dsqpriv->query_read_start) {
		pom_oom(strlen(read_query) + 1);
		return DATASET_QUERY_ERR;
	}

	pomlog(POMLOG_DEBUG "Prepared delete query : %s", delete_query);
	if (dsqpriv->query_delete)
		free(dsqpriv->query_delete);
	dsqpriv->query_delete = strdup(delete_query);
	if (!dsqpriv->query_delete) {
		pom_oom(strlen(delete_query) + 1);
		return DATASET_QUERY_ERR;
	}

	
	return DATASET_QUERY_OK;
}

static int datastore_postgres_dataset_query_cleanup(struct dataset_query *dsq) {
	
	struct dataset_postgres_query_priv *priv = dsq->priv;
	if (!priv)
		return POM_OK;

	if (priv->query_read_start)
		free(priv->query_read_start);

	if (priv->read_res)
		PQclear(priv->read_res);

	if (priv->write_data_buff)
		free(priv->write_data_buff);
	if (priv->write_query_param_val)
		free(priv->write_query_param_val);
	if (priv->write_query_param_len)
		free(priv->write_query_param_len);
	if (priv->write_query_param_format)
		free(priv->write_query_param_format);

	free(priv);
	return POM_OK;
}

static int datastore_postgres_dataset_read(struct dataset_query *dsq) {
	
	struct dataset_postgres_priv *priv = dsq->ds->priv;
	struct datastore_postgres_priv *dpriv = dsq->ds->dstore->priv;
	struct dataset_postgres_query_priv *qpriv = dsq->priv;
	struct datastore_postgres_connection_priv *cpriv = dsq->con->priv;

	int res;




	pom_mutex_lock(&cpriv->lock);
	if (!qpriv->read_res) {
		
		if (cpriv->transaction == DATASTORE_POSTGRES_TRANSACTION_NONE) {
			res = datastore_postgres_exec(dsq->con, "BEGIN;");
			if (res != DATASET_QUERY_OK) {
				pom_mutex_unlock(&cpriv->lock);
				return res;
			}
			cpriv->transaction = DATASTORE_POSTGRES_TRANSACTION_TEMP;
		} else if (cpriv->transaction >= DATASTORE_POSTGRES_TRANSACTION_TEMP) {
			cpriv->transaction++;
		}

		res = datastore_postgres_exec(dsq->con, qpriv->query_read_start);
		if (res != DATASET_QUERY_OK)
			goto end;

		qpriv->read_res = PQexec(cpriv->db, priv->query_read);
		if (PQresultStatus(qpriv->read_res) != PGRES_TUPLES_OK) {
			pomlog(POMLOG_ERR "Error while executing the READ SQL query : %s", PQresultErrorMessage(qpriv->read_res));
			res = datastore_postgres_get_ds_state_error(qpriv->read_res);
			PQclear(qpriv->read_res);
			qpriv->read_res = NULL;
			goto end;
		}

		res = DATASET_QUERY_MORE;

		qpriv->read_query_cur = 0;
		qpriv->read_query_tot = PQntuples(qpriv->read_res);
		if (qpriv->read_query_tot < 0) {
			pomlog(POMLOG_ERR "Result set overflow, possiblty %u results", (unsigned int)qpriv->read_query_tot);
			PQclear(qpriv->read_res);
			qpriv->read_res = NULL;
			res = DATASET_QUERY_ERR;
			goto end;
		}

	}

	if (qpriv->read_query_cur >= qpriv->read_query_tot) {
		// It was the last entry
		PQclear(qpriv->read_res);
		qpriv->read_res = NULL;
		res = DATASET_QUERY_OK;
		goto end;
	}

	uint64_t *ptr = (uint64_t*) PQgetvalue(qpriv->read_res, qpriv->read_query_cur, 0);
	dsq->data_id = ntohll(*ptr);

	struct datavalue *dv = dsq->values;
	struct datavalue_template *dt = dsq->ds->data_template;

	int i;

	for (i = 0; dt[i].name; i++) {
		if (PQgetisnull(qpriv->read_res, qpriv->read_query_cur, i + 1)) {
			dv[i].is_null = 1;
		} else {
			switch (dt[i].native_type) {
				case DATASTORE_POSTGRES_PTYPE_BOOL: {
					uint8_t *res = (uint8_t*) PQgetvalue(qpriv->read_res, qpriv->read_query_cur, i + 1);
					PTYPE_BOOL_SETVAL(dv[i].value, *res);
					break;
				}
				case DATASTORE_POSTGRES_PTYPE_UINT8: {
					uint16_t *res = (uint16_t*) PQgetvalue(qpriv->read_res, qpriv->read_query_cur, i + 1);
					PTYPE_UINT8_SETVAL(dv[i].value, ntohs(*res));
					break;
				}
				case DATASTORE_POSTGRES_PTYPE_UINT16: {
					uint16_t *res = (uint16_t*) PQgetvalue(qpriv->read_res, qpriv->read_query_cur, i + 1);
					PTYPE_UINT16_SETVAL(dv[i].value, ntohs(*res));
					break;
				}
				case DATASTORE_POSTGRES_PTYPE_UINT32: {
					uint32_t *res = (uint32_t*) PQgetvalue(qpriv->read_res, qpriv->read_query_cur, i + 1);
					PTYPE_UINT32_SETVAL(dv[i].value, ntohl(*res));
					break;
				}
				case DATASTORE_POSTGRES_PTYPE_UINT64: {
					uint64_t *res = (uint64_t*) PQgetvalue(qpriv->read_res, qpriv->read_query_cur, i + 1);
					PTYPE_UINT64_SETVAL(dv[i].value, ntohll(*res));
					break;
				}
				case DATASTORE_POSTGRES_PTYPE_TIMESTAMP: {
					ptime t = 0;
					if (dpriv->integer_datetimes) {
						int64_t *my_time = (int64_t*) PQgetvalue(qpriv->read_res, qpriv->read_query_cur, i + 1);
						t = ntohll(*my_time) + pom_sec_ptime((POSTGRES_EPOCH_JDATE - UNIX_EPOCH_JDATE) * SECS_PER_DAY);
					} else {
						double *my_time = (double*) PQgetvalue(qpriv->read_res, qpriv->read_query_cur, i + 1);
						double swp_time = ntohll(*my_time);

						t = pom_sec_ptime(swp_time + ((POSTGRES_EPOCH_JDATE - UNIX_EPOCH_JDATE) * SECS_PER_DAY));
					}
					// Adjust for timezone and daylight
					// Assume that stored values are localtime
					t += pom_sec_ptime(timezone);
/*					if (daylight)
						t -= pom_sec_ptime(3600);
*/
					PTYPE_TIMESTAMP_SETVAL(dv[i].value, t);
					break;
				}
				default: {
					char *pgres = PQgetvalue(qpriv->read_res, qpriv->read_query_cur, i + 1);
					if (ptype_parse_val(dv[i].value, pgres) != POM_OK) {
						PQclear(qpriv->read_res);
						qpriv->read_res = NULL;
						res = DATASET_QUERY_ERR;
						goto end;
					}
					break;
				}
			}
		}
	}
	
	qpriv->read_query_cur++;
	res = DATASET_QUERY_MORE;

end:

	if (res == DATASET_QUERY_OK)
		datastore_postgres_exec(dsq->con, priv->query_read_end);

	if (cpriv->transaction >= DATASTORE_POSTGRES_TRANSACTION_TEMP && res != DATASET_QUERY_MORE) {
		if (cpriv->transaction == DATASTORE_POSTGRES_TRANSACTION_TEMP) {
			if (res == DATASET_QUERY_OK)
				datastore_postgres_exec(dsq->con, "COMMIT;");
			else
				datastore_postgres_exec(dsq->con, "ROLLBACK;");
			cpriv->transaction = DATASTORE_POSTGRES_TRANSACTION_NONE;
		} else {
			cpriv->transaction--;
		}
	}

	pom_mutex_unlock(&cpriv->lock);

	return res;

}

static int datastore_postgres_dataset_write(struct dataset_query *dsq) {
	
	struct datastore_postgres_priv *dpriv = dsq->ds->dstore->priv;
	struct datavalue *dv = dsq->values;
	struct dataset_postgres_query_priv *qpriv = dsq->priv;
	struct datavalue_template *dt = dsq->ds->data_template;
	struct datastore_postgres_connection_priv *cpriv = dsq->con->priv;
	struct dataset_postgres_priv *dspriv = dsq->ds->priv;

	pom_mutex_lock(&cpriv->lock);
	int res = DATASET_QUERY_OK;

	if (cpriv->transaction == DATASTORE_POSTGRES_TRANSACTION_NONE) {
		res = datastore_postgres_exec(dsq->con, "BEGIN;");
		if (res != DATASET_QUERY_OK) {
			pom_mutex_unlock(&cpriv->lock);
			return res;
		}
		cpriv->transaction = DATASTORE_POSTGRES_TRANSACTION_TEMP;
	} else if (cpriv->transaction >= DATASTORE_POSTGRES_TRANSACTION_TEMP) {
		cpriv->transaction++;
	}

	int i;
	for (i = 0; dt[i].name; i++) {
		if (dv[i].is_null) {
			qpriv->write_query_param_val[i] = NULL;
		 } else {
			switch (dt[i].native_type) {
				case DATASTORE_POSTGRES_PTYPE_BOOL:
					qpriv->write_data_buff[i].uint8 = *PTYPE_BOOL_GETVAL(dv[i].value);
					qpriv->write_query_param_val[i] = (char*) &qpriv->write_data_buff[i].uint16;
					qpriv->write_query_param_len[i] = sizeof(uint8_t);
					break;
				case DATASTORE_POSTGRES_PTYPE_UINT8:
					qpriv->write_data_buff[i].uint16 = htons(*PTYPE_UINT8_GETVAL(dv[i].value));
					qpriv->write_query_param_val[i] = (char*) &qpriv->write_data_buff[i].uint16;
					qpriv->write_query_param_len[i] = sizeof(uint16_t);
					break;
				case DATASTORE_POSTGRES_PTYPE_UINT16:
					qpriv->write_data_buff[i].uint16 = htons(*PTYPE_UINT16_GETVAL(dv[i].value));
					qpriv->write_query_param_val[i] = (char*) &qpriv->write_data_buff[i].uint16;
					qpriv->write_query_param_len[i] = sizeof(uint16_t);
					break;
				case DATASTORE_POSTGRES_PTYPE_UINT32:
					qpriv->write_data_buff[i].uint32 = htonl(*PTYPE_UINT32_GETVAL(dv[i].value));
					qpriv->write_query_param_val[i] = (char*) &qpriv->write_data_buff[i].uint32;
					qpriv->write_query_param_len[i] = sizeof(uint32_t);
					break;
				case DATASTORE_POSTGRES_PTYPE_UINT64:
					qpriv->write_data_buff[i].uint64 = htonll(*PTYPE_UINT64_GETVAL(dv[i].value));
					qpriv->write_query_param_val[i] = (char*) &qpriv->write_data_buff[i].uint64;
					qpriv->write_query_param_len[i] = sizeof(uint64_t);
					break;
				case DATASTORE_POSTGRES_PTYPE_TIMESTAMP: {
					ptime *ts = PTYPE_TIMESTAMP_GETVAL(dv[i].value);

					uint64_t sec = pom_ptime_sec(*ts);
					uint64_t usec = pom_ptime_usec(*ts);

					sec -= timezone;
					if (daylight)
						sec += 3600;

					if (dpriv->integer_datetimes) {
						uint64_t my_time = sec - ((POSTGRES_EPOCH_JDATE - UNIX_EPOCH_JDATE) * SECS_PER_DAY);
						my_time *= 1000000;
						my_time += usec;
						qpriv->write_data_buff[i].int64 = (int64_t) htonll(my_time);
						qpriv->write_query_param_val[i] = (char*) &qpriv->write_data_buff[i].int64;
						qpriv->write_query_param_len[i] = sizeof(int64_t);
					} else {
						double my_time = (double)sec + (double)usec / 1000000.0;
						qpriv->write_data_buff[i].dfloat = htonll(my_time);
						qpriv->write_query_param_val[i] = (char*) &qpriv->write_data_buff[i].dfloat;
						qpriv->write_query_param_len[i] = sizeof(double);
					}
					break;
				}
				case DATASTORE_POSTGRES_PTYPE_STRING: {
					char *value = PTYPE_STRING_GETVAL(dv[i].value);
					qpriv->write_query_param_val[i] = value;
					if (value) {
						qpriv->write_query_param_len[i] = strlen(value);
					} else {
						qpriv->write_query_param_len[i] = 0;
					}
					break;
				}

				default: {
					qpriv->write_query_param_val[i] = ptype_print_val_alloc(dv[i].value, NULL);
					if (qpriv->write_query_param_val[i])
						qpriv->write_query_param_len[i] = strlen(qpriv->write_query_param_val[i]);
					break;
				}
			}
		}
		
	}

	PGresult *pgres = PQexecParams(cpriv->db, dspriv->query_write, dspriv->num_fields, NULL, (const char * const *)qpriv->write_query_param_val, qpriv->write_query_param_len, qpriv->write_query_param_format, 1);

	for (i = 0; dt[i].name; i++) {
		if (dt[i].native_type == DATASTORE_POSTGRES_PTYPE_OTHER && !dv[i].is_null)
			free(qpriv->write_query_param_val[i]);
	}

	if (PQresultStatus(pgres) != PGRES_COMMAND_OK) {
		pomlog(POMLOG_ERR "Failed to write to the dataset \"%s\" : %s", dsq->ds->name, PQresultErrorMessage(pgres));
		res = datastore_postgres_get_ds_state_error(pgres);
		PQclear(pgres);
		goto end;
	}
	PQclear(pgres);

	// Find out the last inserted PKID
	pgres = PQexecParams(cpriv->db, dspriv->query_write_get_id, 0, NULL, NULL, NULL, NULL, 1);
	if (PQresultStatus(pgres) != PGRES_TUPLES_OK) {
		pomlog(POMLOG_ERR "Failed to read the last inserted PKID : %s", PQresultErrorMessage(pgres));
		res = datastore_postgres_get_ds_state_error(pgres);
		PQclear(pgres);
		goto end;
	}

	dsq->data_id = ntohll(*(uint64_t*) PQgetvalue(pgres, 0, 0));

	PQclear(pgres);

end:
	if (cpriv->transaction > DATASTORE_POSTGRES_TRANSACTION_TEMP) {
		cpriv->transaction--;
	} else if (cpriv->transaction == DATASTORE_POSTGRES_TRANSACTION_TEMP) {
		if (res == DATASET_QUERY_OK)
			datastore_postgres_exec(dsq->con, "COMMIT;");
		else
			datastore_postgres_exec(dsq->con, "ROLLBACK;");
		cpriv->transaction = DATASTORE_POSTGRES_TRANSACTION_NONE;
	}

	pom_mutex_unlock(&cpriv->lock);

	return res;
}

static int datastore_postgres_dataset_delete(struct dataset_query *dsq) {

	struct dataset_postgres_query_priv *qpriv = dsq->priv;
	return datastore_postgres_exec(dsq->con, qpriv->query_delete);
}
