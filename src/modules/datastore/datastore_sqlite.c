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


#include "datastore_sqlite.h"

#include <pom-ng/ptype_bool.h>
#include <pom-ng/ptype_uint8.h>
#include <pom-ng/ptype_uint16.h>
#include <pom-ng/ptype_uint32.h>
#include <pom-ng/ptype_uint64.h>
#include <pom-ng/ptype_string.h>
#include <pom-ng/ptype_timestamp.h>

#include <stdio.h>

#define DATASTORE_SQLITE_PKID "pkid"

#define DATASTORE_SQLITE_PTYPE_OTHER		0
#define DATASTORE_SQLITE_PTYPE_BOOL		1
#define DATASTORE_SQLITE_PTYPE_UINT8		2
#define DATASTORE_SQLITE_PTYPE_UINT16		3
#define DATASTORE_SQLITE_PTYPE_UINT32		4
#define DATASTORE_SQLITE_PTYPE_UINT64		5
#define DATASTORE_SQLITE_PTYPE_STRING		6
#define DATASTORE_SQLITE_PTYPE_TIMESTAMP	7

struct mod_reg_info *datastore_sqlite_reg_info() {

	static struct mod_reg_info reg_info;
	memset(&reg_info, 0, sizeof(struct mod_reg_info));
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = datastore_sqlite_mod_register;
	reg_info.unregister_func = datastore_sqlite_mod_unregister;
	reg_info.dependencies = "ptype_bool, ptype_string, ptype_uint8, ptype_uint16, ptype_uint32, ptype_uint64, ptype_timestamp";
	
	return &reg_info;
}

static int datastore_sqlite_mod_register(struct mod_reg *mod) {

	if (!sqlite3_threadsafe()) {
		pomlog(POMLOG_ERR "SQLite3 library was not compiled in a thread safe way.");
		return POM_ERR;
	}

	static struct datastore_reg_info datastore_sqlite = {0};
	datastore_sqlite.name = "sqlite";
	datastore_sqlite.mod = mod;
	datastore_sqlite.init = datastore_sqlite_init;
	datastore_sqlite.cleanup = datastore_sqlite_cleanup;
	datastore_sqlite.connect = datastore_sqlite_connect;
	datastore_sqlite.disconnect = datastore_sqlite_disconnect;
	datastore_sqlite.transaction_begin = datastore_sqlite_transaction_begin;
	datastore_sqlite.transaction_commit = datastore_sqlite_transaction_commit;
	datastore_sqlite.transaction_rollback = datastore_sqlite_transaction_rollback;
	datastore_sqlite.dataset_alloc = datastore_sqlite_dataset_alloc;
	datastore_sqlite.dataset_cleanup = datastore_sqlite_dataset_cleanup;
	datastore_sqlite.dataset_create = datastore_sqlite_dataset_create;
	datastore_sqlite.dataset_read = datastore_sqlite_dataset_read;
	datastore_sqlite.dataset_write = datastore_sqlite_dataset_write;
	datastore_sqlite.dataset_delete = datastore_sqlite_dataset_delete;
	datastore_sqlite.dataset_query_alloc = datastore_sqlite_dataset_query_alloc;
	datastore_sqlite.dataset_query_prepare = datastore_sqlite_dataset_query_prepare;
	datastore_sqlite.dataset_query_cleanup = datastore_sqlite_dataset_query_cleanup;

	return datastore_register(&datastore_sqlite);

}

static int datastore_sqlite_mod_unregister() {

	return datastore_unregister("sqlite");
}

static int datastore_sqlite_init(struct datastore *d) {

	struct datastore_sqlite_priv *priv = malloc(sizeof(struct datastore_sqlite_priv));
	if (!priv) {
		pom_oom(sizeof(struct datastore_sqlite_priv));
		return POM_ERR;
	}
	memset(priv, 0, sizeof(struct datastore_sqlite_priv));

	d->priv = priv;

	struct registry_param *p = NULL;

	priv->p_dbfile = ptype_alloc("string");
	if (!priv->p_dbfile)
		goto err;

	p = registry_new_param("dbfile", "pom-ng.db", priv->p_dbfile, "Path to the database", 0);
	if (registry_instance_add_param(d->reg_instance, p) != POM_OK) {
		registry_cleanup_param(p);
		goto err;
	}


	return POM_OK;
err:

	free(priv);

	return POM_ERR;
}

static int datastore_sqlite_cleanup(struct datastore *d) {

	struct datastore_sqlite_priv *priv = d->priv;

	if (priv) {

		ptype_cleanup(priv->p_dbfile);
		free(priv);
	}

	return POM_OK;
}

static int datastore_sqlite_connect(struct datastore_connection *dc) {

	struct datastore_sqlite_priv *priv = dc->d->priv;

	char *dbfile = PTYPE_STRING_GETVAL(priv->p_dbfile);

	struct datastore_sqlite_connection_priv *cpriv = malloc(sizeof(struct datastore_sqlite_connection_priv));
	if (!cpriv) {
		pom_oom(sizeof(struct datastore_sqlite_connection_priv));
		return POM_ERR;
	}
	memset(cpriv, 0, sizeof(struct datastore_sqlite_priv));
	
	if (sqlite3_open_v2(dbfile, &cpriv->db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, NULL)) {
		pomlog(POMLOG_ERR "Connection to database %s failed : %s", dbfile, sqlite3_errmsg(cpriv->db));
		if (cpriv->db)
			if (sqlite3_close(cpriv->db) != SQLITE_OK)
				pomlog(POMLOG_WARN "Warning, sqlite3_close() failed.");
		free(cpriv);
		return POM_ERR;

	}

	sqlite3_busy_handler(cpriv->db, datastore_sqlite_busy_callback, NULL);

	dc->priv = cpriv;

	pomlog(POMLOG_DEBUG "New connection to database %s", dbfile);

	return POM_OK;

	
}

static int datastore_sqlite_disconnect(struct datastore_connection *dc) {

	struct datastore_sqlite_connection_priv *cpriv = dc->priv;

	if (sqlite3_close(cpriv->db) != SQLITE_OK)
		pomlog(POMLOG_WARN "Warning, sqlite3_close() failed.");
	free(cpriv);
	pomlog(POMLOG_DEBUG "Connection to the database closed");

	return POM_OK;

}

static int datastore_sqlite_transaction_begin(struct datastore_connection *dc) {
	
	struct datastore_sqlite_connection_priv *cpriv = dc->priv;

	int res = sqlite3_exec(cpriv->db, "BEGIN", NULL, NULL, NULL);

	if (res != SQLITE_OK)
		pomlog(POMLOG_ERR "Failed to begin transaction on datastore \"%s\" : %s", dc->d->name, sqlite3_errmsg(cpriv->db));
	return datastore_sqlite_get_ds_state_error(res);
}

static int datastore_sqlite_transaction_commit(struct datastore_connection *dc) {
	
	struct datastore_sqlite_connection_priv *cpriv = dc->priv;

	int res = sqlite3_exec(cpriv->db, "COMMIT", NULL, NULL, NULL);

	if (res != SQLITE_OK)
		pomlog(POMLOG_ERR "Failed to commit transaction on datastore \"%s\" : %s", dc->d->name, sqlite3_errmsg(cpriv->db));
	return datastore_sqlite_get_ds_state_error(res);
}

static int datastore_sqlite_transaction_rollback(struct datastore_connection *dc) {
	
	struct datastore_sqlite_connection_priv *cpriv = dc->priv;

	int res = sqlite3_exec(cpriv->db, "ROLLBACK", NULL, NULL, NULL);

	if (res != SQLITE_OK)
		pomlog(POMLOG_ERR "Failed to rollback transaction on datastore \"%s\" : %s", dc->d->name, sqlite3_errmsg(cpriv->db));
	return datastore_sqlite_get_ds_state_error(res);
}


static int datastore_sqlite_dataset_alloc(struct dataset *ds) {

	char read_query[DATASTORE_SQLITE_QUERY_BUFF_LEN + 1];
	strcpy(read_query, "SELECT " DATASTORE_SQLITE_PKID ", ");

	int i;
	struct datavalue_template *dt = ds->data_template;
	for (i = 0; dt[i].name; i++) {
		
		if (!strcmp(dt[i].type, "bool"))
			dt[i].native_type = DATASTORE_SQLITE_PTYPE_BOOL;
		else if (!strcmp(dt[i].type, "uint8"))
			dt[i].native_type = DATASTORE_SQLITE_PTYPE_UINT8;
		else if (!strcmp(dt[i].type, "uint16"))
			dt[i].native_type = DATASTORE_SQLITE_PTYPE_UINT16;
		else if (!strcmp(dt[i].type, "uint32"))
			dt[i].native_type = DATASTORE_SQLITE_PTYPE_UINT32;
		else if (!strcmp(dt[i].type, "uint64"))
			dt[i].native_type = DATASTORE_SQLITE_PTYPE_UINT64;
		else if (!strcmp(dt[i].type, "string"))
			dt[i].native_type = DATASTORE_SQLITE_PTYPE_STRING;
		else if (!strcmp(dt[i].type, "timestamp"))
			dt[i].native_type = DATASTORE_SQLITE_PTYPE_TIMESTAMP;
		else
			dt[i].native_type = DATASTORE_SQLITE_PTYPE_OTHER;

		strncat(read_query, dt[i].name, DATASTORE_SQLITE_QUERY_BUFF_LEN - strlen(read_query));
		if (dt[i + 1].name)
			strncat(read_query, ", ", DATASTORE_SQLITE_QUERY_BUFF_LEN - strlen(read_query));

	}
	strncat(read_query, " FROM ", DATASTORE_SQLITE_QUERY_BUFF_LEN - strlen(read_query));
	strncat(read_query, ds->name, DATASTORE_SQLITE_QUERY_BUFF_LEN - strlen(read_query));
	if (strlen(read_query) >= DATASTORE_SQLITE_QUERY_BUFF_LEN) {
		pomlog(POMLOG_ERR "Read query is too long");
		return POM_ERR;
	}
	pomlog(POMLOG_DEBUG "READ QUERY : %s", read_query);

	char write_query[DATASTORE_SQLITE_QUERY_BUFF_LEN + 1];
	strcpy(write_query, "INSERT INTO ");
	strncat(write_query, ds->name, DATASTORE_SQLITE_QUERY_BUFF_LEN - strlen(write_query));
	strncat(write_query, " ( ", DATASTORE_SQLITE_QUERY_BUFF_LEN - strlen(write_query));

	for (i = 0; dt[i].name; i++) {
		strncat(write_query, dt[i].name, DATASTORE_SQLITE_QUERY_BUFF_LEN - strlen(write_query));
		if (dt[i + 1].name)
			strncat(write_query, ", ", DATASTORE_SQLITE_QUERY_BUFF_LEN - strlen(write_query));

	}
	strncat(write_query, " ) VALUES ( ", DATASTORE_SQLITE_QUERY_BUFF_LEN - strlen(write_query));

	for (i = 0; dt[i].name; i++) {
		strncat(write_query, "?", DATASTORE_SQLITE_QUERY_BUFF_LEN - strlen(write_query));
		if (dt[i + 1].name)
			strncat(write_query, ", ", DATASTORE_SQLITE_QUERY_BUFF_LEN - strlen(write_query));
	}

	strncat(write_query, " )", DATASTORE_SQLITE_QUERY_BUFF_LEN - strlen(write_query));

	pomlog(POMLOG_DEBUG "WRITE QUERY : %s", write_query);

	char delete_query[DATASTORE_SQLITE_QUERY_BUFF_LEN + 1];
	strcpy(delete_query, "DELETE FROM ");
	strncat(delete_query, ds->name, DATASTORE_SQLITE_QUERY_BUFF_LEN - strlen(write_query));

	pomlog(POMLOG_DEBUG "DELETE QUERY : %s", delete_query);

	struct dataset_sqlite_priv *priv = malloc(sizeof(struct dataset_sqlite_priv));
	if (!priv) {
		pom_oom(sizeof(struct dataset_sqlite_priv));
		return POM_ERR;
	}
	memset(priv, 0, sizeof(struct dataset_sqlite_priv));

	priv->read_query = strdup(read_query);
	if (!priv->read_query) {
		pom_oom(strlen(read_query) + 1);
		free(priv);
		return POM_ERR;
	}

	priv->write_query = strdup(write_query);
	if (!priv->write_query) {
		pom_oom(strlen(write_query) + 1);
		free(priv->read_query);
		free(priv);
		return POM_ERR;
	}

	priv->delete_query = strdup(delete_query);
	if (!priv->delete_query) {
		pom_oom(strlen(delete_query) + 1);
		free(priv->read_query);
		free(priv->write_query);
		free(priv);
		return POM_ERR;
	}

	ds->priv = priv;

	return POM_OK;
}

static int datastore_sqlite_dataset_cleanup(struct dataset *ds) {

	struct dataset_sqlite_priv *priv = ds->priv;
	free(priv->read_query);
	free(priv->write_query);
	free(priv->delete_query);

	free(priv);

	return POM_OK;

}

static int datastore_sqlite_dataset_create(struct dataset *ds, struct datastore_connection *dc) {

	char create_query[DATASTORE_SQLITE_QUERY_BUFF_LEN + 1];
	strcpy(create_query, "CREATE TABLE ");
	strncat(create_query, ds->name, DATASTORE_SQLITE_QUERY_BUFF_LEN - strlen(create_query));
	strncat(create_query, " ( " DATASTORE_SQLITE_PKID " INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT, ", DATASTORE_SQLITE_QUERY_BUFF_LEN - strlen(create_query));

	struct datavalue_template *dt = ds->data_template;
	int i;
	for (i = 0; dt[i].name; i++) {
		strncat(create_query, dt[i].name, DATASTORE_SQLITE_QUERY_BUFF_LEN - strlen(create_query));
		char *type = " INTEGER";
		if (dt[i].native_type == DATASTORE_SQLITE_PTYPE_OTHER || dt[i].native_type == DATASTORE_SQLITE_PTYPE_STRING)
			type = " STRING";

		strncat(create_query, type, DATASTORE_SQLITE_QUERY_BUFF_LEN - strlen(create_query));

		if (dt[i + 1].name)
			strncat(create_query, ", ", DATASTORE_SQLITE_QUERY_BUFF_LEN - strlen(create_query));
	}

	strncat(create_query, " )", DATASTORE_SQLITE_QUERY_BUFF_LEN - strlen(create_query));

	if (strlen(create_query) >= DATASTORE_SQLITE_QUERY_BUFF_LEN) {
		pomlog(POMLOG_ERR "Create query too long");
		return POM_ERR;
	}

	pomlog(POMLOG_DEBUG "CREATE QUERY : %s", create_query);

	struct datastore_sqlite_connection_priv *cpriv = dc->priv;

	int res = sqlite3_exec(cpriv->db, create_query, NULL, NULL, NULL);

	if (res != SQLITE_OK)
		pomlog(POMLOG_ERR "Failed to create dataset \"%s\" : %s", ds->name, sqlite3_errmsg(cpriv->db));
	return datastore_sqlite_get_ds_state_error(res);

}

static int datastore_sqlite_dataset_query_alloc(struct dataset_query *dsq) {
	
	struct dataset_sqlite_query_priv *priv = malloc(sizeof(struct dataset_sqlite_query_priv));
	if (!priv) {
		pom_oom(sizeof(struct dataset_sqlite_query_priv));
		return POM_ERR;
	}
	memset(priv, 0, sizeof(struct dataset_sqlite_query_priv));

	dsq->priv = priv;

	return POM_OK;

}

static int datastore_sqlite_dataset_query_prepare(struct dataset_query *dsq) {


	char cond_query[DATASTORE_SQLITE_QUERY_BUFF_LEN + 1] = { 0 };
	char order_query[DATASTORE_SQLITE_QUERY_BUFF_LEN + 1] = { 0 };
	char *read_query = NULL, *delete_query = NULL;
	char tmp_read_query[DATASTORE_SQLITE_QUERY_BUFF_LEN + 1], tmp_delete_query[DATASTORE_SQLITE_QUERY_BUFF_LEN + 1];


	struct dataset_sqlite_query_priv *qpriv = dsq->priv;
	struct dataset_sqlite_priv *priv = dsq->ds->priv;
	struct datastore_sqlite_connection_priv *cpriv = dsq->con->priv;
	struct datavalue_condition *qc = dsq->cond;
	struct datavalue_read_order *qro = dsq->read_order;

	if (qpriv->read_stmt)
		sqlite3_finalize(qpriv->read_stmt);
	if (qpriv->write_stmt)
		sqlite3_finalize(qpriv->write_stmt);
	if (qpriv->delete_stmt)
		sqlite3_finalize(qpriv->delete_stmt);


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
			case DATASTORE_SQLITE_PTYPE_BOOL:
				snprintf(cond_query + strlen(cond_query), DATASTORE_SQLITE_QUERY_BUFF_LEN - strlen(cond_query), " WHERE %s %s %hhu", dt[qc->field_id].name, op, *PTYPE_BOOL_GETVAL(qc->value));
				break;
			case DATASTORE_SQLITE_PTYPE_UINT8:
				snprintf(cond_query + strlen(cond_query), DATASTORE_SQLITE_QUERY_BUFF_LEN - strlen(cond_query), " WHERE %s %s %hhu", dt[qc->field_id].name, op, *PTYPE_UINT8_GETVAL(qc->value));
				break;
			case DATASTORE_SQLITE_PTYPE_UINT16:
				snprintf(cond_query + strlen(cond_query), DATASTORE_SQLITE_QUERY_BUFF_LEN - strlen(cond_query), " WHERE %s %s %hu", dt[qc->field_id].name, op, *PTYPE_UINT16_GETVAL(qc->value));
				break;
			case DATASTORE_SQLITE_PTYPE_UINT32:
				snprintf(cond_query + strlen(cond_query), DATASTORE_SQLITE_QUERY_BUFF_LEN - strlen(cond_query), " WHERE %s %s %u", dt[qc->field_id].name, op, *PTYPE_UINT32_GETVAL(qc->value));
				break;
			case DATASTORE_SQLITE_PTYPE_UINT64:
				snprintf(cond_query + strlen(cond_query), DATASTORE_SQLITE_QUERY_BUFF_LEN - strlen(cond_query), " WHERE %s %s %lu", dt[qc->field_id].name, op, *PTYPE_UINT64_GETVAL(qc->value));
				break;
			case DATASTORE_SQLITE_PTYPE_STRING: {
				snprintf(cond_query + strlen(cond_query), DATASTORE_SQLITE_QUERY_BUFF_LEN - strlen(cond_query), " WHERE %s %s \"", dt[qc->field_id].name, op);
				datastore_sqlite_escape_string(cond_query + strlen(cond_query), PTYPE_STRING_GETVAL(qc->value), DATASTORE_SQLITE_QUERY_BUFF_LEN - strlen(cond_query));
				strncat(cond_query, "\"", DATASTORE_SQLITE_QUERY_BUFF_LEN - strlen(cond_query));
				break;
			}
			default:
				pomlog(POMLOG_ERR "Unsupported ptype in read condition");
				return DATASET_QUERY_ERR;
		}

		if (strlen(cond_query) >= DATASTORE_SQLITE_QUERY_BUFF_LEN) {
			pomlog(POMLOG_ERR "Query conditions too long");
			return DATASET_QUERY_ERR;
		}




	}
	
	if (qro) {
		strncat(order_query, " ORDER BY ", DATASTORE_SQLITE_QUERY_BUFF_LEN - strlen(order_query));
		strncat(order_query, dsq->ds->data_template[qro->field_id].name, DATASTORE_SQLITE_QUERY_BUFF_LEN - strlen(order_query));
		if (qro->direction == DATASET_READ_ORDER_DESC)
			strncat(order_query, " DESC", DATASTORE_SQLITE_QUERY_BUFF_LEN - strlen(order_query));

		if (strlen(order_query) >= DATASTORE_SQLITE_QUERY_BUFF_LEN) {
			pomlog(POMLOG_ERR "Query order too long");
			return DATASET_QUERY_ERR;
		}
	}

	if (qc) {
		read_query = tmp_read_query;
		strcpy(tmp_read_query, priv->read_query);
		strncat(tmp_read_query, cond_query, DATASTORE_SQLITE_QUERY_BUFF_LEN - strlen(cond_query));

		delete_query = tmp_delete_query;
		strcpy(tmp_delete_query, priv->delete_query);
		strncat(tmp_delete_query, cond_query, DATASTORE_SQLITE_QUERY_BUFF_LEN - strlen(cond_query));

	}

	if (qro) {
		if (!read_query) {
			read_query = tmp_read_query;
			strcpy(tmp_read_query, priv->read_query);
		}
		strncat(tmp_read_query, order_query, DATASTORE_SQLITE_QUERY_BUFF_LEN - strlen(order_query));
	}

	if (!read_query)
		read_query = priv->read_query;

	if (!delete_query)
		delete_query = priv->delete_query;
		

	int res = sqlite3_prepare_v2(cpriv->db, read_query, -1, &qpriv->read_stmt, NULL);
	if (res != SQLITE_OK) {
		pomlog(POMLOG_ERR "Unable to prepare the READ SQL query \"%s\" : %s", read_query, sqlite3_errmsg(cpriv->db));
		return datastore_sqlite_get_ds_state_error(res);
	}

	res = sqlite3_prepare_v2(cpriv->db, priv->write_query, -1, &qpriv->write_stmt, NULL);
	if (res != SQLITE_OK) {
		pomlog(POMLOG_ERR "Unable to prepare the write SQL query \"%s\" : %s", priv->write_query, sqlite3_errmsg(cpriv->db));
		sqlite3_finalize(qpriv->read_stmt);
		qpriv->read_stmt = NULL;
		return datastore_sqlite_get_ds_state_error(res);
	}

	res = sqlite3_prepare_v2(cpriv->db, delete_query, -1, &qpriv->delete_stmt, NULL);
	if (res != SQLITE_OK) {
		pomlog(POMLOG_ERR "Unable to prepare the delete SQL query \"%s\" : %s", delete_query, sqlite3_errmsg(cpriv->db));
		sqlite3_finalize(qpriv->read_stmt);
		sqlite3_finalize(qpriv->write_stmt);
		qpriv->read_stmt = NULL;
		qpriv->write_stmt = NULL;
		return datastore_sqlite_get_ds_state_error(res);
	}

	return DATASET_QUERY_OK;
}

static int datastore_sqlite_dataset_query_cleanup(struct dataset_query *dsq) {
	
	struct dataset_sqlite_query_priv *priv = dsq->priv;
	if (priv) {
		if (priv->read_stmt)
			sqlite3_finalize(priv->read_stmt);
		if (priv->write_stmt)
			sqlite3_finalize(priv->write_stmt);
		if (priv->delete_stmt)
			sqlite3_finalize(priv->delete_stmt);
		
		free(priv);

	}
	return POM_OK;
}

static int datastore_sqlite_dataset_read(struct dataset_query *dsq) {

	struct dataset_sqlite_query_priv *qpriv = dsq->priv;

	int res = sqlite3_step(qpriv->read_stmt);
	if (res == SQLITE_DONE) {
		sqlite3_reset(qpriv->read_stmt);
		return DATASET_QUERY_OK;
	} else if (res != SQLITE_ROW) {
		sqlite3_reset(qpriv->read_stmt);
		return datastore_sqlite_get_ds_state_error(res);
	}

	// First read the pkid
	dsq->data_id = sqlite3_column_int64(qpriv->read_stmt, 0);

	struct datavalue *dv = dsq->values;
	struct datavalue_template *dt = dsq->ds->data_template;
	int i;
	for (i = 0; dt[i].name; i++) {

		if (sqlite3_column_type(qpriv->read_stmt, i + 1) == SQLITE_NULL) {
			dv[i].is_null = 1;
		} else {
			switch (dt[i].native_type) {
				case DATASTORE_SQLITE_PTYPE_BOOL: {
					int res = sqlite3_column_int(qpriv->read_stmt, i + 1);
					PTYPE_BOOL_SETVAL(dv[i].value, res);
					break;
				}
				case DATASTORE_SQLITE_PTYPE_UINT8: {
					uint8_t res = sqlite3_column_int(qpriv->read_stmt, i + 1);
					PTYPE_UINT8_SETVAL(dv[i].value, res);
					break;
				}
				case DATASTORE_SQLITE_PTYPE_UINT16: {
					uint16_t res = sqlite3_column_int(qpriv->read_stmt, i + 1);
					PTYPE_UINT16_SETVAL(dv[i].value, res);
					break;
				}
				case DATASTORE_SQLITE_PTYPE_UINT32: {
					uint32_t res = sqlite3_column_int(qpriv->read_stmt, i + 1);
					PTYPE_UINT32_SETVAL(dv[i].value, res);
					break;
				}
				case DATASTORE_SQLITE_PTYPE_UINT64: {
					uint64_t res = sqlite3_column_int64(qpriv->read_stmt, i + 1);
					PTYPE_UINT64_SETVAL(dv[i].value, res);
					break;
				}
				case DATASTORE_SQLITE_PTYPE_TIMESTAMP: {
					time_t res = sqlite3_column_int64(qpriv->read_stmt, i + 1);
					PTYPE_TIMESTAMP_SETVAL(dv[i].value, res);
					break;
				}
				default: {
					const unsigned char *txt = sqlite3_column_text(qpriv->read_stmt, i + 1);
					if (ptype_parse_val(dv[i].value, (char*)txt) != POM_OK) {
						sqlite3_reset(qpriv->read_stmt);
						return DATASET_QUERY_ERR;
					}
					break;
				}
			}
		}
	}

	return DATASET_QUERY_MORE;
}

static int datastore_sqlite_dataset_write(struct dataset_query *dsq) {
	
	struct datavalue *dv = dsq->values;
	struct dataset_sqlite_query_priv *qpriv = dsq->priv;
	struct datavalue_template *dt = dsq->ds->data_template;
	struct datastore_sqlite_connection_priv *cpriv = dsq->con->priv;

	int i, res;
	for (i = 0; dt[i].name; i++) {
		if (dv[i].is_null) {
			res = sqlite3_bind_null(qpriv->write_stmt, i + 1);
		 } else {
			switch (dt[i].native_type) {
				case DATASTORE_SQLITE_PTYPE_BOOL:
					res = sqlite3_bind_int(qpriv->write_stmt, i + 1, *PTYPE_BOOL_GETVAL(dv[i].value));
					break;
				case DATASTORE_SQLITE_PTYPE_UINT8:
					res = sqlite3_bind_int(qpriv->write_stmt, i + 1, *PTYPE_UINT8_GETVAL(dv[i].value));
					break;
				case DATASTORE_SQLITE_PTYPE_UINT16:
					res = sqlite3_bind_int(qpriv->write_stmt, i + 1, *PTYPE_UINT16_GETVAL(dv[i].value));
					break;
				case DATASTORE_SQLITE_PTYPE_UINT32:
					res = sqlite3_bind_int(qpriv->write_stmt, i + 1, *PTYPE_UINT32_GETVAL(dv[i].value));
					break;
				case DATASTORE_SQLITE_PTYPE_UINT64:
					res = sqlite3_bind_int64(qpriv->write_stmt, i + 1, *PTYPE_UINT64_GETVAL(dv[i].value));
					break;
				case DATASTORE_SQLITE_PTYPE_STRING:
					res = sqlite3_bind_text(qpriv->write_stmt, i + 1, PTYPE_STRING_GETVAL(dv[i].value), -1, SQLITE_STATIC);
					break;
				case DATASTORE_SQLITE_PTYPE_TIMESTAMP: {
					struct timeval *tv = PTYPE_TIMESTAMP_GETVAL(dv[i].value);
					res = sqlite3_bind_int64(qpriv->write_stmt, i + 1, tv->tv_sec);
					break;
				}
				default: {
					char *value = ptype_print_val_alloc(dv[i].value);
					res = sqlite3_bind_text(qpriv->write_stmt, i + 1, value, -1, free);
					break;
				}
			}
		}
		if (res != SQLITE_OK) {
			pomlog(POMLOG_ERR "Unable to bind the value to the query : %s", sqlite3_errmsg(cpriv->db));
			sqlite3_reset(qpriv->write_stmt);
			return datastore_sqlite_get_ds_state_error(res);
		}
		
	}


	// We need to make sure we write and retrieve the last row id in an atomic way on a db level
	
	static pthread_mutex_t write_lock = PTHREAD_MUTEX_INITIALIZER;

	pom_mutex_lock(&write_lock);

	res = sqlite3_step(qpriv->write_stmt);
	if (res != SQLITE_DONE) {
		pomlog(POMLOG_ERR "Error while executing the write query : %s", sqlite3_errmsg(cpriv->db));
		pom_mutex_unlock(&write_lock);
		sqlite3_reset(qpriv->write_stmt);
		return datastore_sqlite_get_ds_state_error(res);
	}
	
	dsq->data_id = sqlite3_last_insert_rowid(cpriv->db);

	pom_mutex_unlock(&write_lock);

	sqlite3_reset(qpriv->write_stmt);
	sqlite3_clear_bindings(qpriv->write_stmt);

	return DATASET_QUERY_OK;
}

static int datastore_sqlite_dataset_delete(struct dataset_query *dsq) {

	struct dataset_sqlite_query_priv *qpriv = dsq->priv;

	int res = sqlite3_step(qpriv->delete_stmt);

	return datastore_sqlite_get_ds_state_error(res);
}

static int datastore_sqlite_busy_callback(void *priv, int retries) {

	pomlog(POMLOG_DEBUG "Database is busy, Retry #%i ...", retries);

	usleep(10000);

	return 1;
}

static int datastore_sqlite_get_ds_state_error(int errnum) {
	
	switch (errnum) {
		case SQLITE_OK:
		case SQLITE_DONE:
			return DATASET_QUERY_OK;
		case SQLITE_ERROR:
		case SQLITE_ABORT:
		case SQLITE_MISMATCH:
			return DATASET_QUERY_ERR;
	}

	return DATASET_QUERY_DATASTORE_ERR;
}

static size_t datastore_sqlite_escape_string(char *to, char *from, size_t len) {

	size_t out_len = 0, i;

	for (i = 0; from[i] && out_len < len; i++) {

		switch (from[i]) {
			case '\'':
			case '\\':
				to[out_len] = '\\';
				to[out_len + 1] = from[i];
				out_len += 2;
				break;

			default:
				to[out_len] = from[i];
				out_len++;
				break;

		}
	}
	to[out_len] = 0;
	out_len++;

	return out_len;
}
