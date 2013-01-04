/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2012-2013 Guy Martin <gmsoft@tuxicoman.be>
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


#include <pom-ng/ptype_bool.h>
#include <pom-ng/ptype_string.h>
#include <pom-ng/ptype_uint16.h>
#include <pom-ng/ptype_uint32.h>
#include <pom-ng/proto_tftp.h>
#include <arpa/inet.h>
#include "analyzer_tftp.h"

struct mod_reg_info *analyzer_tftp_reg_info() {

	static struct mod_reg_info reg_info = { 0 };
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = analyzer_tftp_mod_register;
	reg_info.unregister_func = analyzer_tftp_mod_unregister;
	reg_info.dependencies = "ptype_bool, ptype_string, ptype_uint16, ptype_uint32";

	return &reg_info;
}

static int analyzer_tftp_mod_register(struct mod_reg *mod) {

	static struct analyzer_reg analyzer_tftp = { 0 };
	analyzer_tftp.name = "tftp";
	analyzer_tftp.api_ver = ANALYZER_API_VER;
	analyzer_tftp.mod = mod;
	analyzer_tftp.init = analyzer_tftp_init;
	analyzer_tftp.cleanup = analyzer_tftp_cleanup;

	return analyzer_register(&analyzer_tftp);
}

static int analyzer_tftp_mod_unregister() {

	return analyzer_unregister("tftp");
}

static int analyzer_tftp_init(struct analyzer *analyzer) {
	struct analyzer_tftp_priv *priv = malloc(sizeof(struct analyzer_tftp_priv));
	if (!priv) {
		pom_oom(sizeof(struct analyzer_tftp_priv));
		return POM_ERR;
	}
	memset(priv, 0, sizeof(struct analyzer_tftp_priv));

	analyzer->priv = priv;

	static struct data_item_reg evt_file_data_items[ANALYZER_TFTP_EVT_FILE_DATA_COUNT] = { { 0 } };
	evt_file_data_items[analyzer_tftp_file_filename].name = "filename";
	evt_file_data_items[analyzer_tftp_file_filename].value_type = ptype_get_type("string");
	evt_file_data_items[analyzer_tftp_file_mode].name = "mode";
	evt_file_data_items[analyzer_tftp_file_mode].value_type = ptype_get_type("string");
	evt_file_data_items[analyzer_tftp_file_write].name = "write";
	evt_file_data_items[analyzer_tftp_file_write].value_type = ptype_get_type("bool");
	evt_file_data_items[analyzer_tftp_file_size].name = "size";
	evt_file_data_items[analyzer_tftp_file_size].value_type = ptype_get_type("uint32");

	static struct data_reg evt_file_data = {
		.items = evt_file_data_items,
		.data_count = ANALYZER_TFTP_EVT_FILE_DATA_COUNT
	};

	static struct event_reg_info analyzer_tftp_evt_file = { 0 };
	analyzer_tftp_evt_file.source_name = "analyzer_tftp";
	analyzer_tftp_evt_file.source_obj = priv;
	analyzer_tftp_evt_file.name = "tftp_file";
	analyzer_tftp_evt_file.description = "TFTP file";
	analyzer_tftp_evt_file.flags = EVENT_REG_FLAG_PAYLOAD;
	analyzer_tftp_evt_file.data_reg = &evt_file_data;
	analyzer_tftp_evt_file.listeners_notify = analyzer_tftp_event_listeners_notify;

	priv->evt_file = event_register(&analyzer_tftp_evt_file);
	if (!priv->evt_file) {
		free(priv);
		return POM_ERR;
	}

	return POM_OK;
}

static int analyzer_tftp_cleanup(struct analyzer *analyzer) {

	if (analyzer->priv) {
		struct analyzer_tftp_priv *priv = analyzer->priv;
		if (priv->evt_file)
			event_unregister(priv->evt_file);
		free(priv);
	}
	return POM_OK;
}

static int analyzer_tftp_event_listeners_notify(void *obj, struct event_reg *evt_reg, int has_listeners) {

	struct analyzer_tftp_priv *priv = obj;

	if (has_listeners) {
		if (priv->pkt_listener)
			return POM_OK;

		priv->pkt_listener = proto_packet_listener_register(proto_get("tftp"), 0, obj, analyzer_tftp_pkt_process);
		if (!priv->pkt_listener)
			return POM_ERR;
	} else {
		if (proto_packet_listener_unregister(priv->pkt_listener) != POM_OK)
			return POM_ERR;
		priv->pkt_listener = NULL;
	}


	return POM_OK;
}

static int analyzer_tftp_conntrack_priv_cleanup(void *obj, void *priv) {

	struct analyzer_tftp_file *f = priv;

	int res = POM_OK;
	if (f->pload)
		res += analyzer_pload_buffer_cleanup(f->pload);

	if (f->evt)
		res += event_process_end(f->evt);

	free(f);

	return res;
}

static int analyzer_tftp_session_priv_cleanup(void *obj, void *priv) {

	struct analyzer_tftp_session_priv *p = priv;

	while (p->files) {
		struct analyzer_tftp_file *fq = p->files;
		p->files = fq->next;

		event_process_end(fq->evt);

		free(fq);
	}

	free(p);
	return POM_OK;
}

static int analyzer_tftp_pkt_process(void *obj, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct analyzer_tftp_priv *priv = obj;

	struct proto_process_stack *s = &stack[stack_index];

	void *pload = s->pload;
	uint32_t plen = s->plen;

	uint16_t opcode = ntohs(*((uint16_t*)pload));
	pload += sizeof(uint16_t);
	plen += sizeof(uint16_t);

	// Get the session
	struct conntrack_session *session = conntrack_session_get(s->ce);
	if (!session)
		return POM_ERR;

	struct analyzer_tftp_session_priv *spriv = conntrack_session_get_priv(session, obj);

	if (!spriv) {
		// Add session priv if it is not done yet
		spriv = malloc(sizeof(struct analyzer_tftp_session_priv));
		if (!spriv) {
			pom_oom(sizeof(struct analyzer_tftp_session_priv));
			goto err;
		}
		memset(spriv, 0, sizeof(struct analyzer_tftp_session_priv));

		if (conntrack_session_add_priv(session, obj, spriv, analyzer_tftp_session_priv_cleanup) != POM_OK) {
			free(spriv);
			goto err;
		}
	}

	switch (opcode) {
		case tftp_rrq:
		case tftp_wrq: {


			// Find the filename
			// The below should always be valid as proto_tftp already checked this
			char *filename = pload; 
			char *mode = memchr(filename, 0, plen - 1) + 1;

			struct analyzer_tftp_file *fq = malloc(sizeof(struct analyzer_tftp_file));
			if (!fq) {
				pom_oom(sizeof(struct analyzer_tftp_file));
				goto err;
			}
			memset(fq, 0, sizeof(struct analyzer_tftp_file));

			// Get the port on which we expect this file
			// No need to check the IP as we go the session biding
			struct proto_process_stack *s_prev = &stack[stack_index - 1];
			unsigned int i;
			for (i = 0; !fq->port ; i++) {
				char *name = s_prev->proto->info->pkt_fields[i].name;
				if (!name) {
					pomlog(POMLOG_ERR "Source port not found in RRQ/WRQ packets");
					goto err;
				}
				if (!strcmp(name, "sport")) {
					fq->port = *PTYPE_UINT16_GETVAL(s_prev->pkt_info->fields_value[i]);
					break;
				}
			}

			fq->evt = event_alloc(priv->evt_file);
			if (!fq->evt) {
				free(fq);
				goto err;
			}
			
			PTYPE_STRING_SETVAL(fq->evt->data[analyzer_tftp_file_filename].value, filename);
			data_set(fq->evt->data[analyzer_tftp_file_filename]);
			PTYPE_STRING_SETVAL(fq->evt->data[analyzer_tftp_file_mode].value, mode);
			data_set(fq->evt->data[analyzer_tftp_file_mode]);
			PTYPE_BOOL_SETVAL(fq->evt->data[analyzer_tftp_file_write].value, opcode == tftp_wrq);
			data_set(fq->evt->data[analyzer_tftp_file_write]);



			fq->next = spriv->files;
			if (fq->next)
				fq->next->prev = fq;
			spriv->files = fq;
			conntrack_session_unlock(session);

			event_process_begin(fq->evt, stack, stack_index);

			break;
		}

		case tftp_data: {

			struct analyzer_tftp_file *f = conntrack_get_priv(s->ce, obj);

			if (!f) {
				// The file is not yet associated to this connection
				// Find it in the queue
				
				struct proto_process_stack *s_prev = &stack[stack_index - 1];
				unsigned int i;
				uint16_t sport = 0, dport = 0;
				for (i = 0; !sport || !dport ; i++) {
					char *name = s_prev->proto->info->pkt_fields[i].name;
					if (!name) {
						pomlog(POMLOG_ERR "Source port not found in data packets");
						goto err;
					}
					if (!strcmp(name, "sport"))
						sport = *PTYPE_UINT16_GETVAL(s_prev->pkt_info->fields_value[i]);

					if (!strcmp(name, "dport"))
						dport = *PTYPE_UINT16_GETVAL(s_prev->pkt_info->fields_value[i]);
				}

				// Find the file in the session list
				for (f = spriv->files; ; f = f->next) {
					if (*PTYPE_BOOL_GETVAL(f->evt->data[analyzer_tftp_file_write].value)) {
						if (f->port == sport)
							break;
					} else {
						if (f->port == dport)
							break;
					}
				}

				if (!f) {
					pomlog(POMLOG_DEBUG "File not found in queued file request.");
					conntrack_session_unlock(session);
					return POM_OK;
				}
				
				// Remove the file from the queue and assign it to the conntrack
				if (f->prev)
					f->prev->next = f->next;
				else
					spriv->files = f->next;
				if (f->next)
					f->next->prev = f->prev;
				
				f->prev = NULL;
				f->next = NULL;

				// Create the payload buffer
				f->pload = analyzer_pload_buffer_alloc(NULL, 0, ANALYZER_PLOAD_BUFFER_NEED_MAGIC);
				if (!f->pload)
					goto err;

				conntrack_add_priv(s->ce, obj, f, analyzer_tftp_conntrack_priv_cleanup);
			}
			conntrack_session_unlock(session);
		
			if (!f->pload) {
				pomlog(POMLOG_DEBUG "Ignoring extra packet");
				return POM_OK;
			}

			struct proto_process_stack *s_next = &stack[stack_index + 1];

			if (analyzer_pload_buffer_append(f->pload, s_next->pload, s_next->plen) != POM_OK)
				goto err;

			uint32_t *size = PTYPE_UINT32_GETVAL(f->evt->data[analyzer_tftp_file_size].value);
			*size += s_next->plen;

			if (s_next->plen < ANALYZER_TFTP_BLK_SIZE) {
				// Got last packet !
				data_set(f->evt->data[analyzer_tftp_file_size]);
				
				int res = analyzer_pload_buffer_cleanup(f->pload);
				res += event_process_end(f->evt);
				f->evt = NULL;	
				f->pload = NULL;
				if (res)
					goto err;
			}

			break;
		}

		case tftp_error: {
			conntrack_session_unlock(session);

			struct analyzer_tftp_file *f = conntrack_get_priv(s->ce, obj);
			if (f && f->pload) {
				int res = analyzer_pload_buffer_cleanup(f->pload);
				res += event_process_end(f->evt);
				f->pload = NULL;
				f->evt = NULL;
				if (res)
					goto err;
			}
			break;
		}

		default:
			conntrack_session_unlock(session);
			break;
	}
	
	return POM_OK;

err:
	conntrack_session_unlock(session);
	return POM_ERR;
}
