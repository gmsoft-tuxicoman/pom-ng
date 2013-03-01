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

#include <pom-ng/ptype.h>
#include <pom-ng/proto.h>
#include <pom-ng/core.h>
#include <pom-ng/event.h>
#include <pom-ng/stream.h>
#include <pom-ng/ptype_uint16.h>

#include <pom-ng/proto_tftp.h>
#include "proto_tftp.h"

#include <arpa/inet.h>

#if 1
#define debug_tftp(x ...) pomlog(POMLOG_DEBUG x)
#else
#define debug_tftp(x ...)
#endif

struct proto *proto_tftp = NULL;

struct mod_reg_info* proto_tftp_reg_info() {

	static struct mod_reg_info reg_info = { 0 };
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = proto_tftp_mod_register;
	reg_info.unregister_func = proto_tftp_mod_unregister;
	reg_info.dependencies = "ptype_uint16, ptype_uint32";

	return &reg_info;
}

static int proto_tftp_mod_register(struct mod_reg *mod) {

	static struct proto_pkt_field fields[PROTO_TFTP_FIELD_NUM + 1] = { { 0 }};
	fields[0].name = "opcode";
	fields[0].value_type = ptype_get_type("uint16");
	fields[0].description = "OP code";

	static struct proto_reg_info proto_tftp = { 0 };
	proto_tftp.name = "tftp";
	proto_tftp.api_ver = PROTO_API_VER;
	proto_tftp.mod = mod;
	proto_tftp.pkt_fields = fields;

	static struct conntrack_info ct_info = { 0 };
	ct_info.default_table_size = 1; // No hashing done here
	ct_info.cleanup_handler = proto_tftp_conntrack_cleanup;
	proto_tftp.ct_info = &ct_info;

	proto_tftp.init = proto_tftp_init;
	proto_tftp.process = proto_tftp_process;

	if (proto_register(&proto_tftp) == POM_OK)
		return POM_OK;


	return POM_ERR;

}

static int proto_tftp_init(struct proto *proto, struct registry_instance *i) {

	proto_tftp = proto;
	return POM_OK;
}

static int proto_tftp_process(void *proto_priv, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct proto_process_stack *s = &stack[stack_index];
	struct proto_process_stack *s_prev = &stack[stack_index - 1];
	struct proto_process_stack *s_next = &stack[stack_index + 1];

	if (conntrack_get_unique_from_parent(stack, stack_index) != POM_OK) {
		pomlog(POMLOG_ERR "Could not get a conntrack entry");
		return PROTO_ERR;
	}

	struct proto_tftp_conntrack_priv *priv = s->ce->priv;
	if (!priv) {
		priv = malloc(sizeof(struct proto_tftp_conntrack_priv));
		if (!priv) {
			pom_oom(sizeof(struct proto_tftp_conntrack_priv));
			conntrack_unlock(s->ce);
			return POM_ERR;
		}
		memset(priv, 0, sizeof(struct proto_tftp_conntrack_priv));

		s->ce->priv = priv;
	}

	if (priv->flags & PROTO_TFTP_CONN_INVALID) {
		conntrack_unlock(s->ce);
		return PROTO_INVALID;
	}

	void *pload = s->pload;
	uint32_t plen = s->plen;

	uint16_t opcode = ntohs(*((uint16_t*)pload));
	PTYPE_UINT16_SETVAL(s->pkt_info->fields_value[proto_tftp_field_opcode], opcode);
	pload += sizeof(uint16_t);
	plen -= sizeof(uint16_t);

	switch (opcode) {
		case tftp_rrq:
		case tftp_wrq: {

			// Find the filename
			char *filename = pload;
			char *mode = memchr(filename, 0, plen - 1);
			if (!mode) {
				priv->flags |= PROTO_TFTP_CONN_INVALID;
				conntrack_unlock(s->ce);
				debug_tftp("End of filename not found in read/write request");
				return PROTO_INVALID;
			}
			mode++;
			ssize_t filename_len = mode - filename;

			char *end = memchr(mode, 0, plen - filename_len);
			if (!end) {
				priv->flags |= PROTO_TFTP_CONN_INVALID;
				conntrack_unlock(s->ce);
				debug_tftp("End of mode not found in read/write request");
				return PROTO_INVALID;
			}
			debug_tftp("Got read/write request for filename \"%s\" with mode \"%s\"", filename, mode);

			struct conntrack_session *session = conntrack_session_get(s->ce);
			if (!session) {
				conntrack_unlock(s->ce);
				return POM_ERR;
			}

			// We don't need to do anything with the session
			conntrack_session_unlock(session);

			struct proto_expectation *expt = proto_expectation_alloc_from_conntrack(s_prev->ce, proto_tftp, NULL);

			if (!expt) {
				conntrack_unlock(s->ce);
				return PROTO_ERR;
			}

			proto_expectation_set_field(expt, -1, NULL, POM_DIR_REV);

			if (proto_expectation_add(expt, session, PROTO_TFTP_EXPT_TIMER, p->ts) != POM_OK) {
				conntrack_unlock(s->ce);
				proto_expectation_cleanup(expt);
				return PROTO_ERR;
			}

			break;
		}
		case tftp_data: {
			if (plen < 2) {
				priv->flags |= PROTO_TFTP_CONN_INVALID;
				conntrack_unlock(s->ce);
				return PROTO_INVALID;
			}
			uint16_t block_id = ntohs(*((uint16_t*)(pload)));
			pload += sizeof(uint16_t);
			plen -= sizeof(uint16_t);

			s_next->pload = pload;
			s_next->plen = plen;

			if (!priv->stream) {
				priv->stream = stream_alloc(PROTO_TFTP_STREAM_BUFF, s->ce, 0, proto_tftp_process_payload);
				if (!priv->stream) {
					conntrack_unlock(s->ce);
					return PROTO_ERR;
				}
				stream_set_timeout(priv->stream, PROTO_TFTP_PKT_TIMER, 0);
				stream_set_start_seq(priv->stream, s->direction, PROTO_TFTP_BLK_SIZE);
			}

			int res = stream_process_packet(priv->stream, p, stack, stack_index + 1, block_id * 512, 0);
			if (res == PROTO_OK) {
				conntrack_unlock(s->ce);
				return PROTO_STOP;
			}

			conntrack_unlock(s->ce);
			return res;
		}

		case tftp_ack:
			// Nothing to do
			break;

		case tftp_error:
			// An error occured, cleanup this conntrack soon
			conntrack_delayed_cleanup(s->ce, 1, p->ts);
			break;

		default:
			priv->flags |= PROTO_TFTP_CONN_INVALID;
			conntrack_unlock(s->ce);
			return PROTO_INVALID;
	}

	conntrack_delayed_cleanup(s->ce, PROTO_TFTP_PKT_TIMER, p->ts);
	conntrack_unlock(s->ce);
	return PROTO_OK;
}

static int proto_tftp_mod_unregister() {

	return proto_unregister("tftp");
}

static int proto_tftp_conntrack_cleanup(void *ce_priv) {

	struct proto_tftp_conntrack_priv *priv = ce_priv;
		
	if (priv->stream)
		stream_cleanup(priv->stream);

	free(priv);

	return POM_OK;
}

static int proto_tftp_process_payload(struct conntrack_entry *ce, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	return core_process_multi_packet(stack, stack_index, p);
}

