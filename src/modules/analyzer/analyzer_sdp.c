/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2014 Guy Martin <gmsoft@tuxicoman.be>
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

#include "analyzer_sdp.h"

#include <pom-ng/pload.h>
#include <pom-ng/ptype_string.h>

#if 0
#define debug_sdp(x ...) pomlog(POMLOG_DEBUG x)
#else
#define debug_sdp(x ...)
#endif

struct mod_reg_info* analyzer_sdp_reg_info() {

	static struct mod_reg_info reg_info;
	memset(&reg_info, 0, sizeof(struct mod_reg_info));
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = analyzer_sdp_mod_register;
	reg_info.unregister_func = analyzer_sdp_mod_unregister;
	reg_info.dependencies = "ptype_string, ptype_uint64";

	return &reg_info;
}

static int analyzer_sdp_mod_register(struct mod_reg *mod) {

	static struct analyzer_reg analyzer_sdp;
	memset(&analyzer_sdp, 0, sizeof(struct analyzer_reg));
	analyzer_sdp.name = "sdp";
	analyzer_sdp.mod = mod;
	analyzer_sdp.init = analyzer_sdp_init;

	return analyzer_register(&analyzer_sdp);

}

static int analyzer_sdp_mod_unregister() {

	return analyzer_unregister("sdp");
}

static int analyzer_sdp_init(struct analyzer *analyzer) {

	static struct data_item_reg pload_sdp_data_items[ANALYZER_SDP_PLOAD_DATA_COUNT] = { { 0 } };
	pload_sdp_data_items[analyzer_sdp_pload_username].name = "username";
	pload_sdp_data_items[analyzer_sdp_pload_username].value_type = ptype_get_type("string");

	pload_sdp_data_items[analyzer_sdp_pload_sess_id].name = "sess_id";
	pload_sdp_data_items[analyzer_sdp_pload_sess_id].value_type = ptype_get_type("uint64");

	pload_sdp_data_items[analyzer_sdp_pload_sess_version].name = "sess_version";
	pload_sdp_data_items[analyzer_sdp_pload_sess_version].value_type = ptype_get_type("uint64");

	pload_sdp_data_items[analyzer_sdp_pload_sess_addr_type].name = "sess_addr_type";
	pload_sdp_data_items[analyzer_sdp_pload_sess_addr_type].value_type = ptype_get_type("string");

	pload_sdp_data_items[analyzer_sdp_pload_sess_addr].name = "sess_addr";
	pload_sdp_data_items[analyzer_sdp_pload_sess_addr].value_type = ptype_get_type("string");

	pload_sdp_data_items[analyzer_sdp_pload_sess_name].name = "sess_name";
	pload_sdp_data_items[analyzer_sdp_pload_sess_name].value_type = ptype_get_type("string");
	static struct data_reg pload_sdp_data = {
		.items = pload_sdp_data_items,
		.data_count = ANALYZER_SDP_PLOAD_DATA_COUNT
	};

	static struct pload_analyzer pload_analyzer_reg = { 0 };
	pload_analyzer_reg.analyze = analyzer_sdp_pload_analyze;
	pload_analyzer_reg.cleanup = analyzer_sdp_pload_cleanup;
	pload_analyzer_reg.data_reg = &pload_sdp_data;

	return pload_set_analyzer(ANALYZER_SDP_PLOAD_TYPE, &pload_analyzer_reg);
}

static int analyzer_sdp_pload_analyze(struct pload *p, struct pload_buffer *pb, void *priv) {



	size_t len = pb->data_len;
	size_t pos = 0;

	struct data *pload_data = pload_get_data(p);

	struct analyzer_sdp_pload_priv *ppriv = pload_get_priv(p);
	if (ppriv) {
		pos = ppriv->pos;
		len -= pos;
	}

	char *buff = pb->data + pos;

	if (len > 1 && *buff == '\n') {
		// Just in case the last packet ended in the middle of a CRLF
		buff++;
		len--;
	}

	while (len > 0) {
		char *cr = memchr(buff, '\r', len);
		if (!cr) {
			if (!ppriv) {
				ppriv = malloc(sizeof(struct analyzer_sdp_pload_priv));
				if (!priv) {
					pom_oom(sizeof(struct analyzer_sdp_pload_priv));
					return PLOAD_ANALYSIS_ERR;
				}
				memset(priv, 0, sizeof(struct analyzer_sdp_pload_priv));
			}

			ppriv->pos = pos;
			return PLOAD_ANALYSIS_MORE;
		}

		size_t line_len = cr - buff;
		if (line_len < 3) // We need at least 1 byte of data after = sign
			return PLOAD_ANALYSIS_FAILED;
		if (buff[1] != '=')
			return PLOAD_ANALYSIS_FAILED;

		char f = *buff;
		pos += line_len + 1;
		len -= line_len + 1;

		char * line = buff + 2;
		buff += line_len + 1;
		line_len -= 2;

		if (len > 1 && *buff == '\n') {
			pos++;
			len--;
			buff++;
		}

		switch (f) {
			case 'v':
				if (line_len != 1)
					return PLOAD_ANALYSIS_FAILED;
				if (*line != '0') // Version must be 0
					return PLOAD_ANALYSIS_FAILED;
				break;
			case 'o': {
				int tok_num = 0;
				while (line_len) {
					char *space = memchr(line, ' ', line_len);
					size_t tok_len = line_len;
					if (space)
						tok_len = space - line;
					char id_buff[24] = { 0 };
					switch (tok_num) {
						case 0:
							PTYPE_STRING_SETVAL_N(pload_data[analyzer_sdp_pload_username].value, line, tok_len);
							data_set(pload_data[analyzer_sdp_pload_username]);
							break;
						case 1:
						case 2:
							if (tok_len > sizeof(id_buff) -1)
								return PLOAD_ANALYSIS_FAILED;
							memcpy(id_buff, line, tok_len);

							if (ptype_parse_val(pload_data[(tok_num == 1 ? analyzer_sdp_pload_sess_id : analyzer_sdp_pload_sess_version)].value, id_buff) != POM_OK)
								return PLOAD_ANALYSIS_FAILED;
							break;
						case 3:
							break; // It's always 'IN'
						case 4:
						case 5:
							PTYPE_STRING_SETVAL_N(pload_data[(tok_num == 4 ? analyzer_sdp_pload_sess_addr_type : analyzer_sdp_pload_sess_addr)].value, line, tok_len);
							data_set(pload_data[(tok_num == 4 ? analyzer_sdp_pload_sess_addr_type : analyzer_sdp_pload_sess_addr)]);
							break;

					}
					tok_num++;
					line += tok_len;
					line_len -= tok_len;
					while (line_len > 0 && *line == ' ') {
						line_len--;
						line++;
					}
				}
				if (tok_num != 6) 
					return PLOAD_ANALYSIS_FAILED;
				break;
				}
			case 's':
				PTYPE_STRING_SETVAL_N(pload_data[analyzer_sdp_pload_sess_name].value, line, line_len);
				data_set(pload_data[analyzer_sdp_pload_sess_name]);
				return PLOAD_ANALYSIS_OK;
				break;
		}
	}
	
	return PLOAD_ANALYSIS_MORE;
}

static int analyzer_sdp_pload_cleanup(struct pload *p, void *apriv) {

	struct analyzer_sip_pload_priv *priv = pload_get_priv(p);


	if (!priv)
		return POM_OK;

	free(priv);

	return POM_OK;
}

