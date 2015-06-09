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

#include "analyzer_dtmf.h"

#include <pom-ng/pload.h>
#include <pom-ng/ptype_string.h>
#include <pom-ng/ptype_uint16.h>

#if 0
#define debug_dtmf(x ...) pomlog(POMLOG_DEBUG x)
#else
#define debug_dtmf(x ...)
#endif

struct mod_reg_info* analyzer_dtmf_reg_info() {

	static struct mod_reg_info reg_info;
	memset(&reg_info, 0, sizeof(struct mod_reg_info));
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = analyzer_dtmf_mod_register;
	reg_info.unregister_func = analyzer_dtmf_mod_unregister;
	reg_info.dependencies = "ptype_string, ptype_uint16";

	return &reg_info;
}

static int analyzer_dtmf_mod_register(struct mod_reg *mod) {

	static struct analyzer_reg analyzer_dtmf;
	memset(&analyzer_dtmf, 0, sizeof(struct analyzer_reg));
	analyzer_dtmf.name = "dtmf";
	analyzer_dtmf.mod = mod;
	analyzer_dtmf.init = analyzer_dtmf_init;

	return analyzer_register(&analyzer_dtmf);

}

static int analyzer_dtmf_mod_unregister() {

	return analyzer_unregister("dtmf");
}

static int analyzer_dtmf_init(struct analyzer *analyzer) {

	static struct data_item_reg pload_dtmf_data_items[ANALYZER_DTMF_PLOAD_DATA_COUNT] = { { 0 } };
	pload_dtmf_data_items[analyzer_dtmf_pload_signal].name = "signal";
	pload_dtmf_data_items[analyzer_dtmf_pload_signal].value_type = ptype_get_type("string");

	pload_dtmf_data_items[analyzer_dtmf_pload_duration].name = "duration";
	pload_dtmf_data_items[analyzer_dtmf_pload_duration].value_type = ptype_get_type("uint16");

	static struct data_reg pload_dtmf_data = {
		.items = pload_dtmf_data_items,
		.data_count = ANALYZER_DTMF_PLOAD_DATA_COUNT
	};

	static struct pload_analyzer pload_analyzer_reg = { 0 };
	pload_analyzer_reg.analyze = analyzer_dtmf_pload_analyze;
	pload_analyzer_reg.cleanup = analyzer_dtmf_pload_cleanup;
	pload_analyzer_reg.data_reg = &pload_dtmf_data;

	return pload_set_analyzer(ANALYZER_DTMF_PLOAD_TYPE, &pload_analyzer_reg);
}

static int analyzer_dtmf_pload_analyze(struct pload *p, struct pload_buffer *pb, void *priv) {


	struct {
		char *name;
		int field;
	} dtmf_fields[] = {
		{ "Signal=", analyzer_dtmf_pload_signal },
		{ "Duration=", analyzer_dtmf_pload_duration },
		{ NULL, 0 },
	};

	size_t len = pb->data_len;
	size_t pos = 0;

	struct data *pload_data = pload_get_data(p);

	struct analyzer_dtmf_pload_priv *ppriv = pload_get_analyzer_priv(p);
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
				ppriv = malloc(sizeof(struct analyzer_dtmf_pload_priv));
				if (!ppriv) {
					pom_oom(sizeof(struct analyzer_dtmf_pload_priv));
					return PLOAD_ANALYSIS_ERR;
				}
				memset(ppriv, 0, sizeof(struct analyzer_dtmf_pload_priv));
			}

			ppriv->pos = pos;
			pload_set_analyzer_priv(p, ppriv);
			return PLOAD_ANALYSIS_MORE;
		}

		size_t line_len = cr - buff;
		char *line = buff;
		pos += line_len + 1;
		buff += line_len + 1;
		len -= line_len + 1;

		if (len > 1 && *buff == '\n') {
			pos++;
			len--;
			buff++;
		}

		int i;
		for (i = 0; dtmf_fields[i].name; i++) {
			size_t str_len = strlen(dtmf_fields[i].name);
			if (line_len < str_len)
				break;

			if (!strncasecmp(line, dtmf_fields[i].name, str_len)) {
				line += str_len;
				line_len -= str_len;
				while (line_len > 0 && *line == ' ') {
					line++;
					line_len--;
				}

				while (line_len > 0 && line[line_len - 1] == ' ')
					line_len--;
				if (dtmf_fields[i].field == analyzer_dtmf_pload_signal) {
					char signal[2] = { 0 };
					*signal = *line;
					PTYPE_STRING_SETVAL(pload_data[analyzer_dtmf_pload_signal].value, signal);
					data_set(pload_data[analyzer_dtmf_pload_signal]);
				} else if (dtmf_fields[i].field == analyzer_dtmf_pload_duration) {
					char duration_str[5] = { 0 };
					if (line_len >= 5)
						return PLOAD_ANALYSIS_FAILED;
					memcpy(duration_str, line, line_len);
					uint16_t duration = 0;
					if (sscanf(duration_str, "%hu", &duration) != 1)
						return PLOAD_ANALYSIS_FAILED;
					PTYPE_UINT16_SETVAL(pload_data[analyzer_dtmf_pload_duration].value, duration);
					data_set(pload_data[analyzer_dtmf_pload_duration]);
				}
				break;
			}
		}

		if (data_is_set(pload_data[analyzer_dtmf_pload_signal]) && data_is_set(pload_data[analyzer_dtmf_pload_duration]))
			return PLOAD_ANALYSIS_OK;
	}
	
	return PLOAD_ANALYSIS_MORE;
}

static int analyzer_dtmf_pload_cleanup(struct pload *p, void *apriv) {

	struct analyzer_sip_pload_priv *priv = pload_get_analyzer_priv(p);


	if (!priv)
		return POM_OK;

	free(priv);

	return POM_OK;
}

