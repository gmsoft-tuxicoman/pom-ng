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


#ifndef __ANALYZER_SDP_H__
#define __ANALYZER_SDP_H__

#include <pom-ng/analyzer.h>
#include <pom-ng/pload.h>

#define ANALYZER_SDP_PLOAD_TYPE "sdp"

#define ANALYZER_SDP_PLOAD_DATA_COUNT 6


enum analyzer_sdp_pload_data {
	analyzer_sdp_pload_username = 0,
	analyzer_sdp_pload_sess_id ,
	analyzer_sdp_pload_sess_version,
	analyzer_sdp_pload_sess_addr_type,
	analyzer_sdp_pload_sess_addr,
	analyzer_sdp_pload_sess_name,
};


struct analyzer_sdp_pload_priv {

	size_t pos;

};

struct mod_reg_info* analyzer_sdp_reg_info();
static int analyzer_sdp_mod_register(struct mod_reg *mod);
static int analyzer_sdp_mod_unregister();

static int analyzer_sdp_init(struct analyzer *analyzer);
static int analyzer_sdp_pload_analyze(struct pload *p, struct pload_buffer *pb, void *priv);
static int analyzer_sdp_pload_cleanup(struct pload *p, void *apriv);

#endif
