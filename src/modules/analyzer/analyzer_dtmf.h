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


#ifndef __ANALYZER_DTMF_H__
#define __ANALYZER_DTMF_H__

#include <pom-ng/analyzer.h>
#include <pom-ng/pload.h>
#include <pom-ng/analyzer_dtmf.h>

#define ANALYZER_DTMF_PLOAD_TYPE "dtmf"

#define ANALYZER_DTMF_PLOAD_DATA_COUNT 2

struct analyzer_dtmf_pload_priv {

	size_t pos;

};

struct mod_reg_info* analyzer_dtmf_reg_info();
static int analyzer_dtmf_mod_register(struct mod_reg *mod);
static int analyzer_dtmf_mod_unregister();

static int analyzer_dtmf_init(struct analyzer *analyzer);
static int analyzer_dtmf_pload_analyze(struct pload *p, struct pload_buffer *pb, void *priv);
static int analyzer_dtmf_pload_cleanup(struct pload *p, void *apriv);

#endif
