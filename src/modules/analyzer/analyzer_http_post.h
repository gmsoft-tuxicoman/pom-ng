/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2011-2014 Guy Martin <gmsoft@tuxicoman.be>
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


#ifndef __ANALYZER_HTTP_POST_H__
#define __ANALYZER_HTTP_POST_H__

#include "analyzer_http.h"

#define ANALYZER_HTTP_POST_PLOAD_TYPE "form-urlencoded"

struct analyzer_http_post_pload_priv {

	struct event *evt;
	char *buff;

};

int analyzer_http_post_init(struct analyzer *analyzer);
int analyzer_http_post_cleanup(struct analyzer *analyzer);

int analyzer_http_post_pload_open(void *obj, void **priv, struct pload *pload);
int analyzer_http_post_pload_write(void *obj, void *p, void *data, size_t len);
int analyzer_http_post_pload_close(void *obj, void *p);
#endif
