/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2015 Guy Martin <gmsoft@tuxicoman.be>
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

#ifndef __MEDIA_H__
#define __MEDIA_H__


#include <gst/gst.h>
#include <pom-ng/pload.h>

#define MEDIA_REGISTRY "media"

struct media_pload_priv {
	GstElement *gst_pipeline, *gst_src, *gst_dst;
	struct pload_store *src;
	struct pload_store_map *srcmap;
	struct pload *out;
};

int media_init();
int media_cleanup();

int media_param_gst_debug_level_cb(void *priv, struct registry_param *p, struct ptype *value);
void media_debug(GstDebugCategory *category, GstDebugLevel level, const gchar *file, const gchar *function, gint line, GObject *object, GstDebugMessage *message, gpointer user_data) G_GNUC_NO_INSTRUMENT;

struct pload *media_pload_to_container(struct pload_store *p, char *format);

#endif
