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

#include "config.h"
#include "media.h"
#include "pload.h"


#include <gst/app/gstappsrc.h>
#include <gst/app/gstappsink.h>

#define MEDIA_DEFAULT_GST_LOG GST_LEVEL_LOG
#define MEDIA_DEBUG_FORMAT "x%s"

static GMainLoop *loop = NULL;


int media_init() {

	gst_init(NULL, NULL);

	// Setup our own debugging function
	gst_debug_set_default_threshold(MEDIA_DEFAULT_GST_LOG);
	gst_debug_remove_log_function(gst_debug_log_default);
	gst_debug_add_log_function(media_debug, NULL, NULL);

	loop = g_main_loop_new(NULL, TRUE);

	return POM_OK;
}

int media_cleanup() {

	g_main_loop_quit(loop);
	g_main_loop_unref(loop);
	gst_deinit();

	return POM_OK;
}


void media_debug(GstDebugCategory *category, GstDebugLevel level, const gchar *file, const gchar *function, gint line, GObject *object, GstDebugMessage *message, gpointer user_data) {


	char format[strlen(MEDIA_DEBUG_FORMAT) + 1];
	memcpy(format, MEDIA_DEBUG_FORMAT, strlen(MEDIA_DEBUG_FORMAT) + 1);
	switch (level) {
		case GST_LEVEL_NONE:
		case GST_LEVEL_ERROR:
			*format = *POMLOG_ERR;
			break;
		case GST_LEVEL_WARNING:
			*format = *POMLOG_WARN;
			break;
		case GST_LEVEL_FIXME:
		case GST_LEVEL_INFO:
			*format = *POMLOG_INFO;
			break;
		default:
			*format = *POMLOG_DEBUG;
			break;
	}
	pomlog_internal(file, format, gst_debug_message_get(message));
}



void media_pload_need_data(GstElement *appsrc, guint unused_size, gpointer user_data) {

	struct media_pload_priv *priv = user_data;
	if (!priv->srcmap) {
		priv->srcmap = pload_store_read_start(priv->src);
		if (!priv->srcmap) {
			gst_app_src_end_of_stream(GST_APP_SRC(priv->gst_src));
			return;
		}
	}

	void *read_buf = NULL;

	ssize_t res = pload_store_read(priv->srcmap, &read_buf, unused_size);

	if (res == 0) {
		gst_app_src_end_of_stream(GST_APP_SRC(priv->gst_src));
		pload_store_read_end(priv->srcmap);
		return;
	}

	GstBuffer *gst_buf = gst_buffer_new_wrapped(read_buf, res);

	if (gst_app_src_push_buffer(GST_APP_SRC(priv->gst_src), gst_buf) != GST_FLOW_OK) {
		pomlog(POMLOG_ERR "Error while pushing buffer to gstreamer");
	}
}

GstFlowReturn media_pload_new_sample(GstAppSink *appsink, gpointer user_data) {

	struct media_pload_priv *priv = user_data;

	GstSample *sample = gst_app_sink_pull_sample(appsink);

	if (!sample) {
		pomlog(POMLOG_ERR "Got EOS from appsink");
		return GST_FLOW_ERROR;
	}

	GstBuffer *buff = gst_sample_get_buffer(sample);
	if (!buff) {
		pomlog(POMLOG_WARN "GST sample without buffer received");
		gst_sample_unref(sample);
		return GST_FLOW_ERROR;
	}

	GstMemory *mem = gst_buffer_get_all_memory(buff);

	GstMapInfo info = { 0 };
	if (gst_memory_map(mem, &info, GST_MEMORY_FLAG_READONLY) == FALSE) {
		pomlog(POMLOG_ERR "Error while mapping memory");
		gst_sample_unref(sample);
	}

	// FIXME there is probably a better way than copying this memory
	int res = pload_append(priv->out, info.data, info.size);
	//gst_sample_unref(sample);

	if (res != POM_OK)
		return GST_FLOW_ERROR;

	return GST_FLOW_OK;
}

void media_pload_eos(GstAppSink *appsink, gpointer user_data) {

	struct media_pload_priv *priv = user_data;
	pload_end(priv->out);
}

struct pload *media_pload_to_container(struct pload_store *ps, char *format) {


	struct media_pload_priv *priv = malloc(sizeof(struct media_pload_priv));
	if (!priv) {
		pom_oom(sizeof(struct media_pload_priv));
		return NULL;
	}
	memset(priv, 0, sizeof(struct media_pload_priv));
	priv->src = ps;

	GstElement *mux;

	priv->gst_pipeline = gst_pipeline_new(NULL);
	priv->gst_src = gst_element_factory_make("appsrc", NULL);

	// FIXME this must be configurable of course
	mux = gst_element_factory_make("wavenc", NULL);
	priv->gst_dst = gst_element_factory_make("appsink", NULL);

	gst_bin_add_many(GST_BIN(priv->gst_pipeline), priv->gst_src, mux, priv->gst_dst, NULL);
	if (!gst_element_link_many(priv->gst_src, mux, priv->gst_dst, NULL)) {
		pomlog(POMLOG_ERR "Error while linking elements");
		goto err;

	}

	// Setup appsrc
	g_object_set(G_OBJECT(priv->gst_src), "stream-type", GST_APP_STREAM_TYPE_STREAM, "format", GST_FORMAT_TIME, NULL);
	g_signal_connect(priv->gst_src, "need-data", G_CALLBACK(media_pload_need_data), priv);

	struct pload *pload = pload_store_get_pload(ps);
	struct mime_type *m = pload_get_mime_type(pload);
	if (!m)
		goto err;

	char mime_type_str[20] = { 0 };
	snprintf(mime_type_str, sizeof(mime_type_str), "%s/%s", mime_top_type_str(m->top_type), m->name);

	GstCaps *caps = gst_caps_new_empty_simple(mime_type_str);
	int i;
	for (i = 0; i < MIME_MAX_PARAMETERS && m->params[i].name; i++) {
		GType try_types[] = { G_TYPE_INT, G_TYPE_DOUBLE, GST_TYPE_FRACTION, G_TYPE_BOOLEAN, G_TYPE_STRING };
		GValue value = { 0 };
		int j;
		for (j = 0; G_N_ELEMENTS (try_types); j++) {
			g_value_init(&value, try_types[j]);
			int ret = gst_value_deserialize(&value, m->params[i].value);
			if (ret)
				break;
			g_value_unset(&value);
		}
		gst_caps_set_value(caps, m->params[i].name, &value);
		g_value_unset(&value);

	}
	g_object_set (G_OBJECT (priv->gst_src), "caps", caps, NULL);

	// Setup appsink
	g_signal_connect(priv->gst_dst, "new_sample", G_CALLBACK(media_pload_new_sample), priv);
	g_signal_connect(priv->gst_dst, "eos", G_CALLBACK(media_pload_eos), priv);


	struct event *evt = pload_get_related_event(pload);
	priv->out = pload_alloc(evt, 0);
	if (!priv->out)
		goto err;


	// Start the gstreamer magic
	gst_element_set_state(priv->gst_pipeline, GST_STATE_PLAYING);

	pload_store_get_ref(ps);

	return priv->out;

err:
	gst_object_unref(GST_OBJECT(priv->gst_pipeline));
	free(priv);
	return NULL;
}

