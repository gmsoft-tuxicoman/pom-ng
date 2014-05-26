/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2012-2014 Guy Martin <gmsoft@tuxicoman.be>
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


#include "output_tap.h"

#include <pom-ng/ptype_string.h>
#include <pom-ng/ptype_bool.h>
#include <pom-ng/filter.h>

#include <linux/if_tun.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#include <net/if.h>


struct mod_reg_info* output_tap_reg_info() {

	static struct mod_reg_info reg_info;
	memset(&reg_info, 0, sizeof(struct mod_reg_info));
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = output_tap_mod_register;
	reg_info.unregister_func = output_tap_mod_unregister;
	reg_info.dependencies = "proto_ethernet, ptype_bool, ptype_string";

	return &reg_info;

}

int output_tap_mod_register(struct mod_reg *mod) {


	static struct output_reg_info output_tap = { 0 };
	output_tap.name = "tap";
	output_tap.description = "Send packets to a virtual tap interface";
	output_tap.mod = mod;

	output_tap.init = output_tap_init;
	output_tap.open = output_tap_open;
	output_tap.close = output_tap_close;
	output_tap.cleanup = output_tap_cleanup;

	static struct addon_plugin_pload_reg addon_tap = { 0 };
	addon_tap.name = "tap";
	addon_tap.mod = mod;

	addon_tap.open = output_tap_open;
	addon_tap.close = output_tap_close;

	static struct addon_pload_param_reg params[] = {
		{ "ifname", "string" },
		{ "persistent", "bool" },
		{ "filter", "string" },
		{ 0 }
	};

	addon_tap.pload_params = params;

	if (output_register(&output_tap) != POM_OK ||
		addon_plugin_pload_register(&addon_tap) != POM_OK) {
		output_tap_mod_unregister();
		return POM_ERR;
	}

	return POM_OK;
}

int output_tap_mod_unregister() {

	int res = POM_OK;

	res += output_unregister("tap");
	res += addon_plugin_unregister("tap");

	return res;
}

static struct output_tap_priv *tap_init() {

	struct output_tap_priv *priv = malloc(sizeof(struct output_tap_priv));
	if (!priv) {
		pom_oom(sizeof(struct output_tap_priv));
		return NULL;
	}
	memset(priv, 0, sizeof(struct output_tap_priv));

	priv->fd = -1;

	priv->p_ifname = ptype_alloc("string");
	priv->p_persistent = ptype_alloc("bool");
	priv->p_filter = ptype_alloc("string");

	if (!priv->p_ifname || !priv->p_persistent) {
		output_tap_cleanup(priv);
		return NULL;
	}

	return priv;
}

int addon_tap_init(struct addon_plugin *a) {

	struct output_tap_priv *priv = tap_init();
	if (!priv)
		return POM_ERR;

	addon_plugin_set_priv(a, priv);

	if (addon_plugin_add_param(a, "ifname", "pom0", priv->p_ifname) != POM_OK)
		goto err;

	if (addon_plugin_add_param(a, "persistent", "no", priv->p_persistent) != POM_OK)
		goto err;

	return POM_OK;

err:
	output_tap_cleanup(priv);

	return POM_ERR;
}

int output_tap_init(struct output *o) {

	struct output_tap_priv *priv = tap_init();

	if (!priv)
		return POM_ERR;

	output_set_priv(o, priv);

	struct registry_instance *inst = output_get_reg_instance(o);
	priv->perf_pkts_out = registry_instance_add_perf(inst, "pkts_out", registry_perf_type_counter, "Number of packets processed", "pkts");
	priv->perf_bytes_out = registry_instance_add_perf(inst, "bytes_out", registry_perf_type_counter, "Number of bytes processed", "bytes");

	if (!priv->perf_pkts_out || !priv->perf_bytes_out)
		goto err;

	struct registry_param *p = registry_new_param("ifname", "pom0", priv->p_ifname, "Name of the interface to create", 0);
	if (output_add_param(o, p) != POM_OK)
		goto err;

	p = registry_new_param("persistent", "no", priv->p_persistent, "Create a persistent interface", 0);
	if (output_add_param(o, p) != POM_OK)
		goto err;

	p = registry_new_param("filter", "", priv->p_filter, "Filter", REGISTRY_PARAM_FLAG_NOT_LOCKED_WHILE_RUNNING);
	if (output_add_param(o, p) != POM_OK)
		goto err;

	registry_param_set_callbacks(p, priv, output_tap_filter_parse, output_tap_filter_update);
	
	return POM_OK;
err:
	output_tap_cleanup(priv);
	return POM_ERR;

}

int output_tap_cleanup(void *output_priv) {

	struct output_tap_priv *priv = output_priv;
	if (priv) {
		if (priv->p_ifname)
			ptype_cleanup(priv->p_ifname);
		if (priv->p_persistent)
			ptype_cleanup(priv->p_persistent);
		if (priv->p_filter)
			ptype_cleanup(priv->p_filter);
		free(priv);
	}

	return POM_OK;
}

int output_tap_open(void *output_priv) {

	struct output_tap_priv *priv = output_priv;
	
	priv->fd = open("/dev/net/tun", O_RDWR | O_SYNC);
	if (priv->fd < 0) {
		pomlog(POMLOG_ERR "Error while opening the tap device : %s", pom_strerror(errno));
		return POM_ERR;
	}

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(struct ifreq));
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
	strncpy(ifr.ifr_name, PTYPE_STRING_GETVAL(priv->p_ifname), IFNAMSIZ);
	if (ioctl(priv->fd, TUNSETIFF, (void *) &ifr) < 0) {
		pomlog(POMLOG_ERR "Unable to setup tap device %s : %s", PTYPE_STRING_GETVAL(priv->p_ifname), pom_strerror(errno));
		return POM_ERR;
	}

	if (ioctl(priv->fd, TUNSETPERSIST, *PTYPE_BOOL_GETVAL(priv->p_persistent)) < 0) {
		pomlog(POMLOG_WARN "Unable to set persistent mode to tap device %s : %s", PTYPE_STRING_GETVAL(priv->p_ifname), pom_strerror(errno));
	}

	priv->listener = proto_packet_listener_register(proto_get("ethernet"), 0, priv, output_tap_pkt_process, priv->filter);
	if (!priv->listener)
		goto err;

	return POM_OK;

err:
	close(priv->fd);
	priv->fd = -1;
	return POM_ERR;
}

int output_tap_close(void *output_priv) {
	
	struct output_tap_priv *priv = output_priv;

	proto_packet_listener_unregister(priv->listener);

	if (priv->fd != -1) {
		close(priv->fd);
		priv->fd = -1;
	}

	return POM_OK;
}
 
int output_tap_pkt_process(void *obj, struct packet *p, struct proto_process_stack *stack, unsigned int stack_index) {

	struct output_tap_priv *priv = obj;

	struct proto_process_stack *s = &stack[stack_index];

	ssize_t wres = 0;
	size_t size = s->plen, pos = 0;
	while (size > 0) {
		wres = write(priv->fd, s->pload + pos, size);
		if (wres == -1) {
			pomlog(POMLOG_ERR "Error while writing to the tap interface %s : %s", PTYPE_STRING_GETVAL(priv->p_ifname), pom_strerror(errno));
			return POM_ERR;
		}
		pos += wres;
		size -= wres;
	}

	if (priv->perf_pkts_out)
		registry_perf_inc(priv->perf_pkts_out, 1);
	if (priv->perf_bytes_out)
		registry_perf_inc(priv->perf_bytes_out, s->plen);

	return POM_OK;
}

static int output_tap_filter_parse(void *priv, char *value) {
	
	struct output_tap_priv *p = priv;
	return filter_packet(value, &p->filter);
}

static int output_tap_filter_update(void *priv, struct ptype *value) {

	struct output_tap_priv *p = priv;
	if (p->listener)
		proto_packet_listener_set_filter(p->listener, p->filter);
	return POM_OK;
}
