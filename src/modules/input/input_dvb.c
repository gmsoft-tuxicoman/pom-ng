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


#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <arpa/inet.h>

#include <linux/dvb/dmx.h>
#include <linux/dvb/frontend.h>

#include <sys/ioctl.h>
#include <errno.h>

#include <sys/poll.h>

#include <pom-ng/input.h>
#include <pom-ng/ptype_bool.h>
#include <pom-ng/ptype_string.h>
#include <pom-ng/ptype_uint8.h>
#include <pom-ng/ptype_uint16.h>
#include <pom-ng/ptype_uint32.h>

#include <pom-ng/registry.h>

#include <pom-ng/packet.h>
#include <pom-ng/core.h>
#include <pom-ng/timer.h>
#include <pom-ng/event.h>

#include <docsis.h>

#include "input_dvb.h"

/// We use a bigger buffer size of the demux interface. This way we can cope with some burst.
#define DEMUX_BUFFER_SIZE 2097152 // 2MB

#define PID_FULL_TS 0x2000
#define MPEG_TS_LEN 188

#define LNB_COUNT 1

static struct event_reg *input_dvb_evt_status_reg = NULL;
static struct event_reg *evt_docsis_scan_stream_reg = NULL;

static struct input_dvb_lnb_param input_dvb_lnbs[LNB_COUNT] = {
	{ "universal", 9750000, 10600000, 11700000, 10700000, 12750000 },
};

struct mod_reg_info* input_dvb_reg_info() {

	static struct mod_reg_info reg_info;
	memset(&reg_info, 0, sizeof(struct mod_reg_info));
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = input_dvb_mod_register;
	reg_info.unregister_func = input_dvb_mod_unregister;
	reg_info.dependencies = "proto_docsis, proto_mpeg, ptype_bool, ptype_string, ptype_uint8, ptype_uint16, ptype_uint32";

	return &reg_info;

}

static int input_dvb_mod_register(struct mod_reg *mod) {

	int res = POM_OK;

	static struct input_reg_info in_dvb_device;
	memset(&in_dvb_device, 0, sizeof(struct input_reg_info));
	in_dvb_device.name = "dvb_device";
	in_dvb_device.description = "Read from a DVB device not supported by the standard linux DVB API";
	in_dvb_device.flags = INPUT_REG_FLAG_LIVE;
	in_dvb_device.mod = mod;
	in_dvb_device.init = input_dvb_device_init;
	in_dvb_device.open = input_dvb_device_open;
	in_dvb_device.read = input_dvb_read;
	in_dvb_device.close = input_dvb_close;
	in_dvb_device.cleanup = input_dvb_cleanup;

	res += input_register(&in_dvb_device);

	static struct input_reg_info in_dvb_c;
	memset(&in_dvb_c, 0, sizeof(struct input_reg_info));
	in_dvb_c.name = "dvb_c";
	in_dvb_c.description = "Read from a DVB-C device";
	in_dvb_c.flags = INPUT_REG_FLAG_LIVE;
	in_dvb_c.mod = mod;
	in_dvb_c.init = input_dvb_c_init;
	in_dvb_c.open = input_dvb_open;
	in_dvb_c.read = input_dvb_read;
	in_dvb_c.close = input_dvb_close;
	in_dvb_c.cleanup = input_dvb_cleanup;
	in_dvb_c.register_func = input_dvb_register;
	in_dvb_c.unregister_func = input_dvb_unregister;

	res += input_register(&in_dvb_c);

	static struct input_reg_info in_dvb_s;
	memset(&in_dvb_s, 0, sizeof(struct input_reg_info));
	in_dvb_s.name = "dvb_s";
	in_dvb_s.description = "Read from a DVB-S device";
	in_dvb_s.flags = INPUT_REG_FLAG_LIVE;
	in_dvb_s.mod = mod;
	in_dvb_s.init = input_dvb_s_init;
	in_dvb_s.open = input_dvb_open;
	in_dvb_s.read = input_dvb_read;
	in_dvb_s.close = input_dvb_close;
	in_dvb_s.cleanup = input_dvb_cleanup;
	in_dvb_s.register_func = input_dvb_register;
	in_dvb_s.unregister_func = input_dvb_unregister;

	res += input_register(&in_dvb_s);

	static struct input_reg_info in_dvb_atsc;
	memset(&in_dvb_atsc, 0, sizeof(struct input_reg_info));
	in_dvb_atsc.name = "dvb_atsc";
	in_dvb_atsc.description = "Read from a DVB-ATSC device";
	in_dvb_atsc.flags = INPUT_REG_FLAG_LIVE;
	in_dvb_atsc.mod = mod;
	in_dvb_atsc.init = input_dvb_atsc_init;
	in_dvb_atsc.open = input_dvb_open;
	in_dvb_atsc.read = input_dvb_read;
	in_dvb_atsc.close = input_dvb_close;
	in_dvb_atsc.cleanup = input_dvb_cleanup;
	in_dvb_atsc.register_func = input_dvb_register;
	in_dvb_atsc.unregister_func = input_dvb_unregister;

	res += input_register(&in_dvb_atsc);


	static struct input_reg_info in_docsis;
	memset(&in_docsis, 0, sizeof(struct input_reg_info));
	in_docsis.name = "docsis";
	in_docsis.description = "Read a DOCSIS stream";
	in_docsis.flags = INPUT_REG_FLAG_LIVE;
	in_docsis.mod = mod;
	in_docsis.init = input_dvb_docsis_init;
	in_docsis.open = input_dvb_open;
	in_docsis.read = input_dvb_docsis_read;
	in_docsis.close = input_dvb_close;
	in_docsis.cleanup = input_dvb_cleanup;
	in_docsis.register_func = input_dvb_register;
	in_docsis.unregister_func = input_dvb_unregister;

	res += input_register(&in_docsis);

	static struct input_reg_info in_docsis_scan;
	memset(&in_docsis_scan, 0, sizeof(struct input_reg_info));
	in_docsis_scan.name = "docsis_scan";
	in_docsis_scan.description = "Read a DOCSIS stream";
	in_docsis_scan.flags = INPUT_REG_FLAG_LIVE;
	in_docsis_scan.mod = mod;
	in_docsis_scan.init = input_dvb_docsis_scan_init;
	in_docsis_scan.open = input_dvb_docsis_scan_open;
	in_docsis_scan.read = input_dvb_docsis_scan_read;
	in_docsis_scan.close = input_dvb_close;
	in_docsis_scan.cleanup = input_dvb_cleanup;
	in_docsis_scan.register_func = input_dvb_docsis_scan_register;
	in_docsis_scan.unregister_func = input_dvb_docsis_scan_unregister;

	res += input_register(&in_docsis_scan);

	return res;
}

static int input_dvb_mod_unregister() {
	
	int res = POM_OK;
	res += input_unregister("dvb_device");
	res += input_unregister("dvb_c");
	res += input_unregister("dvb_s");
	res += input_unregister("dvb_atsc");
	res += input_unregister("docsis");
	res += input_unregister("docsis_scan");

	return res;
}

static int input_dvb_register() {

	if (input_dvb_evt_status_reg)
		return POM_OK;

	static struct data_item_reg evt_dvb_status_data_items[INPUT_DVB_STATUS_DATA_COUNT] = { { 0 } };
	evt_dvb_status_data_items[input_dvb_status_lock].name = "lock";
	evt_dvb_status_data_items[input_dvb_status_lock].value_type = ptype_get_type("bool");

	evt_dvb_status_data_items[input_dvb_status_adapter].name = "adapter";
	evt_dvb_status_data_items[input_dvb_status_adapter].value_type = ptype_get_type("uint16");

	evt_dvb_status_data_items[input_dvb_status_frontend].name = "frontend";
	evt_dvb_status_data_items[input_dvb_status_frontend].value_type = ptype_get_type("uint16");

	evt_dvb_status_data_items[input_dvb_status_frequency].name = "frequency";
	evt_dvb_status_data_items[input_dvb_status_frequency].value_type = ptype_get_type("uint32");

	evt_dvb_status_data_items[input_dvb_status_input_name].name = "input_name";
	evt_dvb_status_data_items[input_dvb_status_input_name].value_type = ptype_get_type("string");

	static struct data_reg evt_dvb_status_data = {
		.items = evt_dvb_status_data_items,
		.data_count = INPUT_DVB_STATUS_DATA_COUNT
	};

	static struct event_reg_info input_dvb_evt_status = { 0 };
	input_dvb_evt_status.source_name = "input_dvb";
	input_dvb_evt_status.name = "dvb_status";
	input_dvb_evt_status.description = "Provide lock status on DVB interfaces";
	input_dvb_evt_status.data_reg = &evt_dvb_status_data;

	input_dvb_evt_status_reg = event_register(&input_dvb_evt_status);
	if (!input_dvb_evt_status_reg)
		return POM_ERR;

	return POM_OK;
}

static int input_dvb_unregister() {

	int res = POM_OK;
	if (input_dvb_evt_status_reg)
		res = event_unregister(input_dvb_evt_status_reg);

	input_dvb_evt_status_reg = NULL;
	return res;
}

static int input_dvb_docsis_scan_register() {

	static struct data_item_reg evt_docsis_scan_stream_data_items[INPUT_DVB_DOCSIS_STREAM_DATA_COUNT] = { { 0 } };
	evt_docsis_scan_stream_data_items[input_dvb_docsis_stream_frequency].name = "frequency";
	evt_docsis_scan_stream_data_items[input_dvb_docsis_stream_frequency].value_type = ptype_get_type("uint32");

	evt_docsis_scan_stream_data_items[input_dvb_docsis_stream_modulation].name = "modulation";
	evt_docsis_scan_stream_data_items[input_dvb_docsis_stream_modulation].value_type = ptype_get_type("string");

	evt_docsis_scan_stream_data_items[input_dvb_docsis_stream_chan_id].name = "channel_id";
	evt_docsis_scan_stream_data_items[input_dvb_docsis_stream_chan_id].value_type = ptype_get_type("uint8");

	evt_docsis_scan_stream_data_items[input_dvb_docsis_stream_pri_capable].name = "primary_capable";
	evt_docsis_scan_stream_data_items[input_dvb_docsis_stream_pri_capable].value_type = ptype_get_type("bool");

	evt_docsis_scan_stream_data_items[input_dvb_docsis_stream_chan_bonding].name = "channel_bonding";
	evt_docsis_scan_stream_data_items[input_dvb_docsis_stream_chan_bonding].value_type = ptype_get_type("bool");

	evt_docsis_scan_stream_data_items[input_dvb_docsis_stream_input_name].name = "input_name";
	evt_docsis_scan_stream_data_items[input_dvb_docsis_stream_input_name].value_type = ptype_get_type("string");

	static struct data_reg evt_docsis_scan_stream_data = {
		.items = evt_docsis_scan_stream_data_items,
		.data_count = INPUT_DVB_DOCSIS_STREAM_DATA_COUNT
	};

	static struct event_reg_info input_docsis_evt_stream = { 0 };
	input_docsis_evt_stream.source_name = "input_docsis_scan";
	input_docsis_evt_stream.name = "docsis_scan_stream";
	input_docsis_evt_stream.description = "Provide information about new stream found";
	input_docsis_evt_stream.data_reg = &evt_docsis_scan_stream_data;

	evt_docsis_scan_stream_reg = event_register(&input_docsis_evt_stream);
	if (!evt_docsis_scan_stream_reg)
		return POM_ERR;

	return POM_OK;
}

static int input_dvb_docsis_scan_unregister() {

	int res = POM_OK;
	if (evt_docsis_scan_stream_reg)
		res = event_unregister(evt_docsis_scan_stream_reg);

	evt_docsis_scan_stream_reg = NULL;
	return res;
}

static int input_dvb_common_init(struct input *i, enum input_dvb_type type) {

	struct registry_param *p = NULL;
	struct input_dvb_priv *priv = malloc(sizeof(struct input_dvb_priv));
	if (!priv) {
		pom_oom(sizeof(struct input_dvb_priv));
		return POM_ERR;
	}
	memset(priv, 0, sizeof(struct input_dvb_priv));

	i->priv = priv;

	priv->timer = timer_sys_alloc(i, input_dvb_timer_process);
	if (!priv->timer)
		return POM_ERR;

	priv->frontend_fd = -1;
	priv->demux_fd = -1;
	priv->dvr_fd = -1;
	priv->type = type;

	if (type != input_dvb_type_docsis && type != input_dvb_type_docsis_scan) {

		priv->link_proto = proto_get("mpeg_ts");
		if (!priv->link_proto) {
			pomlog(POMLOG_ERR "Cannot initialize input DVB : protocol mpeg_ts not registered");
			return POM_ERR;
		}

		priv->perf_null_discarded = registry_instance_add_perf(i->reg_instance, "null_discarded", registry_perf_type_counter, "Number of NULL MPEG packets discarded.", "pkts");
		if (!priv->perf_null_discarded)
			return POM_ERR;

		priv->filter_null_pid = ptype_alloc("bool");

		p = registry_new_param("filter_null_pid", "yes", priv->filter_null_pid, "Filter out the null MPEG PID (0x1FFF) as it usually contains no usefull data", REGISTRY_PARAM_FLAG_NOT_LOCKED_WHILE_RUNNING);
		if (input_add_param(i, p) != POM_OK) {
			registry_cleanup_param(p);
			return POM_ERR;
		}
	} else {
		priv->link_proto = proto_get("docsis");
		if (!priv->link_proto) {
			pomlog(POMLOG_ERR "Cannot initialize input docsis : protocol docsis not registered");
			return POM_ERR;
		}

	}

	if (type == input_dvb_type_device) {
		priv->frontend = ptype_alloc("string");
		if (!priv->frontend)
			return POM_ERR;

		p = registry_new_param("device", "/dev/dvb/adapterX/dvrY", priv->frontend, "Device to read packets from", 0);
		if (input_add_param(i, p) != POM_OK)
			return POM_ERR;

		return POM_OK;
	}


	priv->adapter = ptype_alloc("uint16");
	priv->frontend = ptype_alloc("uint16");
	priv->freq = ptype_alloc_unit("uint32", "Hz");
	priv->tuning_timeout = ptype_alloc_unit("uint16", "seconds");
	priv->buff_pkt_count = ptype_alloc_unit("uint16", "pkts");

	if (!priv->adapter || !priv->frontend || !priv->freq || !priv->tuning_timeout || !priv->buff_pkt_count)
		return POM_ERR;

	p = registry_new_param("adapter", "0", priv->adapter, "Adapter ID : /dev/dvb/adapterX", 0);
	if (input_add_param(i, p) != POM_OK)
		return POM_ERR;

	p = registry_new_param("frontend", "0", priv->frontend, "Frontend ID : /dev/dvb/adapterX/frontendY", 0);
	if (input_add_param(i, p) != POM_OK)
		return POM_ERR;

	p = registry_new_param("frequency", "0", priv->freq, "Frequency in Hz", 0);
	if (input_add_param(i, p) != POM_OK)
		return POM_ERR;

	p = registry_new_param("tuning_timeout", "3", priv->tuning_timeout, "Timeout while trying to tune in seconds", 0);
	if (input_add_param(i, p) != POM_OK)
		return POM_ERR;

	p = registry_new_param("buff_pkt_count", "10", priv->buff_pkt_count, "Number of MPEG packets to read at once", 0);
	if (input_add_param(i, p) != POM_OK)
		return POM_ERR;

	if (type == input_dvb_type_docsis_scan)
		return POM_OK;

	priv->perf_signal = registry_instance_add_perf(i->reg_instance, "signal", registry_perf_type_gauge, "Signal", "dB");
	priv->perf_snr = registry_instance_add_perf(i->reg_instance, "snr", registry_perf_type_gauge, "Signal to Noise ratio (SNR)", "dB");
	priv->perf_unc = registry_instance_add_perf(i->reg_instance, "unc", registry_perf_type_counter, "Uncorrected blocks", "blocks");
	priv->perf_ber = registry_instance_add_perf(i->reg_instance, "ber", registry_perf_type_gauge, "Bit error rate (BER)", "bits/block");
	if (!priv->perf_signal | !priv->perf_snr | !priv->perf_unc | !priv->perf_ber)
		return POM_ERR;

	registry_perf_set_update_hook(priv->perf_signal, input_dvb_perf_update_signal, priv);
	registry_perf_set_update_hook(priv->perf_snr, input_dvb_perf_update_snr, priv);
	registry_perf_set_update_hook(priv->perf_unc, input_dvb_perf_update_unc, priv);
	registry_perf_set_update_hook(priv->perf_ber, input_dvb_perf_update_ber, priv);


	if (type == input_dvb_type_c || type == input_dvb_type_s) {

		priv->symbol_rate = ptype_alloc_unit("uint32", "symbols/second");
		if (!priv->symbol_rate)
			return POM_ERR;

		p = registry_new_param("symbol_rate", "0", priv->symbol_rate, "Symbols per seconds", 0);
		if (input_add_param(i, p) != POM_OK)
			return POM_ERR;

	}

	if (type == input_dvb_type_c || type == input_dvb_type_atsc || type == input_dvb_type_docsis) {

		priv->modulation = ptype_alloc_unit("string", NULL);
		if (!priv->modulation)
			return POM_ERR;

		p = registry_new_param("modulation", "QAM256", priv->modulation, "Modulation either QAM64 or QAM256", 0);
		if (registry_param_info_add_value(p, "QAM256") != POM_OK || registry_param_info_add_value(p, "QAM64") != POM_OK)
			return POM_ERR;

		if (input_add_param(i, p) != POM_OK)
			return POM_ERR;
	}

	if (type == input_dvb_type_s) {
		priv->tpriv.s.polarity = ptype_alloc_unit("string", NULL);
		priv->tpriv.s.lnb_type = ptype_alloc_unit("string", NULL);
		if (!priv->tpriv.s.polarity || !priv->tpriv.s.lnb_type)
			return POM_ERR;

		p = registry_new_param("polarity", "h" , priv->tpriv.s.polarity, "Polarisation, either 'h' or 'v'", 0);
		if (input_add_param(i, p) != POM_OK)
			return POM_ERR;

		p = registry_new_param("lnb_type", "universal", priv->tpriv.s.lnb_type, "LNB type", 0);
		if (input_add_param(i, p) != POM_OK)
			return POM_ERR;

	}

	return POM_OK;


}


static int input_dvb_device_init(struct input *i) {

	return input_dvb_common_init(i, input_dvb_type_device);
}

static int input_dvb_c_init(struct input *i) {

	return input_dvb_common_init(i, input_dvb_type_c);
}

static int input_dvb_s_init(struct input *i) {

	return input_dvb_common_init(i, input_dvb_type_s);
}

static int input_dvb_atsc_init(struct input *i) {

	return input_dvb_common_init(i, input_dvb_type_atsc);
}

static int input_dvb_docsis_init(struct input *i) {

	return input_dvb_common_init(i, input_dvb_type_docsis);
}

static int input_dvb_docsis_scan_init(struct input *i) {

	if (input_dvb_common_init(i, input_dvb_type_docsis_scan) != POM_OK)
		return POM_ERR;

	struct input_dvb_priv *priv = i->priv;

	struct input_dvb_docsis_scan_priv *spriv = malloc(sizeof(struct input_dvb_docsis_scan_priv));
	if (!spriv) {
		pom_oom(sizeof(struct input_dvb_docsis_scan_priv));
		return POM_ERR;
	}
	memset(spriv, 0, sizeof(struct input_dvb_docsis_scan_priv));

	priv->tpriv.d.scan = spriv;


	struct registry_param *p = NULL;
	spriv->p_scan_qam64 = ptype_alloc("bool");
	spriv->p_complete_freq_scan = ptype_alloc("bool");
	spriv->p_add_input = ptype_alloc("bool");

	if (!spriv->p_scan_qam64 || !spriv->p_complete_freq_scan || !spriv->p_add_input)
		return POM_ERR;

	p = registry_new_param("scan_qam64", "no", spriv->p_scan_qam64, "Scan QAM64 streams in addition to QAM256", 0);
	if (input_add_param(i, p) != POM_OK)
		return POM_ERR;

	p = registry_new_param("scan_all_freq", "no", spriv->p_complete_freq_scan, "Scan all the frequencies, not just the one in the official frequency plan", 0);
	if (input_add_param(i, p) != POM_OK)
		return POM_ERR;

	p = registry_new_param("add_input", "yes", spriv->p_add_input, "Automatically add input for the discovered streams", 0);
	if (input_add_param(i, p) != POM_OK)
		return POM_ERR;

	return POM_OK;
}

static int input_dvb_device_open(struct input *i) {

	struct input_dvb_priv *priv = i->priv;

	char *device_name = PTYPE_STRING_GETVAL(priv->frontend);
	priv->dvr_fd = open(device_name, O_RDONLY);

	if (priv->dvr_fd == -1) {
		pomlog(POMLOG_ERR "Unable to open file %s : %s", device_name, pom_strerror(errno));
		return POM_ERR;
	}

	// FIXME make sure that the file open is a special device

	return POM_OK;
}

static int input_dvb_card_open(struct input_dvb_priv *priv) {

	char adapter[FILENAME_MAX];
	memset(adapter, 0, FILENAME_MAX);
	strcpy(adapter, "/dev/dvb/adapter");
	ptype_print_val(priv->adapter, adapter + strlen(adapter), FILENAME_MAX - strlen(adapter), NULL);

	char frontend[FILENAME_MAX];
	strcpy(frontend, adapter);
	strcat(frontend, "/frontend");
	ptype_print_val(priv->frontend, frontend + strlen(frontend), FILENAME_MAX - strlen(frontend), NULL);
	
	priv->frontend_fd = open(frontend, O_RDWR);
	if (priv->frontend_fd == -1) {
		pomlog(POMLOG_ERR "Unable to open frontend %s : %s", frontend, pom_strerror(errno));
		goto err;
	}

	// Check frontend type
	struct dvb_frontend_info info;
	if (ioctl(priv->frontend_fd, FE_GET_INFO, &info)) {
		pomlog(POMLOG_ERR "Unable to get frontend information from adapter %s : %s", adapter, pom_strerror(errno));
		goto err;
	}

	priv->fe_type = info.type;

	switch (priv->type) {

		case input_dvb_type_c:
			if (priv->fe_type != FE_QAM) {
				pomlog(POMLOG_ERR "The frontend %s is not a DVB-C adapter", frontend);
				goto err;
			}
			break;
		
		case input_dvb_type_s:
			if (priv->fe_type != FE_QPSK) {
				pomlog(POMLOG_ERR "The frontend %s is not a DVB-S adapter", frontend);
				goto err;
			}
			break;

		case input_dvb_type_atsc:
			if (priv->fe_type != FE_ATSC) {
				pomlog(POMLOG_ERR "The frontend %s is not a DVB-ATSC adapter", frontend);
				goto err;
			}

		case input_dvb_type_docsis:
			if (priv->fe_type != FE_QAM && priv->fe_type != FE_ATSC) {
				pomlog(POMLOG_ERR "The frontend %s is neither a DVB-C or an DVB-ATSC adapter", frontend);
				goto err;
			}

		default:
			break;
	}

	// Open the demux
	char demux[FILENAME_MAX];
	strcpy(demux, adapter);
	strcat(demux, "/demux0");

	priv->demux_fd = open(demux, O_RDWR);
	if (priv->demux_fd == -1) {
		pomlog(POMLOG_ERR "Unable to open demux device %s : %s", demux, strerror(errno));
		goto err;
	}

	// Increase buffer size in the kernel
	if (ioctl(priv->demux_fd, DMX_SET_BUFFER_SIZE, (unsigned long) DEMUX_BUFFER_SIZE) != 0) {
		pomlog(POMLOG_ERR "Unable to increase the demuxer buffer size : %s", pom_strerror(errno));
		goto err;
	}

	// Set the PID filter
	struct dmx_pes_filter_params filter;
	memset(&filter, 0, sizeof(struct dmx_pes_filter_params));

	if (priv->type == input_dvb_type_docsis) {
		filter.pid = INPUT_DVB_DOCSIS_PID;
	} else {
		filter.pid = PID_FULL_TS;
	}
	filter.input = DMX_IN_FRONTEND;
	filter.output = DMX_OUT_TS_TAP;
	filter.pes_type = DMX_PES_OTHER;
	filter.flags = DMX_IMMEDIATE_START;

	if (ioctl(priv->demux_fd, DMX_SET_PES_FILTER, &filter)) {
		pomlog(POMLOG_ERR "Unable to set demuxer %s filter's : %s", demux, pom_strerror(errno));
		goto err;
	}

	// Open the DVR device
	char dvr[FILENAME_MAX];
	strcpy(dvr, adapter);
	strcat(dvr, "/dvr0");

	if (priv->type == input_dvb_type_docsis_scan) {
		priv->tpriv.d.scan->dvr_dev = strdup(dvr);
		if (!priv->tpriv.d.scan->dvr_dev) {
			pom_oom(strlen(dvr) + 1);
			return POM_ERR;
		}
		return POM_OK;
	}

	// Queue the timer to check the lock
	timer_sys_queue(priv->timer, 2);

	priv->dvr_fd = open(dvr, O_RDONLY);
	if (priv->dvr_fd == -1) {
		pomlog(POMLOG_ERR "Unable to open DVR device : %s", pom_strerror(errno));
		goto err;
	}

	return POM_OK;

err:
	if (priv->frontend_fd != -1) {
		close(priv->frontend_fd);
		priv->frontend_fd = 1;
	}

	if (priv->demux_fd != -1) {
		close(priv->demux_fd);
		priv->demux_fd = -1;
	}

	if (priv->dvr_fd != -1) {
		close(priv->dvr_fd);
		priv->dvr_fd = -1;
	}

	return POM_ERR;
}

static int input_dvb_docsis_scan_open(struct input *i) {

	struct input_dvb_priv *priv = i->priv;

	// Allocate the buffer
	unsigned int pkt_count = *PTYPE_UINT16_GETVAL(priv->buff_pkt_count);
	priv->mpeg_buff = malloc(MPEG_TS_LEN * pkt_count);
	if (!priv->mpeg_buff)
		return POM_ERR;

	if (input_dvb_card_open(priv) != POM_OK)
		return POM_ERR;


	struct input_dvb_docsis_scan_priv *spriv = priv->tpriv.d.scan;

	if (priv->fe_type == FE_QAM) {
		spriv->freq_max = 858000000;
		spriv->freq_min = 106000000;
		spriv->freq_step = 8000000;
		spriv->freq_fast_start = 306000000;
	} else if (priv->fe_type == FE_ATSC) {
		spriv->freq_max = 999000000;
		spriv->freq_min = 57000000;
		spriv->freq_step = 6000000;
		spriv->freq_fast_start = 471000000;
	} else {
		pomlog(POMLOG_ERR "Frontend is not DVB-C or ASTC/QAM.");
		return POM_ERR;
	}


	struct dvb_frontend_info fe_info = { { 0 } };
	if (ioctl(priv->frontend_fd, FE_GET_INFO, &fe_info)) {
		pomlog(POMLOG_ERR "Error while querying frontend info : %s");
		return POM_ERR;
	}

	if (fe_info.frequency_min > spriv->freq_min) {
		spriv->freq_min = fe_info.frequency_min;
		spriv->freq_min += spriv->freq_step - (spriv->freq_min % spriv->freq_step);
	}
	if (fe_info.frequency_max < spriv->freq_max) {
		spriv->freq_max = fe_info.frequency_max;
		spriv->freq_max -= spriv->freq_max % spriv->freq_step;
	}

	spriv->cur_freq = spriv->freq_fast_start;
	spriv->cur_step = spriv->freq_step;
	spriv->cur_mod = QAM_256;
	spriv->input_id = 0;

	return POM_OK;
}

static int input_dvb_open(struct input *i) {

	struct input_dvb_priv *priv = i->priv;

	// Allocate the buffer
	unsigned int pkt_count = *PTYPE_UINT16_GETVAL(priv->buff_pkt_count);
	priv->mpeg_buff = malloc(MPEG_TS_LEN * pkt_count);
	if (!priv->mpeg_buff)
		return POM_ERR;

	if (input_dvb_card_open(priv) != POM_OK)
		goto err;

	// Do the tuning
	
	fe_modulation_t modulation = 0;

	uint32_t frequency = *PTYPE_UINT32_GETVAL(priv->freq);
	uint32_t tuning_frequency = frequency;
	uint32_t symbol_rate = 0;

	if (priv->type == input_dvb_type_c || priv->type == input_dvb_type_atsc || priv->type == input_dvb_type_docsis) {

		char *mod_str = PTYPE_STRING_GETVAL(priv->modulation);
		if (!strcmp(mod_str, "QAM64"))
			modulation = QAM_64;
		else if (!strcmp(mod_str, "QAM256"))
			modulation = QAM_256;
		else {
			pomlog(POMLOG_ERR "Invalid modulation \"%s\"", mod_str);
			goto err;
		}
	}

	if (priv->type == input_dvb_type_c) {

		symbol_rate = *PTYPE_UINT32_GETVAL(priv->symbol_rate);

	} else if (priv->type == input_dvb_type_s) {
		
		char *polarity = PTYPE_STRING_GETVAL(priv->tpriv.s.polarity);
		fe_sec_voltage_t voltage;
		if (!strcasecmp(polarity, "h")) {
			voltage = SEC_VOLTAGE_18;
		} else if (!strcasecmp(polarity, "v")) {
			voltage = SEC_VOLTAGE_13;
		} else {
			pomlog(POMLOG_ERR "Invalid polarity \"%s\". Valid values are 'h' or 'v'.", polarity);
			goto err;
		}
		
		int lnb_id;
		char *lnb_type = PTYPE_STRING_GETVAL(priv->tpriv.s.lnb_type);
		for (lnb_id = 0; lnb_id < LNB_COUNT && strcmp(input_dvb_lnbs[lnb_id].name, lnb_type); lnb_id++);
		if (lnb_id >= LNB_COUNT) {
			pomlog(POMLOG_ERR "LNB of type \"%s\" unknown", lnb_type);
			goto err;
		}

		if (frequency < input_dvb_lnbs[lnb_id].min_freq || frequency > input_dvb_lnbs[lnb_id].max_freq) {
			pomlog(POMLOG_ERR "Provided frequency outside LNB supported range : provided %u, range %u..%u", frequency, input_dvb_lnbs[lnb_id].min_freq, input_dvb_lnbs[lnb_id].max_freq);
			goto err;
		}

		// Calulate intermediate frequency
		
		fe_sec_tone_mode_t tone = SEC_TONE_OFF;

		if (frequency > input_dvb_lnbs[lnb_id].switch_val) {
			tone = SEC_TONE_ON;
			tuning_frequency = frequency - input_dvb_lnbs[lnb_id].high_val;
		} else {
			if (frequency < input_dvb_lnbs[lnb_id].low_val)
				tuning_frequency = input_dvb_lnbs[lnb_id].low_val - frequency;
			else
				tuning_frequency = frequency - input_dvb_lnbs[lnb_id].low_val;
		}

		if (ioctl(priv->frontend_fd, FE_SET_VOLTAGE, voltage)) {
			pomlog(POMLOG_ERR "Error while setting voltage : %s", pom_strerror(errno));
			goto err;
		}

		if (ioctl(priv->frontend_fd, FE_SET_TONE, tone)) {
			pomlog(POMLOG_ERR "Error while setting tone : %s", pom_strerror(errno));
			goto err;
		}

		symbol_rate = *PTYPE_UINT32_GETVAL(priv->symbol_rate);
	} else if (priv->type == input_dvb_type_docsis) {
		if (priv->fe_type == FE_QAM)
			symbol_rate = 6952000;
		// FE_ATSC doesn't need a symbol rate

		// Invalid sequence that needs initialization
		priv->tpriv.d.mpeg_seq = 0xFF;
	}

	int res = input_dvb_tune(priv, tuning_frequency, symbol_rate, modulation);
	if (res != 1) {
		pomlog("Lock not acquired on frequency %u Hz", frequency);
		goto err;
	}

	return POM_OK;

err:

	if (priv->mpeg_buff)
		free(priv->mpeg_buff);

	return POM_ERR;
}

// Return -1 on fatal error, 0 if not tuned, 1 if tuned
static int input_dvb_tune(struct input_dvb_priv *p, uint32_t frequency, uint32_t symbol_rate, fe_modulation_t modulation) {

	fe_status_t status = 0, last_status = 0;
	struct dvb_frontend_parameters frp;
	struct pollfd pfd[1];

	memset(&frp, 0, sizeof(struct dvb_frontend_parameters));
	frp.frequency = frequency;
	frp.inversion = INVERSION_AUTO;

	switch (p->fe_type) {

		case FE_QAM:
			frp.u.qam.symbol_rate = symbol_rate;
			frp.u.qam.fec_inner = FEC_AUTO;
			frp.u.qam.modulation = modulation;
			break;

		case FE_QPSK:
			frp.u.qpsk.symbol_rate = symbol_rate;
			frp.u.qpsk.fec_inner = FEC_AUTO;
			break;

		case FE_ATSC:
			frp.u.vsb.modulation = modulation;
			break;

		default:
			return -1;

	}

	// Let's do some tuning

	if (ioctl(p->frontend_fd, FE_SET_FRONTEND, &frp) < 0){
		pomlog(POMLOG_ERR "Error while setting tuning parameters : %s", pom_strerror(errno));
		return -1;
	}


	pfd[0].fd = p->frontend_fd;
	pfd[0].events = POLLIN;

	struct timeval now;
	gettimeofday(&now, NULL);
	uint16_t *tuning_timeout = PTYPE_UINT16_GETVAL(p->tuning_timeout);
	time_t timeout = now.tv_sec + *tuning_timeout;

	while (now.tv_sec < timeout) {
		if (poll(pfd, 1, 1000)){
			if (pfd[0].revents & POLLIN) {
				if (ioctl(p->frontend_fd, FE_READ_STATUS, &status)) {
					pomlog(POMLOG_WARN "IOCTL failed while getting status of the DVB adapter");
					return -1; 
				}
				
				if (status & FE_TIMEDOUT) {
					pomlog(POMLOG_WARN "Timeout while tuning");
					return 0;
				}
				if (status & FE_REINIT) {
					pomlog(POMLOG_WARN "Frontend was reinit");
					return 0;
				}

				// Avoid repeating the status if it's always the same
				if (status == last_status)
					continue;

				char status_str[128];
				memset(status_str, 0, sizeof(status_str));
				if (status) {
					strcat(status_str, "Status : " );
					last_status = status;
				}

				if (status & FE_HAS_SIGNAL)
					strcat(status_str, "SIGNAL ");
				if (status & FE_HAS_CARRIER)
					strcat(status_str, "CARRIER ");
				if (status & FE_HAS_VITERBI)
					strcat(status_str, "VITERBI ");
				if (status & FE_HAS_SYNC)
					strcat(status_str, "VSYNC ");
				if (status & FE_HAS_LOCK)
					strcat(status_str, "LOCK ");
				if (status)
					pomlog(POMLOG_DEBUG "%s", status_str);

				if (status & FE_HAS_LOCK) {
					return 1;
				}
			} 
		} 
		gettimeofday(&now, NULL);
	}

	return 0;
}

static int input_dvb_read(struct input *i) {

	struct input_dvb_priv *p = i->priv;

	ssize_t len = 0, r = 0;

	unsigned int pkt_count = *PTYPE_UINT16_GETVAL(p->buff_pkt_count);
	unsigned char *buff = p->mpeg_buff;
	size_t buff_size = MPEG_TS_LEN * pkt_count;

	char filter_null_pid = *PTYPE_BOOL_GETVAL(p->filter_null_pid);

	// Read a few packets at a time
	do {

		r = read(p->dvr_fd, buff + len, buff_size - len);
		if (r < 0) {
			if (errno == EOVERFLOW) {
				pomlog(POMLOG_DEBUG "Overflow in the kernel buffer while reading packets. Lots of packets were missed");
				len = 0;
				r = 0;
				continue;
			} else if (errno == EINTR) {
				pomlog(POMLOG_DEBUG "Read interrupted by signal");
				return POM_ERR;
			}
			pomlog(POMLOG_ERR "Error while reading dvr : %s", pom_strerror(errno));
		} else if (r == 0) {
			// EOF
			return POM_ERR;
		}
		len += r;


	} while (len < buff_size);



	ptime now = pom_gettimeofday();

	int j;
	for (j = 0; j < pkt_count; j++) {

		unsigned char *pload = buff + (j * MPEG_TS_LEN);

		// Check sync byte
		if (pload[0] != 0x47) {
			pomlog(POMLOG_ERR "Error, stream out of sync !");
			return POM_ERR;
		}

		uint16_t pid = ((pload[1] & 0x1F) << 8) | pload[2];
		if (filter_null_pid && pid == 0x1FFF) { // 0x1FFF is the NULL PID
			registry_perf_inc(p->perf_null_discarded, 1);
			continue;
		}


		// Get a new place holder for our packet
		struct packet *pkt = packet_alloc();

		if (!pkt)
			return POM_ERR;

		if (packet_buffer_alloc(pkt, MPEG_TS_LEN, 0) != POM_OK) {
			packet_release(pkt);
			return POM_ERR;
		}

		pkt->input = i;
		pkt->datalink = p->link_proto;
		pkt->ts = now + j;

		memcpy(pkt->buff, pload, MPEG_TS_LEN);


		if (core_queue_packet(pkt, CORE_QUEUE_HAS_THREAD_AFFINITY | CORE_QUEUE_DROP_IF_FULL, pid) != POM_OK)
			return POM_ERR;

	}

	return POM_OK;

}

static int input_dvb_docsis_scan_read(struct input *i) {

	struct input_dvb_priv *p = i->priv;

	struct input_dvb_docsis_scan_priv *spriv = p->tpriv.d.scan;

	uint32_t cur_freq = spriv->cur_freq;
	fe_modulation_t cur_mod = spriv->cur_mod;

	// Calculate next frequency
	spriv->cur_freq += spriv->cur_step;

	// Check if we were before our fast scan
	if (spriv->cur_step == spriv->freq_step) {
		// We are currently scanning the official frequency plan

		if (spriv->cur_freq >= spriv->freq_max) {
			// We started at the "fast scan freq start", restart from the lower freq
			spriv->cur_freq = spriv->freq_min;
		} else if (cur_freq < spriv->freq_fast_start && spriv->cur_freq >= spriv->freq_fast_start) {
			// We scanned from the lower freq up to the "fast scan freq start"
			if (*PTYPE_BOOL_GETVAL(spriv->p_complete_freq_scan)) {
				// The user wants a complete frequency scan
				// Restart with a smaller step and from the min freq
				spriv->cur_step = 1000000;
				spriv->cur_freq = spriv->freq_min;
			} else if (spriv->cur_mod == QAM_256) {
				if (*PTYPE_BOOL_GETVAL(spriv->p_scan_qam64)) {
					// The user wants to scan QAM64
					// Restart at the fast scan freq
					spriv->cur_step = spriv->freq_step;
					spriv->cur_freq = spriv->freq_fast_start;
					spriv->cur_mod = QAM_64;
				} else {
					pomlog(POMLOG_INFO "Fast frequency scan (QAM256 only) completed");
					input_stop(i);
					return POM_OK;
				}
			} else {
				pomlog(POMLOG_INFO "Fast frequency scan (QAM256 and QAM64) completed");
				input_stop(i);
				return POM_OK;
			}
		}
	} else {
		// We are doing a complete scan

		// Skip freq that we already scanned in the fast scan
		if (!((spriv->freq_max - spriv->cur_freq) % spriv->freq_step))
			spriv->cur_freq += spriv->cur_step;

		if (spriv->cur_freq >= spriv->freq_max) {

			if (spriv->cur_mod == QAM_256) {
				if (*PTYPE_BOOL_GETVAL(spriv->p_scan_qam64)) {
					// The user wants to scan QAM64
					// Restart from the fast scan freq
					spriv->cur_step = spriv->freq_step;
					spriv->cur_freq = spriv->freq_fast_start;
					spriv->cur_mod = QAM_64;
				} else {
					pomlog(POMLOG_INFO "Complete frequency scan (QAM256 only) completed");
					input_stop(i);
					return POM_OK;
				}
			} else {
				pomlog(POMLOG_INFO "Complete frequency scan (QAM256 and QAM64) scan completed");
				input_stop(i);
				return POM_OK;
			}
		}
	}

	pomlog(POMLOG_INFO "Scanning frequency %uHz on QAM%s ...", cur_freq, (cur_mod == QAM_256 ? "256" : "64"));
	// US DOCSIS will not use the symbol rate
	int res = input_dvb_tune(p, cur_freq, INPUT_DVB_DOCSIS_EURO_SYMBOLRATE, cur_mod);

	if (res == -1) {
		// Something went wrong
		pomlog(POMLOG_ERR "Error while tuning");
		return POM_ERR;
	}

	if (!res) {
		pomlog(POMLOG_DEBUG "Tuning failed on %uHz", cur_freq);
		return POM_OK;
	}

	spriv->sync_count = 0;
	spriv->mdd_found = 0;
	p->tpriv.d.mpeg_seq = 0xFF; // Invalid sequence that needs initialization

	// We need to open and close the DVR device for each TP in order to flush the buffer from the previous TP
	p->dvr_fd = open(p->tpriv.d.scan->dvr_dev, O_RDONLY);
	if (p->dvr_fd == -1) {
		pomlog(POMLOG_ERR "Error while opening the DVR device : %s", pom_strerror(errno));
		return POM_ERR;
	}

	timer_sys_queue(p->timer, 3);
	while (spriv->sync_count < 10 && spriv->sync_count >= 0) {
		res = input_dvb_docsis_read(i);
		if (res == POM_ERR) {
			spriv->sync_count = -1;
			break;
		}
	}
	timer_sys_dequeue(p->timer);

	if (spriv->sync_count >= 10) {

		if (!spriv->mdd_found) {
			// Give it 30 more sec to find an mdd
			timer_sys_queue(p->timer, 30);
			while (!spriv->mdd_found) {
				res = input_dvb_docsis_read(i);
				if (res == POM_ERR)
					break;
			}

			timer_sys_dequeue(p->timer);
		}


		if (!spriv->mdd_found) {
			// No MDD was found, this means we have a DOCSIS 2 stream

			// Check if a channel with this freq is already known
			struct input_dvb_docsis_scan_priv_stream *s;
			for (s = spriv->streams; s && s->freq != cur_freq; s = s->next);

			if (!s) {
				s = malloc(sizeof(struct input_dvb_docsis_scan_priv_stream));
				if (!s) {
					pom_oom(sizeof(struct input_dvb_docsis_scan_priv_stream));
					return POM_ERR;
				}
				memset(s, 0, sizeof(struct input_dvb_docsis_scan_priv_stream));
				s->freq = cur_freq;
				s->modulation = cur_mod;
				s->chan_bonding = 0;

				s->next = spriv->streams;
				spriv->streams = s;

				if (input_dvb_docsis_process_new_stream(i, s) != POM_OK)
					return POM_ERR;
			}
		}
	} else {
		pomlog(POMLOG_DEBUG "No DOCSIS stream found on %uHz", cur_freq);
	}

	close(p->dvr_fd);
	p->dvr_fd = -1;

	p->tpriv.d.docsis_buff_len = 0;
	if (p->tpriv.d.pkt) {
		packet_release(p->tpriv.d.pkt);
		p->tpriv.d.pkt = NULL;
	}

	return POM_OK;
}

static int input_dvb_docsis_read(struct input *i) {

	struct input_dvb_priv *p = i->priv;

	ssize_t len = 0, r = 0;

	unsigned int pkt_count = *PTYPE_UINT16_GETVAL(p->buff_pkt_count);
	unsigned char *buff = p->mpeg_buff;
	size_t buff_size = MPEG_TS_LEN * pkt_count;

	// Read a few packets at a time
	do {

		r = read(p->dvr_fd, buff + len, buff_size - len);
		if (r < 0) {
			if (errno == EOVERFLOW) {
				pomlog(POMLOG_DEBUG "Overflow in the kernel buffer while reading packets. Lots of packets were missed");
				len = 0;
				r = 0;
				continue;
			} else if (errno == EINTR) {
				pomlog(POMLOG_DEBUG "Read interrupted by signal");
				return POM_ERR;
			}
			pomlog(POMLOG_ERR "Error while reading dvr : %s", pom_strerror(errno));
		} else if (r == 0) {
			// EOF
			return POM_ERR;
		}
		len += r;


	} while (len < buff_size);

	int j;
	for (j = 0; j < pkt_count; j++) {
		if (input_dvb_docsis_process_mpeg_packet(i, buff + (j * MPEG_TS_LEN)) != POM_OK)
			return POM_ERR;

	}


	return POM_OK;
}

static int input_dvb_docsis_process_new_stream(struct input *i, struct input_dvb_docsis_scan_priv_stream *s) {

	if (s->chan_bonding) {
		if (s->pri_capable) {
			pomlog(POMLOG_INFO "Got new DOCSIS 3 stream : %uHz, QAM %u, Primary capable", s->freq, (s->modulation == QAM_256 ? 256 : 64));
		} else {
			pomlog(POMLOG_INFO "Got new DOCSIS 3 stream : %uHz, QAM %u", s->freq, (s->modulation == QAM_256 ? 256 : 64));
		}
	} else {
		pomlog(POMLOG_INFO "Got new pre-DOCSIS 3 stream : %uHz, QAM %u", s->freq, (s->modulation == QAM_256 ? 256 : 64));
	}

	struct input_dvb_priv *p = i->priv;
	struct input_dvb_docsis_scan_priv *spriv = p->tpriv.d.scan;

	if (event_has_listener(evt_docsis_scan_stream_reg)) {
		struct event *evt = event_alloc(evt_docsis_scan_stream_reg);
		if (evt) {
			struct data *evt_data = event_get_data(evt);
			PTYPE_UINT32_SETVAL(evt_data[input_dvb_docsis_stream_frequency].value, s->freq);
			data_set(evt_data[input_dvb_docsis_stream_frequency]);

			PTYPE_STRING_SETVAL(evt_data[input_dvb_docsis_stream_modulation].value, (s->modulation == QAM_256 ? "QAM256" : "QAM64"));
			data_set(evt_data[input_dvb_docsis_stream_modulation]);


			PTYPE_BOOL_SETVAL(evt_data[input_dvb_docsis_stream_chan_bonding].value, s->chan_bonding);
			data_set(evt_data[input_dvb_docsis_stream_chan_bonding]);

			if (s->chan_bonding) {
				PTYPE_UINT8_SETVAL(evt_data[input_dvb_docsis_stream_chan_id].value, s->chan_id);
				data_set(evt_data[input_dvb_docsis_stream_chan_id]);

				PTYPE_BOOL_SETVAL(evt_data[input_dvb_docsis_stream_pri_capable].value, s->pri_capable);
				data_set(evt_data[input_dvb_docsis_stream_pri_capable]);
			}

			PTYPE_STRING_SETVAL(evt_data[input_dvb_docsis_stream_input_name].value, i->name);
			data_set(evt_data[input_dvb_docsis_stream_input_name]);

			event_process(evt, NULL, 0, pom_gettimeofday());
		}
	}

	if (*PTYPE_BOOL_GETVAL(spriv->p_add_input)) {
		char buff[24];
		snprintf(buff, sizeof(buff), "docsis_ch%hhu_%umhz", s->chan_id, s->freq / 1000000);

		struct registry_instance *inst = registry_create_instance("input", "docsis", buff);

		if (!inst)
			return POM_ERR;

		snprintf(buff, sizeof(buff), "%u", s->freq);
		registry_set_param(inst, "frequency", buff);

		registry_set_param(inst, "modulation", (s->modulation == QAM_256 ? "QAM256" : "QAM64"));

		snprintf(buff, sizeof(buff), "%u", spriv->input_id);
		registry_set_param(inst, "adapter", buff);
		spriv->input_id++;

	}


	return POM_OK;
}

static int input_dvb_docsis_process_docsis_mdd(struct input *i,unsigned char *buff, size_t len) {

	struct input_dvb_priv *p = i->priv;
	if (len < 4)
		return POM_ERR;

	// Skip MDD header
	buff += 4;
	len -= 4;

	while (len > 2) {
		uint8_t tlvlen = buff[1];
		switch (buff[0]) {
			case 1: { // Downstream Channel List
				if (len < 4) // 4 = 1 tvl, 1 len 1, 1 subtlv, 1 subtlv len
					return POM_OK;

				struct input_dvb_docsis_scan_priv_stream *s = malloc(sizeof(struct input_dvb_docsis_scan_priv_stream));
				if (!s) {
					pom_oom(sizeof(struct input_dvb_docsis_scan_priv_stream));
					return POM_ERR;
				}
				memset(s, 0, sizeof(struct input_dvb_docsis_scan_priv_stream));
				s->chan_bonding = 1;

				buff += 2;
				len -= tlvlen + 2;
				while (tlvlen > 2) {
					// Sub TLVS
					uint8_t subtlvlen = buff[1];
					if (tlvlen < subtlvlen + 1) {
						free(s);
						return POM_OK;
					}

					uint8_t realsublen = 0;
					switch (buff[0]) {
						case 1:
							s->chan_id = buff[2];
							realsublen = sizeof(uint8_t);
							break;
						case 2: { // Frequency
							if (subtlvlen < sizeof(uint32_t))
								return POM_OK;
							uint32_t val;
							memcpy(&val, buff + 2, sizeof(val));
							s->freq = ntohl(val);
							realsublen = sizeof(uint32_t);
							break;
						}

						case 3:
							if ((buff[2] & 0xF) == 0)
								s->modulation = QAM_64;
							else if ((buff[2] & 0xF) == 1)
								s->modulation = QAM_256;
							realsublen = sizeof(uint8_t);
							break;
						case 4:
							s->pri_capable = buff[2];
							realsublen = sizeof(uint8_t);
							break;
						default:
							realsublen = subtlvlen;
							break;
					}

					if (realsublen != subtlvlen) {
						free(s);
						return POM_OK;
					}

					tlvlen -= subtlvlen + 2;
					buff += subtlvlen + 2;
				}

				len -= tlvlen + 2;


				// Check the result
				if (s->freq == 0 || s->modulation == 0 || s->chan_id == 0) {
					free(s);
					continue;
				}

				struct input_dvb_docsis_scan_priv *spriv = p->tpriv.d.scan;
				struct input_dvb_docsis_scan_priv_stream *tmp;
				for (tmp = spriv->streams; tmp && tmp->chan_id != s->chan_id; tmp = tmp->next);
				if (tmp) {
					free(s);
					continue;
				}

				s->next = spriv->streams;
				spriv->streams = s;

				input_dvb_docsis_process_new_stream(i, s);
				break;
			}

			default:
				len -= tlvlen + 2;
				buff += tlvlen + 2;
				break;
		}
	}

	return POM_OK;
}

static int input_dvb_docsis_process_docsis_packet(struct input *i) {

	struct input_dvb_priv *p = i->priv;

	if (p->type == input_dvb_type_docsis) {
		struct packet *pkt = p->tpriv.d.pkt;
		if (!pkt)
			return POM_ERR;
		p->tpriv.d.pkt = NULL;
		p->tpriv.d.pkt_pos = 0;
		return core_queue_packet(pkt, 0, 0);
	}

	if (p->type != input_dvb_type_docsis_scan)
		return POM_ERR;

	struct input_dvb_docsis_scan_priv *spriv = p->tpriv.d.scan;

	// At this point we are either looking for SYNC messages or MDD messages
	unsigned char *buffer = p->tpriv.d.pkt->buff;
	size_t len = p->tpriv.d.pkt->len;

	if (len < 26)
		goto done;

	// Some things are common for both

	if (
		(buffer[1] != 0) ||  // MAC_PARM = 0
		(buffer[20] != 0) || // DSAP = 0
		(buffer[20] != 0) || // SSAP = 0
		(buffer[22] != 0x3)  // Control = unumbered info
	)
		goto done;

	if (
		(buffer[0] == 0xC0) && // FC_TYPE = 11, FC_PARM = 0, EHDR_ON = 0 -> FC = 0xC0
		(buffer[23] == 0x1) && // Version = 1
		(buffer[24] == 0x1)    // Type = 1 (SYNC msg)
	) {
		// SYNC message
		spriv->sync_count++;
	} else if (
		(buffer[0] == 0xC2) && // FC_TYPE=11, FC_PARM = 1, EHDR_ON = 0 -> FC = 0xC2
		(buffer[23] == 4) &&   // Version = 4
		(buffer[24] == 33)     // Type = 33
	) {
		// MDD message
		if (input_dvb_docsis_process_docsis_mdd(i, buffer + 26, p->tpriv.d.pkt->len - 26) == POM_OK)
			spriv->mdd_found = 1;
	}

done:
	packet_release(p->tpriv.d.pkt);
	p->tpriv.d.pkt = NULL;
	p->tpriv.d.pkt_pos = 0;

	return POM_OK;
}

static int input_dvb_docsis_process_mpeg_packet(struct input *i, unsigned char *buff) {

	struct input_dvb_priv *p = i->priv;

	// Check sync byte
	if (buff[0] != 0x47) {
		pomlog(POMLOG_ERR "Error, stream out of sync !");
		return POM_ERR;
	}

	uint16_t pid = ((buff[1] & 0x1F) << 8) | buff[2];
	if (pid != INPUT_DVB_DOCSIS_PID)
		return POM_OK; // Should not happen unless the filtering on the dvb interface doesn't work

	unsigned char pusi = buff[1] & 0x40;
	unsigned char afc = (buff[3] & 0x30) >> 4; // Adaptation field control
	unsigned char tsc = (buff[3] & 0xC0) >> 6; // Transport scrambling control
	uint8_t mpeg_seq = buff[3] & 0xF; // MPEG continuity counter

	unsigned char *pload = buff + 4;
	unsigned int plen = MPEG_TS_LEN - 4;

	unsigned char pusi_ptr = *pload;

	if (!(afc & 0x1)) // There should be a payload in the packet
		return POM_OK;

	if (p->tpriv.d.mpeg_seq > 0xF) {
		// Init the sequence
		p->tpriv.d.mpeg_seq = mpeg_seq;
	} else {
		p->tpriv.d.mpeg_seq = (p->tpriv.d.mpeg_seq + 1) & 0xF;

		if (p->tpriv.d.mpeg_seq != mpeg_seq) {
			// We missed some packets

			// Lame way to compute the missed packets
			int missed = 0;
			while (p->tpriv.d.mpeg_seq != mpeg_seq) {
				p->tpriv.d.mpeg_seq = (p->tpriv.d.mpeg_seq + 1) & 0xF;
				missed++;
			}

			pomlog(POMLOG_DEBUG "Missed %u MPEG packet(s) on input %s", missed, i->name);

			if (p->tpriv.d.docsis_buff_len) {
				// We had at most 3 bytes of a packet, discard them
				p->tpriv.d.docsis_buff_len = 0;
			} else if (p->tpriv.d.pkt) {
				// We have the begining of a packet try to fill whatever was missed into it
				int missed_len = missed * (MPEG_TS_LEN - 4);
				int remaining_len = p->tpriv.d.pkt->len - p->tpriv.d.pkt_pos;
				if (missed_len > remaining_len)
					missed_len = remaining_len;

				memset(p->tpriv.d.pkt->buff + p->tpriv.d.pkt_pos, 0xFF, remaining_len);
				p->tpriv.d.pkt_pos += remaining_len;

				if (p->tpriv.d.pkt_pos >= p->tpriv.d.pkt->len) {
					// process the packet
					if (input_dvb_docsis_process_docsis_packet(i) != POM_OK)
						return POM_ERR;
				}
			}
		}
	}

	if (tsc || afc != 0x1)
		return POM_OK; // DOCSIS packets are not encrypted on mpeg level and there should not be an adaptation field

	if (pusi) { // Skip the pusi_ptr
		if (pusi_ptr > MPEG_TS_LEN - 5)
			return POM_OK; // Invalid packet

		pload++;
		plen--;
	}

	if (p->tpriv.d.docsis_buff_len) {
		// Start previously too short packet
		if (plen < 4 - p->tpriv.d.docsis_buff_len) // This should not happend
			return POM_ERR;
		memcpy(p->tpriv.d.docsis_buff + p->tpriv.d.docsis_buff_len, pload, 4 - p->tpriv.d.docsis_buff_len);

		struct docsis_hdr *hdr = (struct docsis_hdr*)p->tpriv.d.docsis_buff;
		size_t hdr_len = sizeof(struct docsis_hdr) + hdr->mac_parm;
		unsigned char *tmplen = (unsigned char*)&hdr->len;
		size_t pkt_len = ((tmplen[0] << 8) + tmplen[1]) + sizeof(struct docsis_hdr);

		p->tpriv.d.pkt = packet_alloc();
		if (!p->tpriv.d.pkt)
			return POM_ERR;

		if (packet_buffer_alloc(p->tpriv.d.pkt, pkt_len, ((hdr_len & 3) ? 0 : 2)) != POM_OK) {
			packet_release(p->tpriv.d.pkt);
			p->tpriv.d.pkt = NULL;
			return POM_ERR;
		}

		p->tpriv.d.pkt->input = i;
		p->tpriv.d.pkt->datalink = p->link_proto;
		p->tpriv.d.pkt->ts = pom_gettimeofday();

		// Copy the begining of the packet
		memcpy(p->tpriv.d.pkt->buff, p->tpriv.d.docsis_buff, p->tpriv.d.docsis_buff_len);
		p->tpriv.d.pkt_pos = p->tpriv.d.docsis_buff_len;
		p->tpriv.d.docsis_buff_len = 0;

	}


	if (pusi) {

		if (p->tpriv.d.pkt) {
			// Fill the remaining
			if (pusi_ptr != p->tpriv.d.pkt->len - p->tpriv.d.pkt_pos) {
				pomlog(POMLOG_DEBUG "Invalid tail length for DOCSIS packet : expected %u, got %hhu", p->tpriv.d.pkt->len - p->tpriv.d.pkt_pos, pusi_ptr);
				packet_release(p->tpriv.d.pkt);
				p->tpriv.d.pkt = NULL;
			} else {
				memcpy(p->tpriv.d.pkt->buff + p->tpriv.d.pkt_pos, pload, pusi_ptr);

				// process the packet
				if (input_dvb_docsis_process_docsis_packet(i) != POM_OK)
					return POM_ERR;
			}
		}

		pload += pusi_ptr;
		plen -= pusi_ptr;


	} else if (p->tpriv.d.pkt) {
		// Fill an ongoing packet
		size_t remaining = p->tpriv.d.pkt->len - p->tpriv.d.pkt_pos;
		if (remaining > plen)
			remaining = plen;

		memcpy(p->tpriv.d.pkt->buff + p->tpriv.d.pkt_pos, pload, remaining);
		p->tpriv.d.pkt_pos += remaining;

		pload += remaining;
		plen -= remaining;

		if (p->tpriv.d.pkt_pos >= p->tpriv.d.pkt->len) {
			// process the packet
			if (input_dvb_docsis_process_docsis_packet(i) != POM_OK)
				return POM_ERR;
		}

	} else {
		// Nothing to do as there is no packet currently being processed and no begining of packets
		return POM_OK;
	}

	while (plen) {

		if (*pload == 0xFF) {
			pload++;
			plen--;
			continue;
		}

		if (!p->tpriv.d.pkt) {

			if (plen < 4) {
				// It's a new packet but not enough data, buffer it
				memcpy(p->tpriv.d.docsis_buff, pload, plen);
				p->tpriv.d.docsis_buff_len = plen;
				break;
			}

			struct docsis_hdr *hdr = (struct docsis_hdr*)pload;
			size_t hdr_len = sizeof(struct docsis_hdr) + hdr->mac_parm;
			unsigned char *tmplen = (unsigned char*)&hdr->len;
			size_t pkt_len = ((tmplen[0] << 8) + tmplen[1]) + sizeof(struct docsis_hdr);

			p->tpriv.d.pkt = packet_alloc();
			if (!p->tpriv.d.pkt)
				return POM_ERR;

			if (packet_buffer_alloc(p->tpriv.d.pkt, pkt_len, ((hdr_len & 3) ? 0 : 2)) != POM_OK) {
				packet_release(p->tpriv.d.pkt);
				p->tpriv.d.pkt = NULL;
				return POM_ERR;
			}

			p->tpriv.d.pkt_pos = 0;
			p->tpriv.d.pkt->input = i;
			p->tpriv.d.pkt->datalink = p->link_proto;
			p->tpriv.d.pkt->ts = pom_gettimeofday();
		}

		// Copy stuff to the packet
		size_t remaining_len = p->tpriv.d.pkt->len - p->tpriv.d.pkt_pos;
		if (remaining_len > plen)
			remaining_len = plen;

		memcpy(p->tpriv.d.pkt->buff + p->tpriv.d.pkt_pos, pload, remaining_len);
		p->tpriv.d.pkt_pos += remaining_len;
		pload += remaining_len;
		plen -= remaining_len;

		if (p->tpriv.d.pkt_pos >= p->tpriv.d.pkt->len) {
			// process the packet
			if (input_dvb_docsis_process_docsis_packet(i) != POM_OK)
				return POM_ERR;
		}
	}

	return POM_OK;

}


static void input_dvb_card_close(struct input_dvb_priv *p) {

	if (p->frontend_fd != -1) {
		close(p->frontend_fd);
		p->frontend_fd = -1;
	}

	if (p->demux_fd != -1) {
		close(p->demux_fd);
		p->demux_fd = -1;
	}

	if (p->dvr_fd != -1) {
		close(p->dvr_fd);
		p->dvr_fd = -1;
	}

	timer_sys_dequeue(p->timer);
}

static int input_dvb_close(struct input *i) {

	struct input_dvb_priv *p = i->priv;

	if (p->mpeg_buff)
		free(p->mpeg_buff);

	input_dvb_card_close(p);


	if (p->type == input_dvb_type_docsis_scan) {
		while (p->tpriv.d.scan->streams) {
			struct input_dvb_docsis_scan_priv_stream *tmp = p->tpriv.d.scan->streams;
			p->tpriv.d.scan->streams = tmp->next;
			free(tmp);
		}
		if (p->tpriv.d.scan->dvr_dev)
			free(p->tpriv.d.scan->dvr_dev);
	}

	return POM_OK;
}

static int input_dvb_cleanup(struct input *i) {

	struct input_dvb_priv *p = i->priv;

	if (p->timer)
		timer_sys_cleanup(p->timer);

	if (p->adapter)
		ptype_cleanup(p->adapter);
	if (p->frontend)
		ptype_cleanup(p->frontend);
	if (p->freq)
		ptype_cleanup(p->freq);
	if (p->symbol_rate)
		ptype_cleanup(p->symbol_rate);
	if (p->filter_null_pid)
		ptype_cleanup(p->filter_null_pid);
	if (p->tuning_timeout)
		ptype_cleanup(p->tuning_timeout);

	if (p->modulation)
		ptype_cleanup(p->modulation);

	switch (p->type) {
		case input_dvb_type_s:
			if (p->tpriv.s.polarity)
				ptype_cleanup(p->tpriv.s.polarity);
			if (p->tpriv.s.lnb_type)
				ptype_cleanup(p->tpriv.s.lnb_type);
			break;
		case input_dvb_type_docsis_scan:
			if (p->tpriv.d.scan) {
				if (p->tpriv.d.scan->p_scan_qam64)
					ptype_cleanup(p->tpriv.d.scan->p_scan_qam64);
				if (p->tpriv.d.scan->p_complete_freq_scan)
					ptype_cleanup(p->tpriv.d.scan->p_complete_freq_scan);
				if (p->tpriv.d.scan->p_add_input)
					ptype_cleanup(p->tpriv.d.scan->p_add_input);

				free(p->tpriv.d.scan);
			}
			// No break
		case input_dvb_type_docsis:
			if (p->tpriv.d.pkt)
				packet_release(p->tpriv.d.pkt);
			break;
		default:
			break;
	}

	free(p);

	return POM_OK;

}

static int input_dvb_timer_process(void *input) {

	struct input *i = input;
	struct input_dvb_priv *p = i->priv;

	if (p->type == input_dvb_type_docsis_scan) {

		struct input_dvb_docsis_scan_priv *spriv = p->tpriv.d.scan;
		spriv->sync_count = -1;
		//  Timeout occured, interrupt current read
		pthread_kill(i->thread, SIGCHLD);
		return POM_OK;
	}


	// Check lock status

	fe_status_t status;

	if (ioctl(p->frontend_fd, FE_READ_STATUS, &status)) {
		pomlog(POMLOG_WARN "IOCTL failed while getting status of the DVB adapter");
		input_stop(input);
		return POM_ERR;
	}

	// Requeue the timer
	timer_sys_queue(p->timer, 2);

	if (p->status != status) {

		if (p->status)
			pomlog(POMLOG_WARN "Lock %s on input %s", (status & FE_HAS_LOCK ? "re-aquired" : "lost"), i->name);

		p->status = status;


		if (event_has_listener(input_dvb_evt_status_reg)) {

			struct event *evt = event_alloc(input_dvb_evt_status_reg);
			if (!evt)
				return POM_ERR;

			struct data *evt_data = event_get_data(evt);
			PTYPE_BOOL_SETVAL(evt_data[input_dvb_status_lock].value, (status & FE_HAS_LOCK ? 1 : 0));
			data_set(evt_data[input_dvb_status_lock]);

			ptype_copy(evt_data[input_dvb_status_adapter].value, p->adapter);
			data_set(evt_data[input_dvb_status_adapter]);

			ptype_copy(evt_data[input_dvb_status_frontend].value, p->frontend);
			data_set(evt_data[input_dvb_status_frontend]);

			ptype_copy(evt_data[input_dvb_status_frequency].value, p->freq);
			data_set(evt_data[input_dvb_status_frequency]);

			PTYPE_STRING_SETVAL(evt_data[input_dvb_status_input_name].value, i->name);
			data_set(evt_data[input_dvb_status_input_name]);

			event_process(evt, NULL, 0, pom_gettimeofday());
		}
	}

	return POM_OK;
}

static int input_dvb_perf_update_signal(uint64_t *value, void *priv) {

	struct input_dvb_priv *p = priv;

	if (p->frontend_fd == -1)
		return POM_OK;

	uint16_t signal = 0;
	if (ioctl(p->frontend_fd, FE_READ_SIGNAL_STRENGTH, &signal)) {
		uint16_t *adapter = PTYPE_UINT16_GETVAL(p->adapter);
		uint16_t *frontend = PTYPE_UINT16_GETVAL(p->frontend);
		pomlog(POMLOG_ERR "Error while fetching signal from adapter %u, frontend %u : %s", *adapter, *frontend, pom_strerror(errno));
		return POM_ERR;
	}
	*value = signal;

	return POM_OK;
}

static int input_dvb_perf_update_snr(uint64_t *value, void *priv) {

	struct input_dvb_priv *p = priv;

	if (p->frontend_fd == -1)
		return POM_OK;

	uint16_t snr = 0;
	if (ioctl(p->frontend_fd, FE_READ_SNR, &snr)) {
		uint16_t *adapter = PTYPE_UINT16_GETVAL(p->adapter);
		uint16_t *frontend = PTYPE_UINT16_GETVAL(p->frontend);
		pomlog(POMLOG_ERR "Error while fetching SNR from adapter %u, frontend %u : %s", *adapter, *frontend, pom_strerror(errno));
		return POM_ERR;
	}
	*value = snr;

	return POM_OK;
}

static int input_dvb_perf_update_unc(uint64_t *value, void *priv) {

	struct input_dvb_priv *p = priv;

	if (p->frontend_fd == -1)
		return POM_OK;

	uint16_t unc = 0;
	if (ioctl(p->frontend_fd, FE_READ_UNCORRECTED_BLOCKS, &unc)) {
		uint16_t *adapter = PTYPE_UINT16_GETVAL(p->adapter);
		uint16_t *frontend = PTYPE_UINT16_GETVAL(p->frontend);
		pomlog(POMLOG_ERR "Error while fetching uncorrected blocks from adapter %u, frontend %u : %s", *adapter, *frontend, pom_strerror(errno));
		return POM_ERR;
	}
	// uncorrected blocks value get cleared after polling
	*value += unc;

	return POM_OK;
}

static int input_dvb_perf_update_ber(uint64_t *value, void *priv) {

	struct input_dvb_priv *p = priv;

	if (p->frontend_fd == -1)
		return POM_OK;

	uint16_t ber = 0;
	if (ioctl(p->frontend_fd, FE_READ_BER, &ber)) {
		uint16_t *adapter = PTYPE_UINT16_GETVAL(p->adapter);
		uint16_t *frontend = PTYPE_UINT16_GETVAL(p->frontend);
		pomlog(POMLOG_ERR "Error while fetching the bit error rate from adapter %u, frontend %u : %s", *adapter, *frontend, pom_strerror(errno));
		return POM_ERR;
	}
	*value = ber;

	return POM_OK;
}
