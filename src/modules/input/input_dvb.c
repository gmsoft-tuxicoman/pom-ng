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

#include <linux/dvb/dmx.h>
#include <linux/dvb/frontend.h>

#include <sys/ioctl.h>
#include <errno.h>

#include <sys/poll.h>

#include <pom-ng/input.h>
#include <pom-ng/ptype_bool.h>
#include <pom-ng/ptype_string.h>
#include <pom-ng/ptype_uint16.h>
#include <pom-ng/ptype_uint32.h>

#include <pom-ng/registry.h>

#include <pom-ng/packet.h>
#include <pom-ng/core.h>

#include "input_dvb.h"

/// We use a bigger buffer size of the demux interface. This way we can cope with some burst.
#define DEMUX_BUFFER_SIZE 2097152 // 2MB

#define PID_FULL_TS 0x2000
#define MPEG_TS_LEN 188

#define LNB_COUNT 1

static struct input_dvb_lnb_param input_dvb_lnbs[LNB_COUNT] = {
	{ "universal", 9750000, 10600000, 11700000, 10700000, 12750000 },
};

struct mod_reg_info* input_dvb_reg_info() {

	static struct mod_reg_info reg_info;
	memset(&reg_info, 0, sizeof(struct mod_reg_info));
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = input_dvb_mod_register;
	reg_info.unregister_func = input_dvb_mod_unregister;
	reg_info.dependencies = "proto_mpeg, ptype_bool, ptype_string, ptype_uint16, ptype_uint32";

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

	res += input_register(&in_dvb_s);

	return res;
}

static int input_dvb_mod_unregister() {
	
	int res = POM_OK;
	res += input_unregister("dvb_device");
	res += input_unregister("dvb_c");
	res += input_unregister("dvb_s");

	return res;
}


static int input_dvb_common_init(struct input *i) {

	struct input_dvb_priv *priv = malloc(sizeof(struct input_dvb_priv));
	if (!priv) {
		pom_oom(sizeof(struct input_dvb_priv));
		return POM_ERR;
	}
	memset(priv, 0, sizeof(struct input_dvb_priv));

	priv->frontend_fd = -1;
	priv->demux_fd = -1;
	priv->dvr_fd = -1;

	priv->proto_mpeg_ts = proto_get("mpeg_ts");
	if (!priv->proto_mpeg_ts) {
		pomlog(POMLOG_ERR "Cannot initialize input DVB : protocol mpeg_ts not registered");
		goto err;
	}

	priv->perf_null_discarded = registry_instance_add_perf(i->reg_instance, "null_discarded", registry_perf_type_counter, "Number of NULL MPEG packets discarded.", "pkts");
	priv->perf_signal = registry_instance_add_perf(i->reg_instance, "signal", registry_perf_type_gauge, "Signal", "dB");
	priv->perf_snr = registry_instance_add_perf(i->reg_instance, "snr", registry_perf_type_gauge, "Signal to Noise ratio (SNR)", "dB");
	priv->perf_unc = registry_instance_add_perf(i->reg_instance, "unc", registry_perf_type_counter, "Uncorrected blocks", "blocks");
	priv->perf_ber = registry_instance_add_perf(i->reg_instance, "ber", registry_perf_type_gauge, "Bit error rate (BER)", "bits/block");
	if (!priv->perf_null_discarded | !priv->perf_signal | !priv->perf_snr | !priv->perf_unc | !priv->perf_ber)
		goto err;

	registry_perf_set_update_hook(priv->perf_signal, input_dvb_perf_update_signal, priv);
	registry_perf_set_update_hook(priv->perf_snr, input_dvb_perf_update_snr, priv);
	registry_perf_set_update_hook(priv->perf_unc, input_dvb_perf_update_unc, priv);
	registry_perf_set_update_hook(priv->perf_ber, input_dvb_perf_update_ber, priv);

	priv->filter_null_pid = ptype_alloc("bool");

	struct registry_param *p = registry_new_param("filter_null_pid", "yes", priv->filter_null_pid, "Filter out the null MPEG PID (0x1FFF) as it usually contains no usefull data", 0);
	if (registry_instance_add_param(i->reg_instance, p) != POM_OK) {
		registry_cleanup_param(p);
		goto err;
	}

	i->priv = priv;

	return POM_OK;

err:
	
	if (priv->filter_null_pid)
		ptype_cleanup(priv->filter_null_pid);

	free(priv);
	return POM_ERR;

}


static int input_dvb_device_init(struct input *i) {


	if (input_dvb_common_init(i) != POM_OK)
		return POM_ERR;

	struct input_dvb_priv *priv = i->priv;
	struct registry_param *p = NULL;

	priv->frontend = ptype_alloc("string");
	if (!priv->frontend)
		goto err;

	p = registry_new_param("device", "/dev/dvb/adapterX/dvrY", priv->frontend, "Device to read packets from", 0);
	if (registry_instance_add_param(i->reg_instance, p) != POM_OK)
		goto err;

	priv->type = input_dvb_type_device;

	return POM_OK;

err:

	if (p)
		registry_cleanup_param(p);

	free(priv);

	return POM_ERR;
}

static int input_dvb_c_init(struct input *i) {

	if (input_dvb_common_init(i) != POM_OK)
		return POM_ERR;

	struct input_dvb_priv *priv = i->priv;

	struct registry_param *p = NULL;

	priv->adapter = ptype_alloc("uint16");
	priv->frontend = ptype_alloc("uint16");
	priv->freq = ptype_alloc_unit("uint32", "Hz");
	priv->symbol_rate = ptype_alloc_unit("uint32", "symbols/second");
	priv->tuning_timeout = ptype_alloc_unit("uint16", "seconds");
	priv->tpriv.c.modulation = ptype_alloc_unit("string", NULL);
	if (!priv->adapter || !priv->frontend || !priv->freq || !priv->tuning_timeout || !priv->tpriv.c.modulation) 
		goto err;

	p = registry_new_param("adapter", "0", priv->adapter, "Adapter ID : /dev/dvb/adapterX", 0);
	if (registry_instance_add_param(i->reg_instance, p) != POM_OK)
		goto err;

	p = registry_new_param("frontend", "0", priv->frontend, "Frontend ID : /dev/dvb/adapterX/frontendY", 0);
	if (registry_instance_add_param(i->reg_instance, p) != POM_OK)
		goto err;

	p = registry_new_param("frequency", "0", priv->freq, "Frequency in Hz", 0);
	if (registry_instance_add_param(i->reg_instance, p) != POM_OK)
		goto err;

	p = registry_new_param("symbol_rate", "6952000", priv->symbol_rate, "Symbols per seconds", 0);
	if (registry_instance_add_param(i->reg_instance, p) != POM_OK)
		goto err;

	p = registry_new_param("tuning_timeout", "3", priv->tuning_timeout, "Timeout while trying to tune in seconds", 0);
	if (registry_instance_add_param(i->reg_instance, p) != POM_OK)
		goto err;

	p = registry_new_param("modulation", "QAM256", priv->tpriv.c.modulation, "Modulation either QAM64 or QAM256", 0);
	if (registry_instance_add_param(i->reg_instance, p) != POM_OK)
		goto err;

	priv->type = input_dvb_type_c;

	return POM_OK;

err:

	if (p)
		registry_cleanup_param(p);

	if (priv->adapter)
		ptype_cleanup(priv->adapter);
	if (priv->frontend)
		ptype_cleanup(priv->frontend);
	if (priv->freq)
		ptype_cleanup(priv->freq);
	if (priv->symbol_rate)
		ptype_cleanup(priv->symbol_rate);
	if (priv->tuning_timeout)
		ptype_cleanup(priv->tuning_timeout);
	if (priv->tpriv.c.modulation)
		ptype_cleanup(priv->tpriv.c.modulation);
	
	free(priv);

	return POM_ERR;
}

static int input_dvb_s_init(struct input *i) {

	if (input_dvb_common_init(i) != POM_OK)
		return POM_ERR;

	struct input_dvb_priv *priv = i->priv;

	struct registry_param *p = NULL;

	priv->adapter = ptype_alloc("uint16");
	priv->frontend = ptype_alloc("uint16");
	priv->freq = ptype_alloc_unit("uint32", "Hz");
	priv->symbol_rate = ptype_alloc_unit("uint32", "symbols/second");
	priv->tuning_timeout = ptype_alloc_unit("uint16", "seconds");
	priv->tpriv.s.polarity = ptype_alloc_unit("string", NULL);
	priv->tpriv.s.lnb_type = ptype_alloc_unit("string", NULL);
	if (!priv->adapter || !priv->frontend || !priv->freq || !priv->tuning_timeout || !priv->tpriv.s.polarity || !priv->tpriv.s.lnb_type) 
		goto err;

	p = registry_new_param("adapter", "0", priv->adapter, "Adapter ID : /dev/dvb/adapterX", 0);
	if (registry_instance_add_param(i->reg_instance, p) != POM_OK)
		goto err;

	p = registry_new_param("frontend", "0", priv->frontend, "Frontend ID : /dev/dvb/adapterX/frontendY", 0);
	if (registry_instance_add_param(i->reg_instance, p) != POM_OK)
		goto err;

	p = registry_new_param("frequency", "0", priv->freq, "Frequency in Hz", 0);
	if (registry_instance_add_param(i->reg_instance, p) != POM_OK)
		goto err;

	p = registry_new_param("symbol_rate", "0", priv->symbol_rate, "Symbols per seconds", 0);
	if (registry_instance_add_param(i->reg_instance, p) != POM_OK)
		goto err;

	p = registry_new_param("tuning_timeout", "3", priv->tuning_timeout, "Timeout while trying to tune in seconds", 0);
	if (registry_instance_add_param(i->reg_instance, p) != POM_OK)
		goto err;

	p = registry_new_param("polarity", "h" , priv->tpriv.s.polarity, "Polarisation, either 'h' or 'v'", 0);
	if (registry_instance_add_param(i->reg_instance, p) != POM_OK)
		goto err;

	p = registry_new_param("lnb_type", "universal", priv->tpriv.s.lnb_type, "LNB type", 0);
	if (registry_instance_add_param(i->reg_instance, p) != POM_OK)
		goto err;

	priv->type = input_dvb_type_s;

	return POM_OK;

err:

	if (p)
		registry_cleanup_param(p);

	if (priv->adapter)
		ptype_cleanup(priv->adapter);
	if (priv->frontend)
		ptype_cleanup(priv->frontend);
	if (priv->freq)
		ptype_cleanup(priv->freq);
	if (priv->symbol_rate)
		ptype_cleanup(priv->symbol_rate);
	if (priv->tuning_timeout)
		ptype_cleanup(priv->tuning_timeout);
	if (priv->tpriv.s.polarity)
		ptype_cleanup(priv->tpriv.s.polarity);
	if (priv->tpriv.s.lnb_type)
		ptype_cleanup(priv->tpriv.s.lnb_type);
	
	free(priv);

	return POM_ERR;
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


static int input_dvb_open(struct input *i) {

	struct input_dvb_priv *priv = i->priv;

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
		return POM_ERR;
	}

	// Check frontend type
	struct dvb_frontend_info info;
	if (ioctl(priv->frontend_fd, FE_GET_INFO, &info)) {
		pomlog(POMLOG_ERR "Unable to get frontend information from adapter %s : %s", adapter, pom_strerror(errno));
		goto err;
	}

	switch (priv->type) {

		case input_dvb_type_c:
			if (info.type != FE_QAM) {
				pomlog(POMLOG_ERR "The frontend %s is not a DVB-C adapter", frontend);
				goto err;
			}
			break;
		
		case input_dvb_type_s:
			if (info.type != FE_QPSK) {
				pomlog(POMLOG_ERR "The frontend %s is not a DVB-S adapter", frontend);
				goto err;
			}
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
	filter.pid = PID_FULL_TS;
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

	priv->dvr_fd = open(dvr, O_RDONLY);
	if (priv->dvr_fd == -1) {
		pomlog(POMLOG_ERR "Unable to open DVR device : %s", pom_strerror(errno));
		goto err;
	}


	// Do the tuning
	
	fe_modulation_t modulation = 0;

	uint32_t frequency = *PTYPE_UINT32_GETVAL(priv->freq);
	uint32_t tuning_frequency = frequency;
	uint32_t symbol_rate = *PTYPE_UINT32_GETVAL(priv->symbol_rate);

	if (priv->type == input_dvb_type_c) {

		char *mod_str = PTYPE_STRING_GETVAL(priv->tpriv.c.modulation);
		if (!strcmp(mod_str, "QAM64"))
			modulation = QAM_64;
		else if (!strcmp(mod_str, "QAM256"))
			modulation = QAM_256;
		else {
			pomlog(POMLOG_ERR "Invalid modulation \"%s\"", mod_str);
			goto err;
		}


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


	}

	int res = input_dvb_tune(priv, tuning_frequency, symbol_rate, modulation);
	if (res != 1) {
		pomlog("Lock not acquired on frequency %u Hz", frequency);
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

// Return -1 on fatal error, 0 if not tuned, 1 if tuned
static int input_dvb_tune(struct input_dvb_priv *p, uint32_t frequency, uint32_t symbol_rate, fe_modulation_t modulation) {

	
	fe_status_t status;
	struct dvb_frontend_parameters frp;
	struct pollfd pfd[1];

	memset(&frp, 0, sizeof(struct dvb_frontend_parameters));
	frp.frequency = frequency;
	frp.inversion = INVERSION_AUTO;

	switch (p->type) {

		case input_dvb_type_c:
			frp.u.qam.symbol_rate = symbol_rate;
			frp.u.qam.fec_inner = FEC_AUTO;
			frp.u.qam.modulation = modulation;
			break;

		case input_dvb_type_s:
			frp.u.qpsk.symbol_rate = symbol_rate;
			frp.u.qpsk.fec_inner = FEC_AUTO;
			break;

		default:
			return -1;

	}

	// Let's do some tuning

	if (ioctl(p->frontend_fd, FE_SET_FRONTEND, &frp) < 0){
		pomlog(POMLOG_ERR "Error while setting tuning parameters : %s", pom_strerror(errno));
		return POM_ERR;
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
				
				char status_str[128];
				memset(status_str, 0, sizeof(status_str));
				if (status)
					strcat(status_str, "Status : " );

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

	return POM_OK;
}

static int input_dvb_read(struct input *i) {

	struct input_dvb_priv *p = i->priv;

	ssize_t len = 0, r = 0;

	// Get a new place holder for our packet
	struct packet *pkt = packet_alloc();

	if (!pkt)
		return POM_ERR;

	if (packet_buffer_alloc(pkt, MPEG_TS_LEN, 0) != POM_OK) {
		packet_release(pkt);
		return POM_ERR;
	}

	pkt->input = i;
	pkt->datalink = p->proto_mpeg_ts;

	unsigned char *pload = pkt->buff;

	do {

		r = read(p->dvr_fd, pkt->buff + len, MPEG_TS_LEN - len);
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

		char *filter_null_pid = PTYPE_BOOL_GETVAL(p->filter_null_pid);
		if (*filter_null_pid) {
			uint16_t pid = ((pload[1] & 0x1F) << 8) | (pload)[2];
			if (len > 3 && pid == 0x1FFF) { // 0x1FFF is the NULL PID
				len = 0;
				registry_perf_inc(p->perf_null_discarded, 1);
			}
		}

	} while (len < MPEG_TS_LEN);


	// Check sync byte
	if (pload[0] != 0x47) {
		pomlog(POMLOG_ERR "Error, stream out of sync !");
		return POM_ERR;
	}

	pkt->ts = pom_gettimeofday();

	uint16_t pid = ((pload[1] & 0x1F) << 8) | pload[2];

	return core_queue_packet(pkt, CORE_QUEUE_HAS_THREAD_AFFINITY | CORE_QUEUE_DROP_IF_FULL, pid);

}

static int input_dvb_close(struct input *i) {

	struct input_dvb_priv *p = i->priv;

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

	return POM_OK;
}

static int input_dvb_cleanup(struct input *i) {

	struct input_dvb_priv *p = i->priv;

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

	switch (p->type) {
		case input_dvb_type_c:
			ptype_cleanup(p->tpriv.c.modulation);
			break;

		case input_dvb_type_s:
			ptype_cleanup(p->tpriv.s.polarity);
			ptype_cleanup(p->tpriv.s.lnb_type);
			break;
	
		default:
			return POM_ERR;
	}

	free(p);

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
