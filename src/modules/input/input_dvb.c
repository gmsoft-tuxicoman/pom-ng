/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2010 Guy Martin <gmsoft@tuxicoman.be>
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
#include <pom-ng/ptype_string.h>
#include <pom-ng/ptype_uint16.h>
#include <pom-ng/ptype_uint32.h>

#include "input_dvb.h"

/// We use a bigger buffer size of the demux interface. This way we can cope with some burst.
#define DEMUX_BUFFER_SIZE 2097152 // 2MB

#define PID_FULL_TS 0x2000
#define MPEG_TS_LEN 188

struct mod_reg_info* input_dvb_reg_info() {

	static struct mod_reg_info reg_info;
	memset(&reg_info, 0, sizeof(struct mod_reg_info));
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = input_dvb_mod_register;
	reg_info.unregister_func = input_dvb_mod_unregister;

	return &reg_info;

}

static int input_dvb_mod_register(struct mod_reg *mod) {

	static struct input_reg_info in_dvb_c;
	memset(&in_dvb_c, 0, sizeof(struct input_reg_info));
	in_dvb_c.name = "dvb_c";
	in_dvb_c.api_ver = INPUT_API_VER;
	in_dvb_c.alloc = input_dvb_c_alloc;
	in_dvb_c.open = input_dvb_open;
	in_dvb_c.read = input_dvb_read;
	in_dvb_c.get_caps = input_dvb_get_caps;
	in_dvb_c.close = input_dvb_close;
	in_dvb_c.cleanup = input_dvb_cleanup;
	input_register(&in_dvb_c, mod);

	return POM_OK;
}

static int input_dvb_mod_unregister() {
	
	int res = POM_OK;
	res += input_unregister("dvb_c");

	return res;
}


static int input_dvb_c_alloc(struct input *i) {

	struct input_dvb_priv *priv = malloc(sizeof(struct input_dvb_priv));
	if (!priv)
		return POM_ERR;

	memset(priv, 0, sizeof(struct input_dvb_priv));
	priv->frontend_fd = -1;
	priv->demux_fd = -1;
	priv->dvr_fd = -1;

	priv->adapter = ptype_alloc("uint16");
	priv->frontend = ptype_alloc("uint16");
	priv->freq = ptype_alloc_unit("uint32", "Hz");
	priv->symbol_rate = ptype_alloc_unit("uint32", "symboles/second");
	priv->tuning_timeout = ptype_alloc_unit("uint16", "seconds");
	priv->tpriv.c.modulation = ptype_alloc_unit("string", NULL);
	if (!priv->adapter || !priv->frontend || !priv->freq || !priv->tuning_timeout || !priv->tpriv.c.modulation) 
		goto err;

	if (input_register_param(i, "adapter", priv->freq, "0", "Adapter ID : /dev/dvb/adapterX", 0) != POM_OK)
		goto err;

	if (input_register_param(i, "frontend", priv->freq, "0", "Frontend ID : /dev/dvb/adapterX/frontendY", 0) != POM_OK)
		goto err;

	if (input_register_param(i, "frequency", priv->freq, "0", "Frequency in Hz", 0) != POM_OK)
		goto err;

	if (input_register_param(i, "symbol_rate", priv->symbol_rate, "0", "Symbols per seconds", 0) != POM_OK)
		goto err;

	if (input_register_param(i, "tuning_timeout", priv->tuning_timeout, "3", "Timeout while trying to tune in seconds", 0) != POM_OK)
		goto err;

	if (input_register_param(i, "modulation", priv->tpriv.c.modulation, "0", "Frequency in Hz", 0) != POM_OK)
		goto err;

	priv->type = input_dvb_type_c;

	i->priv = priv;

	return POM_OK;

err:
	if (priv->adapter)
		ptype_cleanup(priv->adapter);
	if (priv->frontend)
		ptype_cleanup(priv->frontend);
	if (priv->freq)
		ptype_cleanup(priv->freq);
	if (priv->symbol_rate)
		ptype_cleanup(priv->symbol_rate);
	if (priv->tpriv.c.modulation)
		ptype_cleanup(priv->tpriv.c.modulation);
	
	free(priv);

	return POM_ERR;
}

static int input_dvb_open(struct input *i) {

	struct input_dvb_priv *priv = i->priv;

	char adapter[FILENAME_MAX];
	memset(adapter, 0, FILENAME_MAX);
	strcpy(adapter, "/dev/dvb/adapter");
	ptype_print_val(priv->adapter, adapter + strlen(adapter), FILENAME_MAX - strlen(adapter));

	char frontend[FILENAME_MAX];
	strcpy(frontend, adapter);
	strcat(frontend, "/frontend");
	ptype_print_val(priv->frontend, frontend + strlen(frontend), FILENAME_MAX - strlen(frontend));
	
	priv->frontend_fd = open(frontend, O_RDWR);
	if (priv->frontend_fd == -1) {
		pomlog(POMLOG_ERR "Unable to open adapter %s : %s", adapter, pom_strerror(errno));
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
				pomlog(POMLOG_ERR "The adapter %s is not a DVB-C adapter", adapter);
				return POM_ERR;
			}
			break;

		default:
			return POM_ERR;
	}

	// Open the demux
	char demux[FILENAME_MAX];
	strcpy(demux, adapter);
	strcat(demux, "/demux0");

	priv->demux_fd = open(demux, O_RDWR);
	if (priv->demux_fd == -1) {
		pomlog(POMLOG_ERR "Unable to open demux device %s : %s", strerror(errno), demux);
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

	fe_modulation_t modulation;
	char *mod_str; PTYPE_STRING_GETVAL(priv->tpriv.c.modulation, mod_str);
	if (!strcmp(mod_str, "QAM64"))
		modulation = QAM_64;
	else if (!strcmp(mod_str, "QAM256"))
		modulation = QAM_256;
	else {
		pomlog(POMLOG_ERR "Invalid modulation \"%s\"", mod_str);
		goto err;
	}

	uint32_t *frequency; PTYPE_UINT32_GETVAL(priv->freq, frequency);
	uint32_t *symbol_rate; PTYPE_UINT32_GETVAL(priv->symbol_rate, symbol_rate);
	int res = input_dvb_tune(priv, *frequency, *symbol_rate, modulation);
	if (res != 1) 
		goto err;

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

		default:
			return -1;

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
	uint16_t *tuning_timeout; PTYPE_UINT16_GETVAL(p->tuning_timeout, tuning_timeout);
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

	pomlog("Lock not acquired on frequency %u Hz", frequency);

	return POM_OK;
}

static int input_dvb_read(struct input *i) {

	struct input_dvb_priv *p = i->priv;

	unsigned char buff[MPEG_TS_LEN];

	ssize_t len = 0, r = 0;

	do {
		r = read(p->dvr_fd, buff + len, MPEG_TS_LEN - len);
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

	} while (len < MPEG_TS_LEN);


	// Check sync byte
	if (buff[0] != 0x47) {
		pomlog(POMLOG_ERR "Error, stream out of sync !");
		return POM_ERR;
	}
	
	struct timeval now;
	if (gettimeofday(&now, NULL)) {
		pomlog(POMLOG_ERR "Error while getting time of the day : %s", pom_strerror(errno));
		return POM_ERR;
	}

	return input_add_processed_packet(i, MPEG_TS_LEN, buff, &now, 1);

}

static int input_dvb_get_caps(struct input *i, struct input_caps *ic) {

	ic->datalink = "mpeg_ts";
	ic->is_live = 1;

	return POM_OK;
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

	ptype_cleanup(p->adapter);
	ptype_cleanup(p->frontend);
	ptype_cleanup(p->freq);
	ptype_cleanup(p->symbol_rate);

	switch (p->type) {
		case input_dvb_type_c:
			ptype_cleanup(p->tpriv.c.modulation);
			break;
	
		default:
			return POM_ERR;
	}


	return POM_OK;

}
