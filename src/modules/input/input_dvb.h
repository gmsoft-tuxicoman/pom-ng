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

#ifndef __INPUT_DVB_H__
#define __INPUT_DVB_H__

#define INPUT_DVB_DOCSIS_PID		0x1FFE
#define INPUT_DVB_DOCSIS_EHDR_MAX_LEN	240

enum input_dvb_type {
	input_dvb_type_device, // Used for card with a user space tuner not compatible with the dvb api
	input_dvb_type_c,
	input_dvb_type_s,
	input_dvb_type_t, // TODO
	input_dvb_type_atsc,
	input_dvb_type_docsis,
};

struct input_dvb_s_priv{
	
	struct ptype *polarity;
	struct ptype *lnb_type;
	// TODO support for DiSEqC
};

struct input_dvb_docsis_priv {

	struct packet *pkt;
	size_t pkt_pos;
	
	unsigned char docsis_buff[3]; // Temporary buffer to gather the docsis headers
	size_t docsis_buff_len; // Size of the docsis header content len

};

struct input_dvb_priv {

	enum input_dvb_type type;

	struct proto *link_proto;

	// Some (mostly) common params
	struct ptype *adapter, *frontend, *freq, *symbol_rate, *tuning_timeout, *filter_null_pid, *modulation, *buff_pkt_count;

	int frontend_fd, demux_fd, dvr_fd;

	fe_type_t fe_type; // Frontend type

	union {
		struct input_dvb_s_priv s;
		struct input_dvb_docsis_priv d;
	} tpriv;

	struct registry_perf *perf_null_discarded;
	struct registry_perf *perf_signal;
	struct registry_perf *perf_snr;
	struct registry_perf *perf_unc;
	struct registry_perf *perf_ber;

	unsigned char *mpeg_buff;

};

struct input_dvb_lnb_param {
	char *name;
	unsigned int low_val;
	unsigned int high_val;
	unsigned int switch_val;
	unsigned int min_freq;
	unsigned int max_freq;
};

struct mod_reg_info* input_dvb_reg_info();
static int input_dvb_mod_register(struct mod_reg *mod);
static int input_dvb_mod_unregister();

static int input_dvb_common_init(struct input *i, enum input_dvb_type type);
static int input_dvb_device_init(struct input *i);
static int input_dvb_c_init(struct input *i);
static int input_dvb_s_init(struct input *i);
static int input_dvb_atsc_init(struct input *i);
static int input_dvb_docsis_init(struct input *i);

static int input_dvb_device_open(struct input *i);
static int input_dvb_open(struct input *i);

static int input_dvb_tune(struct input_dvb_priv *p, uint32_t frequency, uint32_t symbol_rate, fe_modulation_t modulation);
static int input_dvb_read(struct input *i);
static int input_dvb_docsis_read(struct input *i);
static int input_dvb_docsis_process_packet(struct input *i, unsigned char *buff);
static int input_dvb_close(struct input *i);
static int input_dvb_cleanup(struct input *i);

static int input_dvb_perf_update_signal(uint64_t *value, void *priv);
static int input_dvb_perf_update_snr(uint64_t *value, void *priv);
static int input_dvb_perf_update_unc(uint64_t *value, void *priv);
static int input_dvb_perf_update_ber(uint64_t *value, void *priv);

#endif

