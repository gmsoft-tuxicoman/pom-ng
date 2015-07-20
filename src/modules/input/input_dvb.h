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

#define INPUT_DVB_STATUS_DATA_COUNT		5
#define INPUT_DVB_DOCSIS_STREAM_DATA_COUNT	6

#define INPUT_DVB_DOCSIS_PID			0x1FFE
#define INPUT_DVB_DOCSIS_EHDR_MAX_LEN		240
#define INPUT_DVB_DOCSIS_EURO_SYMBOLRATE	6952000


enum {
	input_dvb_status_lock = 0,
	input_dvb_status_adapter,
	input_dvb_status_frontend,
	input_dvb_status_frequency,
	input_dvb_status_input_name
};

enum {
	input_dvb_docsis_stream_frequency = 0,
	input_dvb_docsis_stream_modulation,
	input_dvb_docsis_stream_chan_id,
	input_dvb_docsis_stream_pri_capable,
	input_dvb_docsis_stream_chan_bonding,
	input_dvb_docsis_stream_input_name
};

enum input_dvb_type {
	input_dvb_type_device, // Used for card with a user space tuner not compatible with the dvb api
	input_dvb_type_c,
	input_dvb_type_s,
	input_dvb_type_t, // TODO
	input_dvb_type_atsc,
	input_dvb_type_docsis,
	input_dvb_type_docsis_scan,
};

struct input_dvb_s_priv{
	
	struct ptype *polarity;
	struct ptype *lnb_type;
	// TODO support for DiSEqC
};

struct input_dvb_docsis_priv {

	struct packet *pkt;
	size_t pkt_pos;
	
	size_t docsis_buff_len; // Size of the docsis header content len
	struct input_dvb_docsis_scan_priv *scan;

	unsigned char docsis_buff[3]; // Temporary buffer to gather the docsis headers
	uint8_t mpeg_seq;

};

struct input_dvb_docsis_scan_priv_stream {

	uint32_t freq;
	fe_modulation_t modulation;
	struct input_dvb_docsis_scan_priv_stream *next;
	uint8_t chan_id;
	uint8_t pri_capable;
	uint8_t chan_bonding;
};

struct input_dvb_docsis_scan_priv {

	struct ptype *p_scan_qam64, *p_complete_freq_scan, *p_add_input;

	uint32_t freq_min, freq_max, freq_step;
	uint32_t freq_fast_start;

	uint32_t cur_freq;
	uint32_t cur_step;
	fe_modulation_t cur_mod;
	int sync_count;
	char *dvr_dev;
	int mdd_found;
	int input_id;
	struct input_dvb_docsis_scan_priv_stream *streams;

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

	struct timer_sys *timer;

	fe_status_t status;

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

static int input_dvb_register();
static int input_dvb_unregister();
static int input_dvb_docsis_scan_register();
static int input_dvb_docsis_scan_unregister();

static int input_dvb_common_init(struct input *i, enum input_dvb_type type);
static int input_dvb_device_init(struct input *i);
static int input_dvb_c_init(struct input *i);
static int input_dvb_s_init(struct input *i);
static int input_dvb_atsc_init(struct input *i);
static int input_dvb_docsis_init(struct input *i);
static int input_dvb_docsis_scan_init(struct input *i);

static int input_dvb_device_open(struct input *i);
static int input_dvb_card_open(struct input_dvb_priv *priv);
static int input_dvb_docsis_scan_open(struct input *i);
static int input_dvb_open(struct input *i);

static int input_dvb_tune(struct input_dvb_priv *p, uint32_t frequency, uint32_t symbol_rate, fe_modulation_t modulation);
static int input_dvb_read(struct input *i);
static int input_dvb_docsis_scan_read(struct input *i);
static int input_dvb_docsis_read(struct input *i);
static void input_dvb_docsis_free_buff(struct input_dvb_docsis_priv *p);
static int input_dvb_docsis_process_new_stream(struct input *i, struct input_dvb_docsis_scan_priv_stream *s);
static int input_dvb_docsis_process_docsis_mdd(struct input *i, unsigned char *buff, size_t len);
static int input_dvb_docsis_process_docsis_packet(struct input *i);
static int input_dvb_docsis_process_mpeg_packet(struct input *i, unsigned char *buff);
static void input_dvb_card_close(struct input_dvb_priv *p);
static int input_dvb_close(struct input *i);
static int input_dvb_cleanup(struct input *i);

static int input_dvb_timer_process(void *priv);

static int input_dvb_perf_update_signal(uint64_t *value, void *priv);
static int input_dvb_perf_update_snr(uint64_t *value, void *priv);
static int input_dvb_perf_update_unc(uint64_t *value, void *priv);
static int input_dvb_perf_update_ber(uint64_t *value, void *priv);

#endif

