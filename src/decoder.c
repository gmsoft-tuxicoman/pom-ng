/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2011-2013 Guy Martin <gmsoft@tuxicoman.be>
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

#include "common.h"
#include "mod.h"

#include "decoder.h"

static struct decoder_reg *decoder_reg_head = NULL;


int decoder_register(struct decoder_reg_info *reg_info) {

	pomlog(POMLOG_DEBUG "Registering decoder %s", reg_info->name);

	struct decoder_reg *decoder = malloc(sizeof(struct decoder_reg));
	if (!decoder) {
		pom_oom(sizeof(struct decoder_reg));
		return POM_ERR;
	}
	memset(decoder, 0, sizeof(struct decoder_reg));
	decoder->info = reg_info;

	decoder->next = decoder_reg_head;
	if (decoder->next)
		decoder->next->prev = decoder;
	decoder_reg_head = decoder;

	mod_refcount_inc(reg_info->mod);

	return POM_OK;
}

int decoder_unregister(char *name) {

	struct decoder_reg *tmp;
	for (tmp = decoder_reg_head; tmp && strcmp(tmp->info->name, name); tmp = tmp->next);

	if (!tmp)
		return POM_OK;

	if (tmp->prev)
		tmp->prev->next = tmp->next;
	else
		decoder_reg_head = tmp->next;
	
	if (tmp->next)
		tmp->next->prev = tmp->prev;

	mod_refcount_dec(tmp->info->mod);

	free(tmp);

	return POM_OK;
}

struct decoder *decoder_alloc(char *name) {

	struct decoder_reg *tmp;
	for (tmp = decoder_reg_head; tmp && strcasecmp(tmp->info->name, name); tmp = tmp->next);
	if (!tmp)
		return NULL;
	
	struct decoder *dec = malloc(sizeof(struct decoder));
	if (!dec) {
		pom_oom(sizeof(struct decoder));
		return NULL;
	}
	memset(dec, 0, sizeof(struct decoder));

	dec->reg = tmp->info;

	if (dec->reg->alloc && dec->reg->alloc(dec) != POM_OK) {
		free(dec);
		return NULL;
	}

	return dec;

}

int decoder_cleanup(struct decoder *dec) {

	if (dec->reg->cleanup)
		dec->reg->cleanup(dec);

	free(dec);
	return POM_OK;
}

int decoder_cleanup_all() {
	
	while (decoder_reg_head) {
		struct decoder_reg *tmp = decoder_reg_head;
		decoder_reg_head = tmp->next;
		mod_refcount_dec(tmp->info->mod);
		free(tmp);
	}

	return POM_OK;
}

int decoder_decode(struct decoder *dec) {

	return dec->reg->decode(dec);

}

int decoder_estimate_output_size(struct decoder *dec, size_t in_len) {

	return dec->reg->estimate_size(in_len);

}

int decoder_decode_simple(char *encoding, char *in, size_t in_len, char **out, size_t *out_len) {

	struct decoder_reg *tmp;
	for (tmp = decoder_reg_head; tmp && strcasecmp(tmp->info->name, encoding); tmp = tmp->next);

	if (!tmp) {
		pomlog(POMLOG_ERR "Decoder %s does not exists", encoding);
		*out = NULL;
		*out_len = 0;
		return DEC_ERR;
	}
	
	struct decoder dec = { 0 };
	dec.reg = tmp->info;

	if (dec.reg->alloc && dec.reg->alloc(&dec) != POM_OK)
		return DEC_ERR;

	dec.avail_in = in_len;
	dec.next_in = in;

	size_t buff_len = dec.reg->estimate_size(in_len);
	dec.next_out = malloc(buff_len);
	*out = dec.next_out;

	dec.avail_out = buff_len;
	if (!dec.next_out) {
		pom_oom(dec.avail_out);
		goto err;
	}

	int res = dec.reg->decode(&dec);
	if (res == DEC_ERR) {
		free(dec.next_out);
		goto err;
	}

	if (dec.reg->cleanup)
		dec.reg->cleanup(&dec);
		
	*out_len = buff_len - dec.avail_out;

	return DEC_OK;

err:

	if (dec.reg->cleanup)
		dec.reg->cleanup(&dec);

	*out = NULL;
	*out_len = 0;
	return DEC_ERR;
}
