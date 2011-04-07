/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2006-2008 Guy Martin <gmsoft@tuxicoman.be>
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


#ifndef __DOCSIS_H__
#define __DOCSIS_H__

#include "config.h"
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

struct docsis_hdr {

#if __BYTE_ORDER == __LITTLE_ENDIAN
	unsigned char ehdr_on:1;
	unsigned char fc_parm:5;
	unsigned char fc_type:2;
#elif __BYTE_ORDER == __BIG_ENDIAN
	unsigned char fc_type:2;
	unsigned char fc_parm:5;
	unsigned char ehdr_on:1;
#else
# error "Please fix <bits/endian.h>"
#endif
	unsigned char mac_parm;
	uint16_t len;
	uint16_t hcs; // can also be start of ehdr. See SCTE 22-12002 section 6.2.1.4

};

struct docsis_ehdr {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint8_t eh_len:4;
	uint8_t eh_type:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
	uint8_t eh_type:4;
	uint8_t eh_len:4;
#else
# error "Please fix <bits/endian.h>"
#endif

};


struct docsis_mgmt_hdr {

	unsigned char daddr[6];
	unsigned char saddr[6];
	uint16_t len;
	unsigned char dsap;
	unsigned char ssap;
	unsigned char control;
	unsigned char version;
	unsigned char type;
	unsigned char rsvd;

};

struct docsis_mgmt_mdd_hdr {
	unsigned char change_count;
	unsigned char frag_tot;
	unsigned char frag_seq;
	unsigned char chan_dcid;

};

// Definition of the standard types

#define FC_TYPE_PKT_MAC			0x0 // Packet-based MAC frame
#define FC_TYPE_ATM			0x1 // ATM cell MAC frame
#define FC_TYPE_ISOLATION_PKT_MAC	0x2 // DOCSIS 3 isolation packet MAC frame
#define FC_TYPE_MAC_SPC 		0x3 // MAC-specific header


// Definition of mac management mac_parm values
#define FCP_TIMING	0x00 // Timing header
#define FCP_MGMT	0x01 // Management header
#define FCP_REQ		0x02 // Request header (upstream only)
#define FCP_CONCAT	0x1C // Concatenation header (upstream only)

// Definition of extended header types
#define EH_TYPE_NULL		0x0	// Null type for padding
#define EH_TYPE_MINI_REQ	0x1	// Mini-slot request
#define EH_TYPE_ACK		0x1	// Ack request
#define EH_TYPE_BP_UP		0x2	// Upstream privacy element
#define EH_TYPE_BP_DOWN		0x4	// Downstream privacy element

#endif
