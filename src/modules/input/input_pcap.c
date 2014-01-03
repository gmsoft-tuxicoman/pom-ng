/*
 *  This file is part of pom-ng.
 *  Copyright (C) 2010-2014 Guy Martin <gmsoft@tuxicoman.be>
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

#include <pom-ng/input.h>
#include <pom-ng/ptype_string.h>
#include <pom-ng/ptype_bool.h>

#include <pom-ng/registry.h>

#include <pom-ng/packet.h>
#include <pom-ng/core.h>

#include "input_pcap.h"
#include <string.h>

#include <sys/types.h>
#include <dirent.h>
#include <regex.h>
#include <stddef.h>
#include <signal.h>

// FIXME change this define when this value gets upstream
#define DLT_MPEGTS DLT_USER0

struct mod_reg_info* input_pcap_reg_info() {
	static struct mod_reg_info reg_info;
	memset(&reg_info, 0, sizeof(struct mod_reg_info));
	reg_info.api_ver = MOD_API_VER;
	reg_info.register_func = input_pcap_mod_register;
	reg_info.unregister_func = input_pcap_mod_unregister;
	reg_info.dependencies = "proto_80211, proto_docsis, proto_ethernet, proto_ipv4, proto_mpeg, proto_ppi, proto_radiotap, ptype_string, ptype_bool";

	return &reg_info;
}


static int input_pcap_mod_register(struct mod_reg *mod) {

	int res = POM_OK;

	static struct input_reg_info in_pcap_interface;
	memset(&in_pcap_interface, 0, sizeof(struct input_reg_info));
	in_pcap_interface.name = "pcap_interface";
	in_pcap_interface.flags = INPUT_REG_FLAG_LIVE;
	in_pcap_interface.mod = mod;
	in_pcap_interface.init = input_pcap_interface_init;
	in_pcap_interface.open = input_pcap_interface_open;
	in_pcap_interface.read = input_pcap_read;
	in_pcap_interface.close = input_pcap_close;
	in_pcap_interface.cleanup = input_pcap_cleanup;
	in_pcap_interface.interrupt = input_pcap_interrupt;
	res += input_register(&in_pcap_interface);


	static struct input_reg_info in_pcap_file;
	memset(&in_pcap_file, 0, sizeof(struct input_reg_info));
	in_pcap_file.name = "pcap_file";
	in_pcap_file.mod = mod;
	in_pcap_file.init = input_pcap_file_init;
	in_pcap_file.open = input_pcap_file_open;
	in_pcap_file.read = input_pcap_read;
	in_pcap_file.close = input_pcap_close;
	in_pcap_file.cleanup = input_pcap_cleanup;
	in_pcap_file.interrupt = input_pcap_interrupt;
	res += input_register(&in_pcap_file);

	static struct input_reg_info in_pcap_dir;
	memset(&in_pcap_dir, 0, sizeof(struct input_reg_info));
	in_pcap_dir.name = "pcap_dir";
	in_pcap_dir.mod = mod;
	in_pcap_dir.init = input_pcap_dir_init;
	// Do the open at read() time because scanning can take quite some time
	//in_pcap_dir.open = input_pcap_dir_open;
	in_pcap_dir.read = input_pcap_read;
	in_pcap_dir.close = input_pcap_close;
	in_pcap_dir.cleanup = input_pcap_cleanup;
	in_pcap_dir.interrupt = input_pcap_interrupt;
	res += input_register(&in_pcap_dir);

	return res;

}

static int input_pcap_mod_unregister() {

	int res = POM_OK;
	res += input_unregister("pcap_file");
	res += input_unregister("pcap_interface");
	return res;
}

static int input_pcap_common_init(struct input *i) {

	struct input_pcap_priv *priv;
	priv = malloc(sizeof(struct input_pcap_priv));
	if (!priv) {
		pom_oom(sizeof(struct input_pcap_priv));
		return POM_ERR;
	}
	memset(priv, 0, sizeof(struct input_pcap_priv));

	struct registry_param *p = NULL;

	priv->p_filter = ptype_alloc("string");
	if (!priv->p_filter)
		goto err;
		
	p = registry_new_param("bpf_filter", "", priv->p_filter, "BPF filter to use", 0);
	if (registry_instance_add_param(i->reg_instance, p) != POM_OK)
		goto err;

	i->priv = priv;
	
	return POM_OK;
err:

	if (p)
		registry_cleanup_param(p);

	if (priv->p_filter)
		ptype_cleanup(priv->p_filter);

	free(priv);

	return POM_ERR;
}

static int input_pcap_set_filter(pcap_t *p, char *filter) {

	if (strlen(filter) <= 0)
		return POM_OK;

	struct bpf_program fp;

	if (pcap_compile(p, &fp, filter, 1, PCAP_NETMASK_UNKNOWN) == -1) {
		pomlog(POMLOG_ERR "Unable to compile BPF filter \"%s\"", filter);
		return POM_ERR;
	}

	if (pcap_setfilter(p, &fp) == -1) {
		pcap_freecode(&fp);
		pomlog(POMLOG_ERR "Unable to set the BPF filter \"%s\"", filter);
		return POM_ERR;
	}

	pcap_freecode(&fp);

	return POM_OK;
}

static int input_pcap_common_open(struct input *i) {

	struct input_pcap_priv *priv = i->priv;

	if (!priv || !priv->p)
		return POM_ERR;

	char *datalink = "undefined";

	priv->datalink_type = pcap_datalink(priv->p);
	switch (priv->datalink_type) {
		case DLT_IEEE802_11:
			datalink = "80211";
			break;

		case DLT_IEEE802_11_RADIO:
			datalink = "radiotap";
			break;

		case DLT_EN10MB:
			datalink = "ethernet";
			// Ethernet is 14 bytes long
			priv->align_offset = 2;
			break;

		case DLT_DOCSIS:
			datalink = "docsis";
			break;

/*		case DLT_LINUX_SLL:
			datalink = "linux_cooked";
			break;
*/
		case DLT_RAW:
			datalink = "ipv4";
			break;

		case DLT_MPEGTS: // FIXME update this when upstream add it
			datalink = "mpeg_ts";
			break;

		case DLT_PPI:
			datalink = "ppi";
			break;

		case DLT_PPP_WITH_DIR:
			datalink = "ppp";
			priv->skip_offset = 1;
			break;

		default:
			pomlog(POMLOG_ERR "Datalink %s (%u) is not supported", pcap_datalink_val_to_name(priv->datalink_type), priv->datalink_type);
	}

	priv->datalink_proto = proto_get(datalink);

	if (!priv->datalink_proto) {
		pomlog(POMLOG_ERR "Cannot open input pcap : protocol %s not registered", datalink);
		input_pcap_close(i);
		return POM_ERR;
	}


	if (input_pcap_set_filter(priv->p, PTYPE_STRING_GETVAL(priv->p_filter)) != POM_OK) {
		input_pcap_close(i);
		return POM_ERR;
	}

	return POM_OK;

}

/*
 * input pcap type interface
 */

static int input_pcap_interface_init(struct input *i) {

	if (input_pcap_common_init(i) != POM_OK)
		return POM_ERR;

	struct input_pcap_priv *priv = i->priv;
	
	struct registry_param *p = NULL;

	priv->tpriv.iface.p_interface = ptype_alloc("string");
	priv->tpriv.iface.p_promisc = ptype_alloc("bool");
	if (!priv->tpriv.iface.p_interface || !priv->tpriv.iface.p_promisc)
		goto err;

	char err[PCAP_ERRBUF_SIZE] = { 0 };
	char *dev = pcap_lookupdev(err);
	if (!dev) {
		pomlog(POMLOG_WARN "Warning, could not find a suitable interface to sniff packets from : %s", err);
		dev = "none";
	}

	p = registry_new_param("interface", dev, priv->tpriv.iface.p_interface, "Interface to capture packets from", 0);
	if (registry_instance_add_param(i->reg_instance, p) != POM_OK)
		goto err;

	p = registry_new_param("promisc", "no", priv->tpriv.iface.p_promisc, "Promiscious mode", 0);
	if (registry_instance_add_param(i->reg_instance, p) != POM_OK)
		goto err;

	priv->type = input_pcap_type_interface;

	return POM_OK;

err:

	if (priv->tpriv.iface.p_interface)
		ptype_cleanup(priv->tpriv.iface.p_interface);

	if (priv->tpriv.iface.p_promisc)
		ptype_cleanup(priv->tpriv.iface.p_promisc);

	if (p)
		registry_cleanup_param(p);

	free(priv);

	return POM_ERR;

}

static int input_pcap_interface_open(struct input *i) {

	struct input_pcap_priv *p = i->priv;
	char errbuf[PCAP_ERRBUF_SIZE + 1] = { 0 };

	char *interface = PTYPE_STRING_GETVAL(p->tpriv.iface.p_interface);
	char *promisc = PTYPE_BOOL_GETVAL(p->tpriv.iface.p_promisc);

	p->p = pcap_open_live(interface, INPUT_PCAP_SNAPLEN_MAX, *promisc, 0,errbuf);
	if (!p->p) {
		pomlog(POMLOG_ERR "Error opening interface %s : %s", interface, errbuf);
		return POM_ERR;
	}

	return input_pcap_common_open(i);

}

/*
 * input pcap type file
 */

static int input_pcap_file_init(struct input *i) {

	if (input_pcap_common_init(i) != POM_OK)
		return POM_ERR;

	struct input_pcap_priv *priv = i->priv;

	struct registry_param *p = NULL;

	priv->tpriv.file.p_file = ptype_alloc("string");
	if (!priv->tpriv.file.p_file)
		goto err;

	p = registry_new_param("filename", "dump.cap", priv->tpriv.file.p_file, "File in PCAP format", 0);
	if (registry_instance_add_param(i->reg_instance, p) != POM_OK)
		goto err;

	priv->type = input_pcap_type_file;

	return POM_OK;

err:

	if (priv->tpriv.file.p_file)
		ptype_cleanup(priv->tpriv.file.p_file);

	if (p)
		registry_cleanup_param(p);

	free(priv);

	return POM_ERR;
}

static int input_pcap_file_open(struct input *i) {

	struct input_pcap_priv *p = i->priv;
	char errbuf[PCAP_ERRBUF_SIZE + 1] = { 0 };

	char *filename = PTYPE_STRING_GETVAL(p->tpriv.file.p_file);
	p->p = pcap_open_offline(filename, errbuf);
	if (!p->p) {
		pomlog(POMLOG_ERR "Error opening file %s for reading : %s", filename, errbuf);
		return POM_ERR;
	}

	return input_pcap_common_open(i);

}

/*
 * input pcap type dir
 */

static int input_pcap_dir_init(struct input *i) {

	if (input_pcap_common_init(i) != POM_OK)
		return POM_ERR;

	struct input_pcap_priv *priv = i->priv;

	struct registry_param *p = NULL;
	priv->tpriv.dir.p_dir = ptype_alloc("string");
	priv->tpriv.dir.p_match = ptype_alloc("string");
	if (!priv->tpriv.dir.p_dir || !priv->tpriv.dir.p_match)
		goto err;

	p = registry_new_param("directory", "/tmp", priv->tpriv.dir.p_dir, "Directory containing pcap files", 0);
	if (registry_instance_add_param(i->reg_instance, p) != POM_OK)
		goto err;

	p = registry_new_param("match", "\\.p\\?cap[0-9]*$", priv->tpriv.dir.p_match, "Match files with the specific pattern (regex)", 0);
	if (registry_instance_add_param(i->reg_instance, p) != POM_OK)
		goto err;

	priv->type = input_pcap_type_dir;
	
	return POM_OK;

err:
	
	if (priv->tpriv.dir.p_dir)
		ptype_cleanup(priv->tpriv.dir.p_dir);

	if (p)
		registry_cleanup_param(p);

	free(priv); 

	return POM_ERR;
}

static int input_pcap_dir_open(struct input *i) {

	struct input_pcap_priv *p = i->priv;

	struct input_pcap_dir_priv *dp = &p->tpriv.dir;

	// Reset the interrupt flag
	dp->interrupt_scan = 0;

	pomlog(POMLOG_INFO "Scanning directory %s for pcap files ...", PTYPE_STRING_GETVAL(dp->p_dir));

	int found = input_pcap_dir_browse(p);

	if (dp->interrupt_scan)
		return POM_ERR;

	if (found == POM_ERR)
		return POM_ERR;

	pomlog(POMLOG_INFO "Found %u files", found);
	
	dp->cur_file = dp->files;

	// Skip files which were not read
	while (dp->cur_file && !dp->cur_file->first_pkt)
		dp->cur_file = dp->cur_file->next;

	if (!dp->cur_file) {
		pomlog(POMLOG_ERR "No useable file found");
		return POM_ERR;
	}

	char errbuf[PCAP_ERRBUF_SIZE + 1] = { 0 };
	p->p = pcap_open_offline(dp->cur_file->full_path, errbuf);
	if (!p->p) {
		pomlog(POMLOG_ERR "Error opening %s for reading", dp->cur_file->full_path);
		return POM_ERR;
	}

	pomlog("Reading file %s", dp->cur_file->filename);

	return input_pcap_common_open(i);
}

static int input_pcap_dir_browse(struct input_pcap_priv *priv) {

	// Open the directory
	char *path = PTYPE_STRING_GETVAL(priv->tpriv.dir.p_dir);

	DIR *dir = opendir(path);
	if (!dir) {
		pomlog(POMLOG_ERR "Error while opening directory %s : %s", path, pom_strerror(errno));
		return POM_ERR;
	}

	// Compile the regex used to match files
	char *match = PTYPE_STRING_GETVAL(priv->tpriv.dir.p_match);
	regex_t preg;
	int errcode = regcomp(&preg, match, REG_NOSUB);

	if (errcode) {
		char errbuf[256] = { 0 };
		regerror(errcode, &preg, errbuf, sizeof(errbuf) - 1);
		pomlog(POMLOG_ERR "Error while compiling regex \"%s\" : %s", match, errbuf);
		return POM_ERR;
	}


	// Browse the given directory
	struct dirent *buf, *de;
	size_t len = offsetof(struct dirent, d_name) + pathconf(path, _PC_NAME_MAX) + 1;
	buf = malloc(len);

	int tot_files = 0;

	while (!priv->tpriv.dir.interrupt_scan) {

		int res = readdir_r(dir, buf, &de);
		if (res) {
			pomlog(POMLOG_ERR "Error while reading directory entry : %s", pom_strerror(errno));
			regfree(&preg);
			free(buf);
			closedir(dir);
			return POM_ERR;
		}

		if (!de)
			break;

		// Match our file against regex
		if (regexec(&preg, buf->d_name, 1, NULL, 0)) {
			pomlog(POMLOG_DEBUG "Discarding file %s, regular expression not matched", buf->d_name);
			continue;
		}

		// Check if we already know about that file
		struct input_pcap_dir_file *tmp = priv->tpriv.dir.files;
		int found = 0;
		while (tmp) {
			if (!strcmp(tmp->filename, buf->d_name)) {
				found = 1;
				break;
			}
			tmp = tmp->next;
		}
		if (found)
			continue;


		// We don't know about this file, parse it
		char errbuf[PCAP_ERRBUF_SIZE + 1];

		// Alloc the new file
		struct input_pcap_dir_file *cur = malloc(sizeof(struct input_pcap_dir_file));
		if (!cur) {
			free(cur->full_path);
			regfree(&preg);
			pom_oom(sizeof(struct input_pcap_dir_file));
			return POM_ERR;
		}
		memset(cur, 0, sizeof(struct input_pcap_dir_file));

		cur->full_path = malloc(strlen(path) + strlen(buf->d_name) + 2);
		if (!cur->full_path) {
			regfree(&preg);
			pom_oom(strlen(path) + strlen(buf->d_name) + 2);
			return POM_ERR;
		}
		strcpy(cur->full_path, path);
		if (*cur->full_path && cur->full_path[strlen(cur->full_path) - 1] != '/')
			strcat(cur->full_path, "/");
		cur->filename = cur->full_path + strlen(cur->full_path);
		strcat(cur->full_path, buf->d_name);

		// Get the time of the first packet
		pcap_t *p = pcap_open_offline(cur->full_path, errbuf);
		if (!p) {
			cur->next = priv->tpriv.dir.files;
			priv->tpriv.dir.files = cur; // Add at the begning in order not to process it again
			pomlog(POMLOG_WARN "Unable to open file %s : %s", cur->full_path, errbuf);
			continue;
		}
	
		if (input_pcap_set_filter(priv->p, PTYPE_STRING_GETVAL(priv->p_filter)) != POM_OK) {
			cur->next = priv->tpriv.dir.files;
			priv->tpriv.dir.files = cur; // Add at the begning in order not to process it again
			pomlog(POMLOG_WARN "Could not set filter on file %s", cur->full_path);
			continue;
		}

		const u_char *next_pkt;
		struct pcap_pkthdr *phdr;

		int result = pcap_next_ex(p, &phdr, &next_pkt);

		if (result <= 0) {
			cur->next = priv->tpriv.dir.files;
			priv->tpriv.dir.files = cur; // Add at the begning in order not to process it again
			pomlog(POMLOG_WARN "Could not read first packet from file %s", cur->full_path);
			free(cur->full_path);
			pcap_close(p);
			continue;
		}

		cur->first_pkt = pom_timeval_to_ptime(phdr->ts);
		pcap_close(p);

		// Add the packet at the right position
		tmp = priv->tpriv.dir.files;

		if (!tmp || (tmp && (cur->first_pkt < tmp->first_pkt))) {
			// Add at the begining
			cur->next = priv->tpriv.dir.files;
			priv->tpriv.dir.files = cur;

		} else {
			while (tmp->next) {
				if (cur->first_pkt < tmp->next->first_pkt) {
					// Add in the middle
					cur->next = tmp->next;
					tmp->next = cur;
					break;
				}
				tmp = tmp->next;
			}

			if (!tmp->next) {
				// Add at the end
				tmp->next = cur;
			}
		}


		pomlog(POMLOG_DEBUG "Added file %s to the list", cur->full_path);
		tot_files++;

	}

	regfree(&preg);
	free(buf);

	closedir(dir);

	if (priv->tpriv.dir.interrupt_scan)
		return 0;

	return tot_files;

}

static int input_pcap_dir_open_next(struct input_pcap_priv *p) {

	struct input_pcap_dir_priv *dp = &p->tpriv.dir;

	int rescanned = 0;
	do {
		if (!dp->cur_file->next) { // No more file
			if (!rescanned) {
				// Rescan the directory for possible new files
				pomlog(POMLOG_INFO "Rescanning directory %s for pcap files ...", PTYPE_STRING_GETVAL(dp->p_dir));
				int new_found = input_pcap_dir_browse(p);
				if (dp->interrupt_scan)
					return POM_OK;
				if (new_found == POM_ERR)
					return POM_ERR;
				pomlog(POMLOG_INFO "Found %u new files", new_found);
				rescanned = 1;
				continue;
			} else {
				dp->cur_file = NULL;
				return POM_OK;
			}
		}

		dp->cur_file = dp->cur_file->next;


		char errbuf[PCAP_ERRBUF_SIZE + 1] = { 0 };
		p->p = pcap_open_offline(dp->cur_file->full_path, errbuf);
		if (!p->p || input_pcap_set_filter(p->p, PTYPE_STRING_GETVAL(p->p_filter)) != POM_OK) {
			pomlog(POMLOG_ERR "Error while opening next file %s in the directory : %s. Skipping", dp->cur_file->filename, errbuf);
			continue;
		}

		if (input_pcap_set_filter(p->p, PTYPE_STRING_GETVAL(p->p_filter)) != POM_OK) {
			pomlog(POMLOG_ERR "Error while setting filter on file %s", dp->cur_file->filename);
			continue;
		}

		// Make sure this file has the same datalink as the previous one
		if (pcap_datalink(p->p) == p->datalink_type)
			break;

		pcap_close(p->p);
		p->p = NULL;
		pomlog(POMLOG_WARN "Skipping file %s as it doesn't have the same datalink type as the previous ones", dp->cur_file->filename);

	} while (1);

	pomlog("Reading file %s", dp->cur_file->filename);

	return POM_OK;
}

/*
 * common input pcap functions
 */

static int input_pcap_read(struct input *i) {

	struct input_pcap_priv *p = i->priv;

	if (p->type == input_pcap_type_dir && !p->tpriv.dir.files) {
		if (input_pcap_dir_open(i) != POM_OK) {
			// Don't error out if the scan was interrupted
			if (p->tpriv.dir.interrupt_scan)
				return POM_OK;
			return POM_ERR;
		}
	}

	struct pcap_pkthdr *phdr;
	const u_char *data;
	int result = pcap_next_ex(p->p, &phdr, &data);
	if (phdr->len > phdr->caplen && !p->warning) {
		pomlog(POMLOG_WARN "Warning, some packets were truncated at capture time on input %s", i->name);
		p->warning = 1;
	}

	if (result < 0) { // End of file or error 

		if (p->type == input_pcap_type_dir) {

			if (result != -2)
				pomlog(POMLOG_WARN "Error while reading packet from file : %s. Moving on the next file ...", pcap_geterr(p->p), p->tpriv.dir.cur_file->filename);
			
			pcap_close(p->p);
			p->p = NULL;
			p->warning = 0;

			if (input_pcap_dir_open_next(p) != POM_OK)
				return POM_ERR;

			if (!p->tpriv.dir.cur_file) {
				// No more file
				return input_stop(i);
			}

			result = pcap_next_ex(p->p, &phdr, &data);
			if (result < 0) {
				pomlog(POMLOG_ERR "Error while reading first packet of new file");
				return POM_ERR;
			}
		} else {
			if (result == -2) // EOF
				return input_stop(i);

			pomlog(POMLOG_ERR "Error while reading file : %s", pcap_geterr(p->p));
			return POM_ERR;
		}
	}

	if (result == 0) // Timeout
		return POM_OK;

	struct packet *pkt = packet_alloc();
	if (!pkt)
		return POM_ERR;

	if (packet_buffer_alloc(pkt, phdr->caplen - p->skip_offset, p->align_offset) != POM_OK) {
		packet_release(pkt);
		return POM_ERR;
	}

	pkt->input = i;
	pkt->datalink = p->datalink_proto;
	pkt->ts = pom_timeval_to_ptime(phdr->ts);
	memcpy(pkt->buff, data + p->skip_offset, phdr->caplen - p->skip_offset);

	unsigned int flags = 0, affinity = 0;

	if (p->type == input_pcap_type_interface)
		flags = CORE_QUEUE_DROP_IF_FULL;

	if (p->datalink_type == DLT_MPEGTS) {
		// MPEG2 TS has thread affinity based on the PID
		flags |= CORE_QUEUE_HAS_THREAD_AFFINITY;
		affinity = ((((char*)pkt->buff)[1] & 0x1F) << 8) | ((char *)pkt->buff)[2];
	}

	return core_queue_packet(pkt, flags, affinity);
}

static int input_pcap_close(struct input *i) {

	struct input_pcap_priv *priv = i->priv;

	if (priv->p) {
		pcap_close(priv->p);
		priv->p = NULL;
	}

	priv->datalink_proto = NULL;
	priv->align_offset = 0;
	priv->skip_offset = 0;

	if (priv->type == input_pcap_type_dir) {
		struct input_pcap_dir_priv *dp = &priv->tpriv.dir;
		while (dp->files) {
			struct input_pcap_dir_file *tmp = dp->files;
			dp->files = tmp->next;
			free(tmp->full_path);
			free(tmp);
		}
	}

	return POM_OK;
}

static int input_pcap_cleanup(struct input *i) {

	struct input_pcap_priv *priv;
	priv = i->priv;
	if (priv->p)
		pcap_close(priv->p);
	switch (priv->type) {
		case input_pcap_type_interface:
			ptype_cleanup(priv->tpriv.iface.p_interface);
			ptype_cleanup(priv->tpriv.iface.p_promisc);
			break;
		case input_pcap_type_file:
			ptype_cleanup(priv->tpriv.file.p_file);
			break;
		case input_pcap_type_dir:
			ptype_cleanup(priv->tpriv.dir.p_dir);
			ptype_cleanup(priv->tpriv.dir.p_match);
			break;

	}
	ptype_cleanup(priv->p_filter);
	free(priv);

	return POM_OK;

}

static int input_pcap_interrupt(struct input *i) {

	struct input_pcap_priv *priv = i->priv;
	if (priv->type == input_pcap_type_dir)
		priv->tpriv.dir.interrupt_scan = 1;

	if (priv->p)
		pcap_breakloop(priv->p);
	pthread_kill(i->thread, SIGCHLD);
	return POM_OK;
}
