/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/stat.h>
#include <signal.h>
#include "formats.h"
#include "netframe.h"
#include "hexval.h"
#include "squirrel.h"
#include "sqdb/sqdb2.h"
#include "mongoose.h"
#include "pixie.h"
#include "sprintf_s.h"

#ifdef WIN32
#include <direct.h> /* for Posix mkdir() */
#else
#include <unistd.h>
#endif

#include "pcapfile.h"
#include "pcaplive.h"
#include "mystring.h"

/**
 * This structure is initialized with 'pcap_init()' at the beginning
 * of the 'main()' function to runtime load the libpcap library.
 */
struct PCAPLIVE pcap;
pcap_if_t *alldevs;

enum {
	FERRET_SNIFF_NONE,
	FERRET_SNIFF_ALL,
	FERRET_SNIFF_MOST,
	FERRET_SNIFF_IVS,
	FERRET_SNIFF_SIFT
};

void SQUIRREL_EVENT(const char *msg, ...)
{
#if 0
	va_list marker;
	va_start(marker, msg);
	vfprintf(stderr, msg, marker);
	va_end(marker);
#endif
}

void FRAMERR(struct NetFrame *frame, const char *msg, ...)
{
	va_list marker;
	va_start(marker, msg);

	fprintf(stderr, "%s(%d): ", frame->filename, frame->frame_number);

	vfprintf(stderr, msg, marker);

	va_end(marker);
}


void *squirrel_create()
{
	struct Squirrel *result;

	result = (struct Squirrel*)malloc(sizeof(*result));
	memset(result, 0, sizeof(*result));

	result->sqdb = sqdb_create();
	result->cs = pixie_initialize_critical_section();
	return result;
}
void squirrel_destroy(struct Squirrel *squirrel)
{
	free(squirrel);
}



int debug=1;




unsigned control_c_pressed=0;

void control_c_handler(int sig)
{
	control_c_pressed = 1;
}
void sigpipe_handler(int sig){
    
    fprintf(stderr, "\nCaught signal SIGPIPE %d\n\n",sig);
}



/**
 * Verifies that a directory exists, this will create the directory
 * if necessary.
 */
int verify_directory(const char *dirname)
{
	char part[256];
	size_t i;
	struct stat s;

	/* Starting condition: when it starts with a slash */
	i=0;
	if (dirname[i] == '/' || dirname[i] == '\\')
		i++;

	/* move forward until next slash */
again:
	while (dirname[i] != '\0' && dirname[i] != '/' && dirname[i] != '\\')
		i++;
	memcpy(part, dirname, i);
	part[i] = '\0';


	/* Make sure it exists */
	if (stat(part, &s) != 0) {
#ifdef WIN32
		_mkdir(part);
#else
		mkdir(part, 0777);
#endif
	} else if (!(s.st_mode & S_IFDIR)) {
		fprintf(stderr, "%s: not a directory\n", part);
		return -1;
	}

	if (dirname[i] == '\0')
		return 0;
	else {
		while (dirname[i] == '/' || dirname[i] == '\\')
			i++;
		goto again;
	}
}

/**
 * This is a small packet sniffer function that either sniffs
 * all packets, most of them (ignoring common repeats, like beacon
 * frames), just the IVS for WEP cracking, or just the ones that
 * trigger data to be generated.
 *
 * The packets are appended to rotating logfiles in the specified
 * directory.
 */
void sniff_packets(struct Squirrel *squirrel, const unsigned char *buf, const struct NetFrame *frame)
{
	time_t now;
	struct tm *ptm;


	/* First, test if we are allowed to capture this packet into a file */
	switch (squirrel->output.sniff) {
	case FERRET_SNIFF_NONE:
		return;
	case FERRET_SNIFF_ALL:
		break;
	case FERRET_SNIFF_MOST:
		if (frame->flags.found.repeated)
			return;
		break;
	case FERRET_SNIFF_IVS:
		if (!frame->flags.found.ivs)
			return;
		break;
	case FERRET_SNIFF_SIFT:
		if (!squirrel->something_new_found)
			return;
		break;
	default:
		return;
	}


	/* If we don't have a file open for sniffing, then open one. Also,
	 * if the linktype changes, we need to close the previous file we
	 * were writing to and open a new one to avoid mixing frames incorrectly.
	 */
	if (squirrel->output.pf == NULL || squirrel->output.linktype != squirrel->linktype) {
		char filename[256];
		char linkname[16];

		if (squirrel->output.pf) {
			pcapfile_close(squirrel->output.pf);
			squirrel->output.pf = NULL;
		}

		switch (squirrel->linktype) {
		case 1:
			strcpy_s(linkname, sizeof(linkname), "eth");
			break;
		case 0x69:
			strcpy_s(linkname, sizeof(linkname), "wifi");
			break;
		default:
			sprintf_s(linkname, sizeof(linkname), "%d", squirrel->linktype);
			break;
		}



		/* Format the current time */
		now = time(0);
		ptm = localtime(&now);

		if (squirrel->output.filename[0]) {
			strcpy_s(filename, sizeof(filename), squirrel->output.filename);
		} else {
			/* make sure we have a directory name */
			if (squirrel->output.directory[0] == '\0') {
				squirrel->output.directory[0] = '.';
				squirrel->output.directory[1] = '\0';
			}
			/* Make sure the directory exists */
			if (verify_directory(squirrel->output.directory) == -1) {
				/* oops, error creating directory, so just exit */
				return;
			}

			sprintf_s(filename, sizeof(filename), "%s/sniff-%04d-%02d-%02d-%s.pcap",
				squirrel->output.directory,
				ptm->tm_year+1900,
				ptm->tm_mon+1,
				ptm->tm_mday,
				linkname
				);
		}

		/*
		 * Normally, we append to files (because we need to keep so many open,
		 * we temporarily close some).
		 */
		if (squirrel->output.noappend)
			squirrel->output.pf = pcapfile_openwrite(filename, squirrel->linktype);
		else
			squirrel->output.pf = pcapfile_openappend(filename, squirrel->linktype);


		squirrel->output.linktype = squirrel->linktype;
		squirrel->output.pf_opened = time(0); /* now */
	}


	if (squirrel->output.pf) {
		if (squirrel->filter.is_filtering && !frame->flags.found.filtered)
			return;

		pcapfile_writeframe(squirrel->output.pf, buf, frame->captured_length, frame->original_length,
			frame->time_secs, frame->time_usecs);

		/* Close the file occasionally to make sure it's flushed to the disk */
		if (!squirrel->output.noappend)
		if (squirrel->output.pf_opened+600 < time(0)) {
			pcapfile_close(squirrel->output.pf);
			squirrel->output.pf = NULL;
		}
	}

	

}
int
ferret_filter_mac(struct Squirrel *squirrel, const unsigned char *mac_addr)
{
	unsigned i;

	for (i=0; i<squirrel->filter.mac_address_count; i++) {
		if (memcmp(mac_addr, squirrel->filter.mac_address[i], 6) == 0)
			return 1;
	}
	return 0;
}


void
squirrel_frame(struct Squirrel *squirrel,
               struct NetFrame *frame,
               const unsigned char *px, unsigned length)
{
	/* Record the current time */
	if (squirrel->now != (time_t)frame->time_secs) {
		squirrel->now = (time_t)frame->time_secs;

		if (squirrel->first == 0)
			squirrel->first = frame->time_secs;

        squirrel->sqdb->kludge.time_stamp = frame->time_secs;
	}

    squirrel->sqdb->kludge.dbm = 0;
    squirrel->sqdb->kludge.channel = 0;

	/* Clear the information that we will set in the frame */
	//squirrel->frame.flags2 = 0;
	frame->flags.clear = 0;
	squirrel->something_new_found = 0;


	switch (frame->layer2_protocol) {
	case 1: /* Ethernet */
		squirrel_ethernet_frame(squirrel, frame, px, length);
		break;
	case 0x69: /* WiFi */
		squirrel_wifi_frame(squirrel, frame, px, length);
		break;
	case 119: /* DLT_PRISM_HEADER */
		/* This was original created to handle Prism II cards, but now we see this
		 * from other cards as well, such as the 'madwifi' drivers using Atheros
		 * chipsets.
		 *
		 * This starts with a "TLV" format, a 4-byte little-endian tag, followed by
		 * a 4-byte little-endian length. This TLV should contain the entire Prism
		 * header, after which we'll find the real header. Therefore, we should just
		 * be able to parse the 'length', and skip that many bytes. I'm told it's more
		 * complicated than that, but it seems to work right now, so I'm keeping it 
		 * this way.
		 */
		if (length < 8) {
			FRAMERR(frame, "unknown linktype = %d (expected Ethernet or wifi)\n", frame->layer2_protocol);
			return;
		}
		if (ex32le(px+0) != 0x00000044) {
			FRAMERR(frame, "unknown linktype = %d (expected Ethernet or wifi)\n", frame->layer2_protocol);
			return;
		} else {
			unsigned header_length = ex32le(px+4);

			if (header_length >= length) {
				FRAMERR(frame, "unknown linktype = %d (expected Ethernet or wifi)\n", frame->layer2_protocol);
				return;
			}

			/*
			 * Ok, we've skipped the Prism header, now let's process the 
			 * wifi packet as we would in any other case. TODO: in the future,
			 * we should parse the Prism header and extract some of the
			 * fields, such as signal strength.
			 */
			squirrel_wifi_frame(squirrel, frame, px+header_length, length-header_length);
		}
		break;

	case 127: /* Radiotap headers */
		if (length < 4) {
			//FRAMERR(frame, "radiotap headers too short\n");
			return;
		}
		{
			unsigned version = px[0];
			unsigned header_length = ex16le(px+2);
			unsigned features = ex32le(px+4);
            unsigned flags = px[16];
			unsigned offset;
            int dbm_noise = 0;
            unsigned lock_quality = 0;

            frame->dbm = 0;

			if (version != 0 || header_length > length) {
				FRAMERR(frame, "radiotap headers corrupt\n");
				return;
			}

			/* If FCS is present at the end of the packet, then change
			 * the length to remove it */
			if (features & 0x4000) {
				unsigned fcs_header = ex32le(px+header_length-4);
				unsigned fcs_frame = ex32le(px+length-4);
				if (fcs_header == fcs_frame)
					length -= 4;
				if (header_length >= length) {
					FRAMERR(frame, "radiotap headers corrupt\n");
					return;
				}
			}

			offset = 8;

			if (features & 0x000001) offset += 8;	/* TSFT - Timestamp */
            if (features & 0x000002) {
                flags = px[offset];
                offset += 1;
                
                /* If there's an FCS at the end, then remove it so that we
                 * don't try to decode it as payload */
                if (flags & 0x10)
                    length -= 4;
            }
			if (features & 0x000004) offset += 1;	/* Rate */	
            if (features & 0x000008 && offset+2<header_length) {
                unsigned channel_frequency = ex16le(px+offset);
                unsigned channel = 0;
                switch (channel_frequency) {
                case 2412: channel = 1; break;
                case 2417: channel = 2; break;
                case 2422: channel = 3; break;
                case 2427: channel = 4; break;
                case 2432: channel = 5; break;
                case 2437: channel = 6; break;
                case 2442: channel = 7; break;
                case 2447: channel = 8; break;
                case 2452: channel = 9; break;
                case 2457: channel =10; break;
                case 2462: channel =11; break;
                case 2467: channel =12; break;
                case 2472: channel =13; break;
                case 2477: channel =14; break;
                }
                squirrel->sqdb->kludge.channel = channel;
                offset += 2;	
            }
            if (features & 0x000008 && offset+2<header_length) {
                /*unsigned channel_flags = ex16le(px+offset);*/
                offset += 2;
            }
			if (features & 0x000010) offset += 2;	/* FHSS */	
			if (features & 0x000020 && offset+1<header_length) {
				frame->dbm = ((signed char*)px)[offset];
                squirrel->sqdb->kludge.dbm = frame->dbm;
                offset += 1;
			}
			if (features & 0x000040 && offset+1<header_length) {
				dbm_noise = ((signed char*)px)[offset];

			}
			if (features & 0x000080 && offset+1<header_length) {
				lock_quality = ((unsigned char*)px)[offset];
			}

            if (flags & 0x40) {
                /* FCS/CRC error */
                return;
            }


			squirrel_wifi_frame(squirrel, frame, px+header_length, length-header_length);

		}
		break;
	default:
		FRAMERR(frame, "unknown linktype = %d (expected Ethernet or wifi)\n", frame->layer2_protocol);
		break;
	}
}

#define REMCONNECTIONS 40960
#define REMBUFSIZE 100000000
struct RemConnection {
	unsigned src_ip;
	unsigned dst_ip;
	unsigned short src_port;
	unsigned short dst_port;
	uint64_t trigger_frame_number; /* the frame number where we create this entry */
	struct RemConnection *next;
};

struct Remember {
	unsigned char buf[REMBUFSIZE];
	unsigned head;
	unsigned tail;
	unsigned top;
	unsigned count;
	uint64_t frame_number;

	struct RemConnection *connections[REMCONNECTIONS];
} *remember;


/**
 * Hashes the TCP connection to start the lookup in our remembrance table
 */
static unsigned rem_hash(struct NetFrame *frame)
{
	unsigned result;

	result = frame->dst_ipv4;
	result ^= frame->src_ipv4*2;
	result ^= frame->dst_port;
	result ^= frame->dst_port*2;

	result &= REMCONNECTIONS-1;
	return result;
}


/**
 * Looks up a connection entry.
 * If this is a "head" frame that passes the filter test, then we
 * create a new entry in this table. If this is a "tail" frame that
 * is being discarded, we test to see if there is an entry in this
 * table. If so, we know that we have a connection entry from BEFORE
 * the trigger event.
 */
static unsigned rem_connection(struct Squirrel *squirrel, struct NetFrame *frame, uint64_t frame_number, unsigned do_track)
{
	unsigned index;
	struct RemConnection **r_record;
	
	index = rem_hash(frame);

	r_record = &remember->connections[index];

	while (*r_record) {
		struct RemConnection *r = *r_record;

		if (   r->src_ip == frame->src_ipv4 
			&& r->dst_ip == frame->dst_ipv4 
			&& r->src_port == frame->src_port 
			&& r->dst_port == frame->dst_port)
			break;

		r_record = &(r->next);
	}


	if (*r_record == NULL) {
		struct RemConnection *r;
		
		/* If 'do_track' is set, then it forces us to create a new entry.
		 * Otherwise, if the connection doens't exist, we don't track it */
		if (!do_track)
			return 0;

		if (frame->src_ipv4==0 && frame->dst_ipv4 == 0)
			return 0; /* don't remember non-IPv4 connections */

		r = (struct RemConnection *)malloc(sizeof(*r));
		memset(r, 0, sizeof(*r));
		r->src_ip = frame->src_ipv4;
		r->dst_ip = frame->dst_ipv4;
		r->src_port = frame->src_port;
		r->dst_port = frame->dst_port;
		r->trigger_frame_number = frame_number; /* the frame number where we create this entry */
		r->next = NULL;
	
		*r_record = r;
		return 1;
	} else {
		if (!do_track && (frame_number > (*r_record)->trigger_frame_number)) {
			/* We are past the trigger packet, therefore remove it
			 * from our table */
			struct RemConnection *r = *r_record;

			*r_record = r->next;
			free(r);
			return 0;
		}
	}
	
	if (frame_number <= (*r_record)->trigger_frame_number)
		return 1;
	return 0;
}




unsigned rem_has_space(struct Squirrel *squirrel, const unsigned char *buf, struct NetFrame *frame)
{
	unsigned space_needed;
	unsigned space_remaining;

	assert(remember->tail < REMBUFSIZE);

	space_needed = sizeof(*frame) + frame->captured_length;
	space_needed += 8 - space_needed%8;


/*
                                 head      tail
                                   V        V
   ...----------+---------+--------+--------+---------+---------+--------...
                | headfrm | headbuf|        | tailfrm | tailbuf |    
   ...----------+---------+--------+--------+---------+---------+--------...
*/

	if (remember->tail > remember->head) {
		space_remaining = remember->tail - remember->head;
		assert(space_remaining < REMBUFSIZE);
	} else if (remember->tail < remember->head) {
		if (remember->head + space_needed < REMBUFSIZE)
			space_remaining = REMBUFSIZE - remember->head;
		else
			space_remaining = remember->tail;
		assert(space_remaining < REMBUFSIZE);
	} else {
		/* start condition where they are the same */
		if (remember->head == 0)
			return 1;
		else
			return 0;
	}

	if (space_needed > space_remaining)
		return 0;
	else
		return 1;
}

void rem_release_packet(struct Squirrel *squirrel)
{
/*
                                 head      tail
                                   V        V
   ...----------+---------+--------+--------+---------+---------+--------...
                | headfrm | headbuf|        | tailfrm | tailbuf |    
   ...----------+---------+--------+--------+---------+---------+--------...
*/
	struct NetFrame *frame = (struct NetFrame*)(remember->buf + remember->tail);
	unsigned next_tail = remember->tail + sizeof(*frame) + frame->captured_length;
	assert(remember->tail < REMBUFSIZE);

	/* See if this frame is part of a triggered TCP connection */
	if (!frame->flags.found.filtered) {
		if (rem_connection(squirrel, frame, remember->frame_number-remember->count, 0))
			frame->flags.found.filtered = 1;
	}

	assert(remember->count > 0);

	next_tail += 8 - next_tail%8;

	sniff_packets(squirrel, remember->buf+remember->tail+sizeof(*frame), frame);

	remember->tail = next_tail;
	if (remember->tail >= remember->top) {
		remember->top = remember->head;
		remember->tail = 0;
	}
	remember->count--;
	//printf("[%d] ", remember->count);
	assert(remember->tail < REMBUFSIZE);
}
void rem_save_packet(struct Squirrel *squirrel, const unsigned char *buf, struct NetFrame *frame)
{
	unsigned new_head;
	assert(remember->tail < REMBUFSIZE);

	remember->frame_number++;

	/* Put trigger packets into the TCP table so that released packets before
	 * the trigger can also be saved to the target capture file */
	if (frame->flags.found.filtered) {
		rem_connection(squirrel, frame, remember->frame_number, 1);
	}

	new_head = remember->head + sizeof(*frame) + frame->captured_length;
	new_head += 8-new_head%8;

	if (new_head > REMBUFSIZE) {
		remember->head = 0;
		new_head = remember->head + sizeof(*frame) + frame->captured_length;
		new_head += 8-new_head%8;
		assert(new_head <= remember->tail);
	}


	memcpy(remember->buf+remember->head, frame, sizeof(*frame));
	remember->head += sizeof(*frame);
	memcpy(remember->buf+remember->head, buf, frame->captured_length);
	remember->head += frame->captured_length;
	remember->head += 8-remember->head%8;
	
	if (remember->top < remember->head)
		remember->top = remember->head;
	
	remember->count++;
	//printf("(%d) ", remember->count);
	assert(remember->tail < REMBUFSIZE);
}

void remember_packet(struct Squirrel *squirrel, const unsigned char *buf, struct NetFrame *frame)
{
	assert(remember->tail < REMBUFSIZE);
	while (!rem_has_space(squirrel, buf, frame)) {
		/*unsigned desired_count = remember->count/2;
		do {*/
			rem_release_packet(squirrel);
		/*} while (remember->count > desired_count);*/
	}
	rem_save_packet(squirrel, buf, frame);
}
void remember_none(struct Squirrel *squirrel)
{
	while (remember->count)
		rem_release_packet(squirrel);
}

static unsigned filtered_out(struct NetFrame *frame, const char *mac_address)
{
	if (frame->src_mac && memcmp(frame->src_mac, mac_address, 6) == 0)
		return 1;
	if (frame->dst_mac && memcmp(frame->dst_mac, mac_address, 6) == 0)
		return 1;
    if (frame->bss_mac == 0 && mac_address == 0)
        return 1;
    if (frame->bss_mac == 0 || mac_address == 0)
        return 0;
	if (frame->bss_mac && memcmp(frame->bss_mac, mac_address, 6) == 0)
		return 1;

	return 0;
}

/**
 * Process a file containing packet capture data.
 */
int process_file(struct Squirrel *squirrel, const char *capfilename)
{
	struct PcapFile *capfile;
	unsigned char buf[2048];
	unsigned linktype;
	unsigned frame_number = 0;
	clock_t last_time = clock();
	uint64_t last_bytes=0;

	/*
	 * Open the capture file
	 */
	capfile = pcapfile_openread(capfilename);
	if (capfile == NULL)
		return 0;
	linktype = pcapfile_datalink(capfile);
	squirrel->linktype = linktype;
	
	//fprintf(stderr,"%s...", capfilename);
	fflush(stderr);

	/*
	 * Read in all the packets
	 */
	for (;;) {
		struct NetFrame frame[1];
		unsigned x;

		memset(frame,0,sizeof(*frame));

		/* Get next frame */
		x = pcapfile_readframe(capfile,
			&frame->time_secs,
			&frame->time_usecs,
			&frame->original_length,
			&frame->captured_length,
			buf,
			sizeof(buf)
			);

		if (x == 0 || clock() > last_time+1000) {
			char xxx[64];
			uint64_t bytes_read = 0;
			unsigned pdone;
			double bps;
			double mbps;
			clock_t this_time = clock();

			pdone = pcapfile_percentdone(capfile, &bytes_read);
			bps = ((int64_t)(bytes_read-last_bytes)) / ((this_time-last_time)/(double)CLOCKS_PER_SEC);
			mbps = bps * 8.0 / 1000000.0;


			sprintf_s(xxx, sizeof(xxx), "%d", pdone);
			//fprintf(stderr, "%3s%% %7.2f-mbps", xxx, (float)mbps);
			//fprintf(stderr, "%.*s", 17, "\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b");
			fflush(stderr);
			last_time = this_time;
			last_bytes = bytes_read;
		}
		if (x == 0)
			break;

		/* Clear the flag. This will be set if the processing finds something
		 * interesting. At that point, we might want to save a copy of the 
		 * frame in a 'sift' file. */
		frame->filename = capfilename;
		frame->layer2_protocol = linktype;
		frame->frame_number = ++frame_number;
        frame->px = buf;

		/*
		 * Analyze the packet
		 */
		squirrel_frame(squirrel, frame, buf, frame->captured_length);
		if (filtered_out(frame, "\x00\x1f\x33\xf8\x92\x2a"))
			continue;
		remember_packet(squirrel, buf, frame);
	}

	/*
	 * Close the file
	 */
	//fprintf(stderr, "100%%\n");
	fflush(stderr);
	pcapfile_close(capfile);

	return 0;
}


/**
 * Provide help, either an overview, or more help on a specific option.
 */
void main_help()
{
	fprintf(stderr,"options:\n");
	fprintf(stderr," -i <adapter>    Sniffs the wire(less) attached to that network adapter. \n");
	fprintf(stderr,"                 Must have libpcap or winpcap installed to work.\n");
	fprintf(stderr," -r <files>      Read files in off-line mode. Can use wildcards, such as \n");
	fprintf(stderr,"                 using \"squirrel -r *.pcap\". Doesn't need libpcap to work.\n");
	fprintf(stderr," -c <file>       Reads in more advanced parameters from a file.\n");
}


unsigned cfg_prefix(const char *name, const char *prefix, unsigned offset)
{
	unsigned i, p;

	if (name[offset] == '.')
		offset++;

	for (i=offset, p=0; name[i] && prefix[p]; i++, p++)
		if (name[i] != prefix[p])
			return 0;
	if (prefix[p] == '\0')
		return i;
	else
		return 0;
}

static unsigned
parse_boolean(const char *value)
{
	switch (value[0]) {
	case '1': /*1*/
	case 'y': /*yes*/
	case 'Y': /*YES*/
	case 'e': /*enabled*/
	case 'E': /*ENABLED*/
	case 't': /*true*/
	case 'T': /*TRUE*/
		return 1;
	case 'o': /*on/off*/
	case 'O': /*ON/OFF*/
		if (value[1] == 'n' || value[1] == 'N')
			return 1;
	}
	return 0;
}
/**
 * Parse a MAC address from hex input. It can be in a number of
 * formats, such as:
 *	[00:00:00:00:00:00]
 *  00-00-00-00-00-00
 *  000000000000
 */
void
parse_mac_address(unsigned char *dst, size_t sizeof_dst, const char *src)
{
	unsigned i=0;
	unsigned found_non_xdigit=0;
	unsigned premature_end=0;

	if (*src == '[')
		src++;

	while (*src && i<6) {
		if (!isxdigit(*src)) {
			found_non_xdigit = 1;
			src++;
		} else {
			unsigned c;

			c = hexval(*src);
			src++;
			if (*src == '\0')
				premature_end=1;
			else if (!isxdigit(*src))
				found_non_xdigit = 1;
			else {
				c = c<<4 | hexval(*src);
				src++;
			}

			if (i<sizeof_dst)
				dst[i++] = (unsigned char)c;
			
			if (*src && ispunct(*src))
				src++;
		}
	}

	if (found_non_xdigit)
		fprintf(stderr, "parse_mac_address: non hex-digit found\n");
}
/**
 * Figures out whether the specified filename is a directory or normal
 * file. This is useful when recursing directories -- such as reading in
 * all packet-capture files in a directory structure for testing.
 */
static int
is_directory(const char *filename)
{
	struct stat s;

	if (stat(filename, &s) != 0) {
		/* Not found, so assume a "file" instead of "directory" */
		return 0;
	} else if (!(s.st_mode & S_IFDIR)) {
		/* Directory flag not set, so this is a "file" not a "directory" */
		return 0;
	}
	return 1;
}

void add_port_filter(unsigned **r_ports, unsigned *r_port_count, unsigned port)
{
	unsigned *new_ports;
	unsigned new_count = *r_port_count + 1;

	if (port >= 65536)
		return;

	new_ports = (unsigned*)malloc(sizeof(unsigned) * (new_count));
	if (*r_ports) {
		memcpy(new_ports, *r_ports, sizeof(unsigned) * (new_count));
		free(*r_ports);
	}
	*r_ports = new_ports;
	new_ports[*r_port_count] = port;
	*r_port_count = new_count;
}

unsigned filter_has_port(unsigned *list, unsigned count, unsigned port)
{
	unsigned i;
	for (i=0; i<count; i++) {
		if (list[i] == port)
			return 1;
	}
	return 0;
}

void 
squirrel_set_parameter(struct Squirrel *squirrel, const char *name, const char *value, unsigned depth)
{
	unsigned x=0;

	if (depth > 10)
		return;
	
	/* This macro is defined to match the leading keyword */
	#define MATCH(str) cfg_prefix(name, str, x) && ((x=cfg_prefix(name, str, x))>0)

	if (MATCH("config")) {
		if (MATCH("echo")) {
			squirrel->cfg.echo = strdup(value);
		} else if (MATCH("quiet")) {
			squirrel->cfg.quiet = parse_boolean(value);
		} else
			fprintf(stderr, "%sunknown parm: %s=%s\n", "ERR:CFG: ", name, value);
    } else
        
    if (MATCH("webroot")) {
        if (squirrel->webroot)
            free(squirrel->webroot);
        squirrel->webroot = strdup(value);
        {
            char foo[512];
            fprintf(stderr, "Set root: %s %s\n", getcwd(foo, sizeof(foo)), squirrel->webroot);
        }
    } else

	if (MATCH("interface")) {
		if (MATCH("checkfcs")) {
			squirrel->cfg.interface_checkfcs = parse_boolean(value);
		} else if (MATCH("scan")) {
			squirrel->cfg.interface_scan = parse_boolean(value);
		} else if (MATCH("interval")) {
			if (MATCH("inactive"))
				squirrel->interface_interval_inactive = (unsigned)strtoul(value,0,0);
			else if (MATCH("active"))
				squirrel->interface_interval_active = (unsigned)strtoul(value,0,0);
			
		}
	} else if (MATCH("vector")) {
		if (MATCH("mode")) {
			if (strcmp(value, "none")==0)
				squirrel->cfg.no_vectors = 1;
		}
	} else if (MATCH("filter")) {
		squirrel->filter.is_filtering = 1;
		if (MATCH("mac")) {
			/* Parse the MAC address in the value field and add it
			 * to the end of our list of MAC address filters.
			 * TODO: we should probably sort these and/or check
			 * for duplicates */
			unsigned char **newfilters = (unsigned char**)malloc((squirrel->filter.mac_address_count+1)*sizeof(unsigned char*));
			unsigned i;
			for (i=0; i<squirrel->filter.mac_address_count; i++)
				newfilters[i] = squirrel->filter.mac_address[i];
			newfilters[i] = (unsigned char*)malloc(6);
			memset(newfilters[i], 0xa3, 6);
			parse_mac_address(newfilters[i], 6, value);
			if (squirrel->filter.mac_address)
				free(squirrel->filter.mac_address);
			squirrel->filter.mac_address = newfilters;
			squirrel->filter.mac_address_count++;
		} else if (MATCH("ssh")) {
			squirrel->filter.is_ssh = 1;
			squirrel->filter.something_tcp = 1;
		} else if (MATCH("tcp")) {
			add_port_filter(&squirrel->filter.tcp_ports, &squirrel->filter.tcp_port_count, (int)strtol(value,0,0));
			squirrel->filter.something_tcp = 1;
		} else if (MATCH("udp")) {
			add_port_filter(&squirrel->filter.udp_ports, &squirrel->filter.udp_port_count, (int)strtol(value,0,0));
		} else if (MATCH("snap.oui")) {
			add_port_filter(&squirrel->filter.snap_ouis, &squirrel->filter.snap_oui_count, (int)strtol(value,0,0));
		} else
			printf("unknowwn filter %s\n", name);
	} else if (MATCH("include")) {
		FILE *fp;
		char line[2048];

		fp = fopen(value, "rt");
		if (fp == NULL) {
			fprintf(stderr, "%sreading configuration file\n", "ERR:CFG: ");
			perror(value);
			return;
		}

		while (fgets(line, sizeof(line), fp)) {
			char *name;
			char *value;

			name = line;
			value = strchr(line, '=');
			if (value == NULL)
				continue;
			*value = '\0';
			value++;

			while (*name && isspace(*name))
				memmove(name, name+1, strlen(name));
			while (*value && isspace(*value))
				memmove(value, value+1, strlen(value));
			while (*name && isspace(name[strlen(name)-1]))
				name[strlen(name)-1] = '\0';
			while (*value && isspace(value[strlen(value)-1]))
				value[strlen(value)-1] = '\0';

			squirrel_set_parameter(squirrel, name, value, depth+1);

		}
	} else if (MATCH("statistics")) {
		squirrel->cfg.statistics_print = parse_boolean(value);
	} else if (MATCH("sniffer")) {
		if (MATCH("dir")) {
			const char *directory_name = value;
			size_t directory_length = strlen(directory_name);
			char *p;

			if (directory_length > sizeof(squirrel->output.directory)-1) {
				fprintf(stderr, "%sparameter too long: %s=%s\n", "ERR:CFG: ", name, value);
				return;
			}
			if (squirrel->output.directory[0]) {
				fprintf(stderr, "%sparameter exists: old: %s=%s\n", "ERR:CFG: ", name, squirrel->output.directory);
				fprintf(stderr, "%sparameter exists: new: %s=%s\n", "ERR:CFG: ", name, value);
				return;
			}

			/* Remove trailing spaces and slashes */
			p = squirrel->output.directory;
			while (*p && (isspace(p[strlen(p)-1]) || p[strlen(p)-1]=='/' || p[strlen(p)-1]=='\\'))
				p[strlen(p)-1] = '\0';

			strcpy_s(squirrel->output.directory, sizeof(squirrel->output.directory), directory_name);
			return;
		} else if (MATCH("filename")) {
			if (is_directory(value)) {
				squirrel_set_parameter(squirrel, "sniffer.directory", value, depth);
				return;
			}
			strcpy_s(squirrel->output.filename, sizeof(squirrel->output.filename), value);
			if (squirrel->output.sniff == FERRET_SNIFF_NONE)
				squirrel->output.sniff = FERRET_SNIFF_MOST;
			if (squirrel->output.noappend == 0)
				squirrel->output.noappend = 1;
		} else if (MATCH("mode")) {
			if (strcmp(value, "all")==0)
				squirrel->output.sniff = FERRET_SNIFF_ALL;
			else if (strcmp(value, "most")==0)
				squirrel->output.sniff = FERRET_SNIFF_MOST;
			else if (strcmp(value, "ivs")==0)
				squirrel->output.sniff = FERRET_SNIFF_IVS;
			else if (strcmp(value, "sift")==0)
				squirrel->output.sniff = FERRET_SNIFF_SIFT;
			else if (strcmp(value, "none")==0)
				squirrel->output.sniff = FERRET_SNIFF_NONE;
			else {
				fprintf(stderr, "%sparameter unknown: %s=%s\n", "ERR:CFG: ", name, value);
				return;
			}
		} else if (MATCH("noappend")) {
			squirrel->output.noappend = parse_boolean(value);
		} else
			fprintf(stderr, "%sunknown parm: %s=%s\n", "ERR:CFG: ", name, value);
	} else if (MATCH("snarfer")) {
		if (MATCH("dir")) {
			const char *directory_name = value;
			size_t directory_length = strlen(directory_name);
			char *p;

			if (directory_length > sizeof(squirrel->snarfer.directory)-1) {
				fprintf(stderr, "%sparameter too long: %s=%s\n", "ERR:CFG: ", name, value);
				return;
			}
			if (squirrel->snarfer.directory[0]) {
				fprintf(stderr, "%sparameter exists: old: %s=%s\n", "ERR:CFG: ", name, squirrel->snarfer.directory);
				fprintf(stderr, "%sparameter exists: new: %s=%s\n", "ERR:CFG: ", name, value);
				return;
			}

			/* Remove trailing spaces and slashes */
			p = squirrel->snarfer.directory;
			while (*p && (isspace(p[strlen(p)-1]) || p[strlen(p)-1]=='/' || p[strlen(p)-1]=='\\'))
				p[strlen(p)-1] = '\0';

			strcpy_s(squirrel->snarfer.directory, sizeof(squirrel->snarfer.directory), directory_name);
			return;
		} else if (MATCH("mode")) {
			if (strcmp(value, "all")==0)
				squirrel->snarfer.mode = FERRET_SNIFF_ALL;
			else if (strcmp(value, "most")==0)
				squirrel->snarfer.mode = FERRET_SNIFF_MOST;
			else if (strcmp(value, "none")==0)
				squirrel->snarfer.mode = FERRET_SNIFF_NONE;
			else {
				fprintf(stderr, "%sparameter unknown: %s=%s\n", "ERR:CFG: ", name, value);
				return;
			}
		} else
			fprintf(stderr, "%sunknown parm: %s=%s\n", "ERR:CFG: ", name, value);

	} else
		fprintf(stderr, "%sunknown parm: %s=%s\n", "ERR:CFG: ", name, value);

}


/**
 * Parse the command-line arguments
 */
static void 
main_args(int argc, char **argv, struct Squirrel *squirrel)
{
	int i;

	for (i=1; i<argc; i++) {
		const char *arg = argv[i];

		/* See if a <name=value> style configuration parameter was 
		 * given on the command-line */
		if (arg[0] != '-' && strchr(argv[i],'=')) {
			char name[256];
			size_t name_length;
			const char *value;
			unsigned j;

			/* Extract the name */
			name_length = strchr(argv[i], '=') - argv[i];
			if (name_length > sizeof(name)-1)
				name_length = sizeof(name)-1;
			memcpy(name, argv[i], name_length);
			while (name_length && isspace(name[name_length-1]))
				name_length--;
			while (name_length && isspace(name[0]))
				memmove(name, name+1, --name_length);
			name[name_length] = '\0';
			for (j=0; j<name_length; j++)
				name[j] = (char)tolower(name[j]);
			
			/* Extract the value */
			value = strchr(argv[i],'=') + 1;
			while (*value && isspace(*value))
				value++;

			/* Set the configuration parameter */
			squirrel_set_parameter(squirrel, name, value,1);

			continue; /*loop to next command-line parameter*/
		}

		if (arg[0] != '-')
			continue;

		if (arg[1] == '-') {
            if (strcasecmp_s(arg, "--server") == 0)
                squirrel_set_parameter(squirrel, "mode", "server", 0);
            else if (strcasecmp_s(arg, "--webroot") == 0)
                squirrel_set_parameter(squirrel, "webroot", argv[++i], 0);
			continue;
		}

		switch (arg[1]) {
		case 'c':
			if (arg[2] == '\0')
				squirrel_set_parameter(squirrel, "include", argv[++i], 0);
			else
				squirrel_set_parameter(squirrel, "include", argv[i]+2, 0);
			break;
		case 'd':
			debug++;
			break;
		case 'h':
		case 'H':
		case '?':
			main_help();
			exit(0);
			break;

		case 'q':
			squirrel_set_parameter(squirrel, "config.quiet", "true", 0);
			break;

		case 'F':
			squirrel_set_parameter(squirrel, "interface.checkfcs", "true", 0);
			break;
		case 'S':
			squirrel_set_parameter(squirrel, "statistics.print", "true", 0);
			break;

		case 'r':
			if (squirrel->is_live) {
				fprintf(stderr,"ERROR: cannot process live and offline data at the same time\n");
				squirrel->is_error = 1;
			}
			squirrel->is_offline = 1;
			if (argv[i][2] == '\0') {
				while (i+1<argc) {
					const char *filename = argv[i+1];
					if (filename[0] == '-' || strchr(filename, '='))
						break;
					else
						i++;
				}
			}
			break;
		case 'i':
			if (squirrel->is_offline) {
				fprintf(stderr,"Cannot process live and offline data at the same time\n");
				squirrel->is_error = 1;
			} else {
				if (arg[2] == '\0' && i+1<argc) {
					strcpy_s(squirrel->interface_name, sizeof(squirrel->interface_name), argv[i+1]);
					i++;
					squirrel->is_live = 1;
					/* TODO: validate*/
				} else if (isdigit(arg[2])) {
					strcpy_s(squirrel->interface_name, sizeof(squirrel->interface_name), arg+2);
					squirrel->is_live = 1;
				} else {
					fprintf(stderr, "%s: invalid argument, expected something like \"-i1\" or \"-i eth0\"\n", argv[i]);
					squirrel->is_error = 1;
				}
			}
			break;
		case 'W':
			squirrel->is_live = 1;
			break;
		case 'w':
			if (arg[2] == '\0')
				squirrel_set_parameter(squirrel, "sniffer.filename", argv[++i], 0);
			else
				squirrel_set_parameter(squirrel, "sniffer.filename", argv[i]+2, 0);
			
			squirrel_set_parameter(squirrel, "sniffer.mode", "most", 0);
			break;
		}
	}
}

static unsigned count_digits(uint64_t n)
{
	unsigned i=0;
	for (i=0; n; i++)
		n = n/10;

	if (i == 0)
		i = 1;
	return i;
}

void
print_stats(const char *str1, unsigned stat1, const char *str2, unsigned stat2)
{
	size_t i;
	unsigned digits;

	/* first number */
	digits = count_digits(stat1);
	fprintf(stderr, "%s", str1);
	for (i=strlen(str1); i<16; i++)
		printf(".");
	for (i=digits; i<11; i++)
		printf(".");
	printf("%d", stat1);

	printf(" ");

	/* second number */
	digits = count_digits(stat2);
	fprintf(stderr, "%s", str2);
	for (i=strlen(str2); i<16; i++)
		printf(".");
	for (i=digits; i<11; i++)
		printf(".");
	printf("%d", stat2);

	printf("\n");
}


extern void display_bssid_list(struct mg_connection *conn, const struct mg_request_info *ri, void *user_data);
extern void display_events_list(struct mg_connection *conn, const struct mg_request_info *ri, void *user_data);
extern void display_probers_list(struct mg_connection *conn, const struct mg_request_info *ri, void *user_data);
extern void display_bssid_item(struct mg_connection *conn, const struct mg_request_info *ri, void *user_data);
extern void display_station_item(struct mg_connection *conn, const struct mg_request_info *ri, void *user_data);
extern void xml_bssid_list(struct mg_connection *c, const struct mg_request_info *ri, void *user_data);
extern void xml_probers_list(struct mg_connection *c, const struct mg_request_info *ri, void *user_data);
extern void display_adapters(struct mg_connection *c, const struct mg_request_info *ri, void *user_data);
extern void display_adapter(struct mg_connection *c, const struct mg_request_info *ri, void *user_data);
extern void display_decode_beacon(struct mg_connection *c, const struct mg_request_info *ri, void *user_data);
extern void display_decode_probe(struct mg_connection *c, const struct mg_request_info *ri, void *user_data);
extern void display_decode_eventpkt(struct mg_connection *c, const struct mg_request_info *ri, void *user_data);
extern void display_decode_xmitpkt(struct mg_connection *c, const struct mg_request_info *ri, void *user_data);

#define X mg_printf

/*===========================================================================
 *===========================================================================*/
void
display_monitor(struct mg_connection *c, const struct mg_request_info *ri, void *user_data)
{
	/*struct Squirrel *squirrel = (struct Squirrel *)user_data;*/
	char errbuf[1024];

	mg_headers_ok(c, "text/html");
	X(c, "Connection: close\r\n");
	X(c, "\r\n");

	//X(c, "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\" \"http://www.w3.org/TR/html4/strict.dtd\">\r\n");
	X(c,"<html>\n");
	X(c,"<head>\n");
	X(c," <title>Squirrel WiFi monitor: Settings</title>\n");
	X(c," <link rel=\"stylesheet\" type=\"text/css\" href=\"squirrel.css\" />\n");
	X(c," <link rel=\"Shortcut Icon\" href=\"favicon.ico\" type=\"image/x-icon\">\n");
	X(c,"</head>\n");
	X(c,"<body>\n");

	X(c, "<table class=\"topmenu\">\n"
			"<tr>\n"
			" <td class=\"logo\"><img src=\"/logo.gif\" border=\"0\" width=\"30\" height=\"30\" alt=\"squirrel\" /></td>\n"
			" <td class=\"title\">squirrel 1.0</td>\n"
			" <td class=\"menu\">\n"
			"   <a href=\"/\">Access-Points</a> | \n"
			"   <a href=\"/stations.html\">Stations</a> | \n"
			"   <a href=\"/settings.html\">Settings</a> | \n"
			"   <a href=\"http://squirrel.erratasec.com/wiki/\">Wiki</a> | \n"
			"   <a href=\"http://squirrel.erratasec.com/forum/\">Forum</a> | \n"
			"   <a href=\"http://squirrel.erratasec.com/help/\">Help</a>\n"
			" </td>\n"
			"</tr>\n"
			"</table>\n");

	if (!pcap.is_available) {
		X(c, "<h1>ERROR: no libpcap</h1>\n");
		X(c, " On Unix, install libpcap from tcpdump site. On Windows, instal WinPcap from WinDump site.\n");
		return;
	} else if (pcap.findalldevs(&alldevs, errbuf) == -1) {
		X(c, "<h1>ERROR: no adapters found</h1>\n");
		X(c, "<p>%s</p>\n", errbuf);
		X(c, "<p>Make sure you have root/administrator privileges</p>\n");
		return;
	} else if (alldevs == NULL) {
		X(c, "<h1>ERROR: no adapters found</h1>\n");
		X(c, "<p>Make sure you have root/administrator privileges</p>\n");
		return;
	} else {
		pcap_if_t *d;
		unsigned i=0;

		/* Print the list */
		X(c, "<table class=\"bssids\">\n");
		X(c, " <tr><th>Index</th><th>Name</th><th>Driver</th><th>Description</th><th>Monitor</th><th>Inject</th></tr>\n");
		for(d=alldevs; d; d=d->next)
		{
			++i;
			X(c, " <tr>\n");
			X(c, "  <td class=\"index\"><a href=\"monitor.php?index=%d\">%d</a></td>\n", i, i);
			X(c, "  <td>%s</td>\n", d->name);
			if (strstr(d->name, "\\airpcap")) {
				X(c, "  <td>airpcap</td>\n\n");  
			} else {
				X(c, "  <td>ndis</td>\n");  
			}
			if (d->description)
				X(c, "  <td>%s</td>\n", d->description);
			else
				X(c, "  <td>%s</td>\n", "");
	
			if (strstr(d->name, "\\airpcap")) {
				X(c, "  <td>yes</td>\n  <td>yes</td>\n");  
			} else {
				X(c, "  <td>no</td>\n  <td>no</td>\n");  
			}
		}
		X(c, "</table>\n");
	}
}

void squirrel_set_interface_status(struct Squirrel *squirrel, const char *devicename, unsigned is_running, unsigned channel)
{
	pixie_enter_critical_section(squirrel->cs);
	{
		unsigned i;
		for (i=0; i<squirrel->adapter_count; i++) {
			if (strcmp(squirrel->adapter[i].name, devicename) == 0) {
				squirrel->adapter[i].is_open = is_running;
				squirrel->adapter[i].channel = channel;
				squirrel->adapter[i].last_activity = time(0);
			}
		}
		if (i < sizeof(squirrel->adapter)/sizeof(squirrel->adapter[0])) {
			memcpy(squirrel->adapter[i].name, devicename, strlen(devicename)+1);
			squirrel->adapter[i].is_open = is_running;
			squirrel->adapter[i].channel = channel;
			squirrel->adapter[i].last_activity = time(0);
			squirrel->adapter_count++;				
		}
	}
	pixie_leave_critical_section(squirrel->cs);
}
unsigned squirrel_get_interface_status(struct Squirrel *squirrel, const char *devicename, unsigned *r_channel)
{
	unsigned is_running = 0;
	pixie_enter_critical_section(squirrel->cs);
	{
		unsigned i;
		for (i=0; i<squirrel->adapter_count; i++) {
			if (strcmp(squirrel->adapter[i].name, devicename) == 0) {
				is_running = squirrel->adapter[i].is_open;
				if (r_channel)
					*r_channel = squirrel->adapter[i].channel;
			}
		}
	}
	pixie_leave_critical_section(squirrel->cs);
	return is_running;
}



void pcapHandlePacket(unsigned char *v_seap, 
    const struct pcap_pkthdr *framehdr, const unsigned char *buf)
{
	static struct NetFrame frame[1];
	struct Squirrel *squirrel = (struct Squirrel*)v_seap;

	memset(frame,0,sizeof(*frame));

	frame->filename = "live";
	frame->layer2_protocol = squirrel->linktype;
	frame->frame_number++;
	
	frame->time_secs = (unsigned)framehdr->ts.tv_sec;
	frame->time_usecs = framehdr->ts.tv_usec;
	frame->original_length = framehdr->len;
	frame->captured_length = framehdr->caplen;
	frame->layer2_protocol = squirrel->linktype;	
    frame->px = buf;

	/* Wrap in try/catch block */
	squirrel_frame(squirrel, frame, buf, frame->captured_length);

	if (filtered_out(frame, "\x00\x1f\x33\xf8\x92\x2a"))
		return;
	if (filtered_out(frame, "\x06\x1f\x33\xf8\x92\x2a"))
		return;

	sniff_packets(squirrel, buf, frame);

}

/**
 * Return the name of the type of link giving it's numeric identifier
 */
const char *
get_link_name_from_type(unsigned linktype)
{
	switch (linktype) {
	case 0: return "UNKNOWN";
	case 1: return "Ethernet";
	case 105: return "WiFi";
	case 109: return "WiFi-Prism";
	case 127: return "WiFi-Radiotap";
	default: return "";
	}
}

/**
 * Configure or re-configure the channel on the specified WiFi interface.
 */
static void
wifi_set_channel(void *hPcap, unsigned channel, const char *interface_name)
{
    fprintf(stderr, "Change channel: %s %d\n", interface_name, channel);
#ifdef __linux
	{
		char cmd[256];
		int result;
		sprintf_s(cmd, sizeof(cmd), "iwconfig %s channel %u\n", interface_name, channel);
		fprintf(stderr, "CHANGE: %s", cmd);
		result = system(cmd);
		if (result != 0)
		    fprintf(stderr, "CHANGE: %s (FAILED)", cmd);
	}
#endif
#ifdef WIN32
	{
		void *h = pcap.get_airpcap_handle(hPcap);
		if (h == NULL) {
			fprintf(stderr, "ERR: Couldn't get Airpcap handle\n");
		} else {
			if (pcap.airpcap_set_device_channel(h, channel) != 1) {
				fprintf(stderr, "ERR: Couldn't set '%s' to channel %d\n", interface_name, channel);
			} else
				fprintf(stderr, "CHANGE: monitoring channel %d on wifi interface %s\n", channel, interface_name);
		}
	}
#endif
#ifdef __APPLE__
    {
        char cmd[256];
        int result;
        sprintf_s(cmd, sizeof(cmd), "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport %s -c%d\n", interface_name, channel);
        fprintf(stderr, "CHANGE: %s", cmd);
        result = system(cmd);
        if (result != 0)
            fprintf(stderr, "CHANGE: %s (FAILED)", cmd);
    }
#endif
}


struct MonitorThread {
	struct Squirrel *squirrel;
	char devicename[256];
	const char *drivername;
};


void squirrel_monitor_thread(void *user_data)
{
	struct MonitorThread *mt = (struct MonitorThread*)user_data;
	struct Squirrel *squirrel = mt->squirrel;
	const char *devicename = mt->devicename;
	/*const char *drivername = mt->drivername;*/
    int traffic_seen = 0;
    int total_packets_processed = 0;
    void *hPcap;
    char errbuf[1024];
	unsigned interface_channel = 0;
	unsigned old_interface_channel;
	clock_t old_scan_time = clock();
	unsigned old_scan_channel = 1;

	fprintf(stderr, "Monitor thread start\n");
	
	/* Get the configured channel, if there is one */
	squirrel_get_interface_status(squirrel, devicename, &interface_channel);

	/*
	 * Open the adapter
	 */
#if 0
	hPcap =  pcap.open_live( devicename,
							4000,				/*snap len*/
							1,					/*promiscuous*/
							10,					/*10-ms read timeout*/
							errbuf
							);
#endif
    hPcap = pcap.create(devicename, errbuf);
    if (hPcap == NULL) {
		squirrel_set_interface_status(squirrel, devicename, 0, interface_channel);
		fprintf(stderr, "%s: %s\n", devicename, errbuf);
		return;
	}
    fprintf(stderr, "set_snaplen\n"); fflush(stderr);
    pcap.set_snaplen(hPcap, 4096);
    pcap.set_promisc(hPcap, 1);
    pcap.set_timeout(hPcap, 10);
    pcap.set_immediate_mode(hPcap, 1);
    
    if (pcap.can_set_rfmon(hPcap) == 1) {
        fprintf(stderr, "%s: setting monitor mode\n", devicename);
        pcap.set_rfmon(hPcap, 1);
        pcap.set_datalink(hPcap, 127);
    }

    pcap.activate(hPcap);
    squirrel_set_interface_status(squirrel, devicename, 1, interface_channel);
    fprintf(stderr, "%s: monitoring\n", devicename);


	squirrel->linktype = pcap.datalink(hPcap);
	fprintf(stderr, "SNIFFING: %s\n", devicename);
	fprintf(stderr, "LINKTYPE: %d %s\n", squirrel->linktype, get_link_name_from_type(squirrel->linktype));


    /* 
	 * MAIN LOOOP
	 *
	 * Sit in this loop forever, reading packets from the network then
	 * processing them.
	 */
	old_interface_channel = interface_channel;
    while (!control_c_pressed) {
        int packets_read;
		unsigned is_running;

		/* See if the interface status is still on. When the user turns off
		 * an adapter, we'll first notice it here */
		is_running = squirrel_get_interface_status(squirrel, devicename, &interface_channel);
		if (!is_running)
			break;

		/* See if the user has changed which interface we are supposed to be
		 * monitoring */
		if (interface_channel != old_interface_channel) {
			if (interface_channel != 0 && interface_channel != (unsigned)-1)
				wifi_set_channel(hPcap, interface_channel, devicename);
			old_interface_channel = interface_channel;
		}

		/* See if are scanning channels */
		if (interface_channel == (unsigned)-1) {
			clock_t new_scan_time = clock();			
			if (new_scan_time > old_scan_time + (CLOCKS_PER_SEC/10)) {
				unsigned new_scan_channel = old_scan_channel + 1;
				if (new_scan_channel > 11)
					new_scan_channel = 1;
				wifi_set_channel(hPcap, new_scan_channel, devicename);
				old_scan_channel = new_scan_channel;
				old_scan_time = new_scan_time;
			}
		}

		packets_read = pcap.dispatch(
								hPcap, /*handle to PCAP*/
								10,        /*next 10 packets*/
								pcapHandlePacket, /*callback*/
								(unsigned char*)squirrel);
		if (packets_read < 0)
			break;
        total_packets_processed += packets_read;
        if (!traffic_seen && total_packets_processed > 0) {
            fprintf(stderr, "Traffic seen\n");
            traffic_seen = 1;
        }
    }

    /* Close the file and go onto the next one */
    pcap.close(hPcap);
	squirrel_set_interface_status(squirrel, devicename, 0, interface_channel);
	printf("****end monitor thread %s****\n", devicename);
}

void launch_thread(struct Squirrel *squirrel, const char *adapter_name)
{
	ptrdiff_t result;
	struct MonitorThread *mt = (struct MonitorThread*)malloc(sizeof(*mt));
	memset(mt, 0, sizeof(*mt));
	sprintf_s(mt->devicename, sizeof(mt->devicename), "%s", adapter_name);
	fprintf(stderr, "Starting monitor thread for \"%s\"\n", adapter_name);
#ifdef WIN32
	mt->drivername = "airpcap";
#endif
	mt->squirrel = squirrel;
	result = pixie_begin_thread(squirrel_monitor_thread, 0, mt);
	if (result != 0)
		fprintf(stderr, "Error starting thread\n");
	else
		fprintf(stderr, "Thread started\n");
}

/**
 * This is the main entry point to the program
 */
#ifndef FERRET_MAIN
#define FERRET_MAIN main
#endif
/*
int main(int argc, char **argv)
*/
int FERRET_MAIN(int argc, char **argv)
{
	int i;
	struct Squirrel *squirrel;

	fprintf(stderr, "-- SQUIRREL 1.0 - 2008 (c) Errata Security\n");
	fprintf(stderr, "-- build = %s %s (%u-bits)\n", __DATE__, __TIME__, (unsigned)sizeof(size_t)*8);

	/*
	 * Register a signal handler for the <ctrl-c> key. This allows
	 * files to be closed gracefully when exiting. Otherwise, the
	 * last bit of data gets corrupted when the user hits <ctrl-c>
	 */
	signal(SIGINT, control_c_handler);
    signal(SIGPIPE, sigpipe_handler);
    
    
	/*
	 * Runtime-load the libpcap shared-object or the winpcap DLL. We
	 * load at runtime rather than loadtime to allow this program to 
	 * be used to process offline content, and to provide more helpful
	 * messages to people who don't realize they need to install PCAP.
	 */
	pcaplive_init(&pcap);
	if (!pcap.is_available) {
		fprintf(stderr,"WinPcap is not available. Please install it from: http://www.winpcap.org/\n");
		fprintf(stderr,"Without WinPcap, you can process capture packet capture files (offline mode), \n");
		fprintf(stderr,"but you will not be able to monitor the network (live mode).\n");
	} else {
		fprintf(stderr,"-- %s\n", pcap.lib_version());
	}


	/*
	 * Create a Squirrel instance. These are essentially the "globals"
	 * of the system. 
	 */
	squirrel = squirrel_create();
	remember = (struct Remember*)malloc(sizeof(*remember));
	memset(remember, 0, sizeof(*remember));
	
	/*
	 * Parse the command-line arguments. This many also parse the configuration
	 * file that contains more difficult options.
	 */
	main_args(argc, argv, squirrel);


	/* 
	 * If the user doesn't specify any options, then print a helpful
	 * message.
	 */
	if (argc <= 1) {
		fprintf(stderr,"Usage:\n");
		fprintf(stderr," squirrel -w <file> -r <file1> <file2> ...   (where <files> contain captured packets)\n");
		fprintf(stderr," squirrel -h						 (for more help)\n");
		return 0;
	}

	/*
	 * Mongoose simple HTTPD
	 */
    {
        void *mongoose_ctx = mg_start();
        mg_set_option(mongoose_ctx, "ports", "1234");
        if (squirrel->webroot)
            mg_set_option(mongoose_ctx, "root", squirrel->webroot);
        
        mg_bind_to_uri(mongoose_ctx, "/", &display_bssid_list, squirrel->sqdb);
        mg_bind_to_uri(mongoose_ctx, "/accesspoints.html", &display_bssid_list, squirrel->sqdb);
        mg_bind_to_uri(mongoose_ctx, "/probers.html", &display_probers_list, squirrel->sqdb);
        mg_bind_to_uri(mongoose_ctx, "/events.html", &display_events_list, squirrel->sqdb);
        mg_bind_to_uri(mongoose_ctx, "/probers.xml", &xml_probers_list, squirrel->sqdb);
        mg_bind_to_uri(mongoose_ctx, "/bssids.xml", &xml_bssid_list, squirrel->sqdb);
        mg_bind_to_uri(mongoose_ctx, "/bssid/*", &display_bssid_item, squirrel->sqdb);
        mg_bind_to_uri(mongoose_ctx, "/station/*", &display_station_item, squirrel->sqdb);
        mg_bind_to_uri(mongoose_ctx, "/adapters.html", &display_adapters, squirrel);
        mg_bind_to_uri(mongoose_ctx, "/adapter/*", &display_adapter, squirrel);
        mg_bind_to_uri(mongoose_ctx, "/beacon/*", &display_decode_beacon, squirrel->sqdb);
        mg_bind_to_uri(mongoose_ctx, "/probe/*", &display_decode_probe, squirrel->sqdb);
        mg_bind_to_uri(mongoose_ctx, "/eventpkt/*", &display_decode_eventpkt, squirrel->sqdb);
        mg_bind_to_uri(mongoose_ctx, "/xmit.html", &display_decode_xmitpkt, squirrel->sqdb);
    }

	for (i=1; i<argc; i++) {
		if (argv[i][0] != '-')
			continue;
		if (argv[i][1] != 'r')
			continue;
		/* Process one or more filenames after the '-r' option */
		if (argv[i][2] != '\0')
			process_file(squirrel, argv[i]+2);
		while (i+1 < argc && argv[i+1][0] != '-' && strchr(argv[i+1],'=') == NULL) {
			process_file(squirrel, argv[i+1]);
			i++;
		}
	}

	remember_none(squirrel);
	if (squirrel->output.pf) {
		pcapfile_close(squirrel->output.pf);
		squirrel->output.pf = NULL;
	}

	if (squirrel->cfg.statistics_print) {
		struct tm *tm_first;
		struct tm *tm_last;
		char sz_first[64], sz_last[64];
		int diff = (int)(squirrel->now-squirrel->first);

		tm_first = localtime(&squirrel->first);
		strftime(sz_first, sizeof(sz_first), "%Y-%m-%d %H:%M:%S", tm_first);
		
		tm_last = localtime(&squirrel->now);
		strftime(sz_last, sizeof(sz_last), "%Y-%m-%d %H:%M:%S", tm_last);

		fprintf(stderr, "Capture started at %s and ended at %s (%d seconds)\n",
				sz_first, sz_last, diff);

	}

	/*FIXME TEMP TODO
	 * Hardcode monitor thread for testing
	 */
	if (squirrel->is_live) {
		printf("5\n");
		fprintf(stderr, "Starting monitor thread\n");
		launch_thread(squirrel, squirrel->interface_name);
	}

	{unsigned i=0;
	while (!control_c_pressed) {
		printf("%c\x08", "|\\-/"[i&0x03]);
		fflush(stdout);
		i++;
		pixie_sleep(1000);
	}
	}

	squirrel_destroy(squirrel);

	return 0;
}
