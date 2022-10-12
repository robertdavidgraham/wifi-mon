/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
#ifndef __PFILTER_H
#define __PFILTER_H
#ifdef __cplusplus
extern "C" {
#endif
#include <stdio.h>
#include <time.h>
#include "sqdb.h"
enum OutputSniff {
    FERRET_SNIFF_NONE,
    FERRET_SNIFF_ALL,
    FERRET_SNIFF_MOST,
    FERRET_SNIFF_IVS,
    FERRET_SNIFF_SIFT
};

struct TCPENTRY {
	unsigned ip_src;
	unsigned ip_dst;
	unsigned short port_src;
	unsigned short port_dst;
	unsigned first_seqno;
	unsigned packet_count;
	unsigned virtual_port;
	struct TCPENTRY *next;
};

struct Filter {
	unsigned is_filtering;
	unsigned is_ssh:1;
	unsigned something_tcp:1;
	unsigned char **mac_address;
	unsigned mac_address_count;
	unsigned *tcp_ports;
	unsigned tcp_port_count;
	unsigned *udp_ports;
	unsigned udp_port_count;
	unsigned *snap_ouis;
	unsigned snap_oui_count;
};
struct Snarfer {
	char directory[256];
	unsigned mode;

	unsigned id;

	struct {
		char filename[256];
		FILE *fp;
		time_t last_activity;
	} files[32];
	unsigned file_count;
	unsigned max_files;
};
struct Squirrel
{
	void *cs;
	unsigned is_error:1;
	unsigned is_offline:1;
	unsigned is_live:1;
	unsigned is_ignoring_errors:1;
	unsigned is_verbose:1;

    /* The root directory for the web server */
    char *webroot;
    
	union {
		struct {
			unsigned something_found:1;
			unsigned repeated_frame:1;
			unsigned wep_ivs_data:1;
		} flags;
		unsigned flags2;

	} framez;

	unsigned something_new_found;

	unsigned fcs_successes;

	struct Snarfer snarfer;

	/** A structure for doing simple IPv6 fragment reassembly */
	struct IPv6frag *ipv6frags[256];

	/**
	 * Information about the output 
	 */
	struct {
		char directory[256];
		char filename[256];
		char comment[256];
		enum OutputSniff sniff;
		unsigned noappend:1;
		unsigned include_fcs_err:1;
		char current_name[256];
		struct PcapFile *pf;
		time_t pf_opened;
		int linktype;
	} output;

	struct FerretEngine *eng[16];
	unsigned engine_count;


	/**
	 * A structure used when printout out the JavaScript Tree info
	 */
	struct {
		FILE *fp;
	} jtree;

	/**
	 * The adapter index we should listen on when monitoring 
	 * packets live from a network.
	 */
	int linktype;

	/** 
	 * The system that records all the information that we find within
	 * the packets
	 */
	struct Jotdown *jot;


	struct {
		unsigned is_quiet_wifi:1;
		unsigned interface_checkfcs:1;
		unsigned interface_scan:1;
		unsigned no_vectors:1;
		unsigned statistics_print:1;
		unsigned quiet:1; /* global quiet flag that turns off reporting with -q on the command line */
		char *echo;
	} cfg;

	char interface_name[256];
	unsigned interface_channel;

	time_t interface_last_activity;
	time_t now;
	time_t first;
	unsigned interface_interval_inactive;
	unsigned interface_interval_active;

	struct ActiveInterface {
		char name[256];
		unsigned channel;
		time_t last_activity;
		unsigned is_open;
	} adapter[16];
	unsigned adapter_count;

	/**
	 * Streamer
	 */
	struct {
		/** Reflects the total count of segments in the system,
		 * which can be tested against the max number of segments 
		 * to prevent the system from allocating too many */
		unsigned segment_count;

		/** The maximum number of segments possible */
		unsigned max_segments;

		/** A list of freed segments, so we don't have to stress
		 * the malloc()/free() operators too much, we can instead
		 * realloc a recently used segment */
		struct TCP_segment *segments;
	} streamer;

	struct Filter filter;

	struct TCPENTRY *connections[4096];

	struct SQDB *sqdb;
};



int ferret_filter_mac(struct Squirrel *squirrel, const unsigned char *mac_addr);

void squirrel_ethernet_frame(struct Squirrel *squirrel, struct StackFrame *frame, const unsigned char *px, unsigned length);
void squirrel_ip(struct Squirrel *squirrel, struct StackFrame *frame, const unsigned char *px, unsigned length);
void squirrel_arp(struct Squirrel *squirrel, struct StackFrame *frame, const unsigned char *px, unsigned length);
void squirrel_udp(struct Squirrel *squirrel, struct StackFrame *frame, const unsigned char *px, unsigned length);
void squirrel_tcp(struct Squirrel *squirrel, struct StackFrame *frame, const unsigned char *px, unsigned length);
void squirrel_wifi_frame(struct Squirrel *squirrel, struct StackFrame *frame, const unsigned char *px, unsigned length);
void squirrel_dhcp(struct Squirrel *squirrel, struct StackFrame *frame, const unsigned char *px, unsigned length);
void squirrel_dns(struct Squirrel *squirrel, struct StackFrame *frame, const unsigned char *px, unsigned length);

unsigned filter_has_port(unsigned *list, unsigned count, unsigned port);


#define X mg_printf

unsigned squirrel_get_interface_status(struct Squirrel *squirrel, const char *devicename, unsigned *r_channel);
void squirrel_set_interface_status(struct Squirrel *squirrel, const char *devicename, unsigned is_running, unsigned channel);
void launch_thread(struct Squirrel *squirrel, const char *adapter_name);


#ifdef __cplusplus
}
#endif
#endif /*__PFILTER_H*/
