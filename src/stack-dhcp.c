/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
/*
	DYNAMIC HOST CONFIGURATION PROTOCOL

  DHCP is the protocol that assigns the IP address when a machine connects
  to the network.

  A machine broadcasting requests also tells us things, Some information
  it tells us is:
	- operating system version
	- former IP address (that it is requesting again)
	- hostname
*/
#include "stack-frame.h"
#include "squirrel.h"
#include "util-extract.h"
#include "util-stratom.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "util-annexk.h"
#include "sift.h"

struct DHCP {
	unsigned op;
	unsigned hardware_type;
	unsigned hardware_address_length;
	unsigned hops;
	unsigned transaction_id;
	unsigned seconds_elapsed;
	unsigned flags;

	unsigned ciaddr;		/* client IP address (if client can respond to ARPs */
	unsigned yiaddr;		/* "your" (client) IP address */
	unsigned siaddr;		
	unsigned giaddr;		/* Relay agent IP address, used when router relays packets */ 
	unsigned char chaddr[20];	/* client hardware address */
	unsigned sname[68];		/* Optional server host name */
	unsigned char file[130];	/* Optional boot file name */

	unsigned msg;
	unsigned server_identifier;
	unsigned rfc2563_auto_configure;	/* 1=yes, 2=no*/

	unsigned overload_servername;
	unsigned overload_filename;
};

static void _dhcp_get_option(const unsigned char *px, unsigned length, unsigned offset, unsigned option_tag, const unsigned char **r_option, unsigned *r_option_length, unsigned *r_overload)
{

	while (offset < length) {
		unsigned tag;
		unsigned len;

		tag = px[offset++];
		if (tag == 0xFF)
			break; /*end of list*/
		if (tag == 0x00)
			continue; /*padding*/

		if (offset >= length)
			return;
		len = px[offset++];
		if (offset >= length)
			return;

		if (tag == option_tag)
		{
			*r_option = px+offset;
			*r_option_length = len;
		}

		if (tag == 52) {
			if (len != 1)
				;
			else if (r_overload) {
				*r_overload = px[offset];
			}
		}

		offset += len;
	}
}


static void dhcp_get_option(const unsigned char *px, unsigned length, unsigned option_tag, const unsigned char **r_option, unsigned *r_option_length)
{
	unsigned overload = 0;
	unsigned offset=0;

	*r_option = px;
	*r_option_length = 0;

	offset = 28+16+64+128;

	if (offset+4 > length)
		return;

	if (memcmp(px+offset, "\x63\x82\x53\x63", 4) != 0)
		return;
	offset += 4;

	_dhcp_get_option(px, length, offset, option_tag, r_option, r_option_length, &overload);
	if (overload & 1)
		_dhcp_get_option(px, 28+16+64+128, 28+16+64, option_tag, r_option, r_option_length, 0);
	if (overload & 2)
		_dhcp_get_option(px, 28+16+64, 28+16, option_tag, r_option, r_option_length, 0);
}

void process_dhcp_options(struct Squirrel *squirrel, struct StackFrame *frame, const unsigned char *px, unsigned length, unsigned offset, struct DHCP *dhcp)
{
	while (offset < length) {
		unsigned tag;
		unsigned len;

		tag = px[offset++];
		if (tag == 0xFF)
			break; /*end of list*/
		if (tag == 0x00)
			continue; /*padding*/

		if (offset >= length) {
			FRAMERR(frame, "dhcp: option too short\n");
			break;
		}
		len = px[offset++];
		if (offset >= length) {
			FRAMERR(frame, "dhcp: option too short\n");
			break;
		}

		//SAMPLE(squirrel,"DHCP", JOT_NUM("tag",	 tag));

		switch (tag) {
		case 1: /*0x01 - Subnet tag */
			break;
		case 3: /*Router */
			if (len !=  4)
				FRAMERR(frame, "dhcp: abnormal length, tag=%d, len=%d\n", tag, len);
			else {
				/*unsigned ip = ex32be(px+offset);*/
				/*JOTDOWN(squirrel,
					JOT_SZ("proto", "DHCP"),
					JOT_SRC("server", frame), 
					JOT_SZ("op", "offer"),
					JOT_IPv4("router", ip),
					0);*/
				//FRAMERR(frame, "%s: %s\n", "dhcp", "fixme");
			}
			break;
		case 6: /*DNS server*/
			{
				unsigned i;
				for (i=0; i<len; i+=4) {
					/*unsigned ip = ex32be(px+offset+i);*/
					/*JOTDOWN(squirrel,
						JOT_SZ("proto", "DHCP"),
						JOT_SRC("server", frame),
						JOT_SZ("op", "offer"),
						JOT_IPv4("dns-server", ip),
						0);
					*/
					//FRAMERR(frame, "%s: %s\n", "dhcp", "fixme");
				}
			}
			break;
		case 12: /*0x0c - Hostname */
			if (len ==  0)
				FRAMERR(frame, "dhcp: abnormal length, tag=%d, len=%d\n", tag, len);
			else {
				char *hostname;
				/*JOTDOWN(squirrel,
					JOT_MACADDR("ID-MAC", dhcp->chaddr),
					JOT_SZ("proto", "DHCP"),
					JOT_SZ("op", "Hostname"),
					JOT_PRINT("hostname",	 	px+offset,	len),
					0);*/
				switch (dhcp->op) {
				case 1: /*REF: wifi-2009-02-09.pcap(126) */
				case 2: /*REF: wifi-2009-02-09.pcap(403938) */
					hostname = (char*)malloc(len+1);
					memcpy(hostname, px+offset, len);
					hostname[len] = '\0';
					
					sqdb_add_info(	squirrel->sqdb, 
									frame->src_mac,
									frame->bss_mac,
									"name",
									hostname, -1);
					free(hostname);
					break;
				default:
					FRAMERR(frame, "%s: %s\n", "dhcp", "fixme");
				}
			}
			break;
		case 15: /*0x0f - Domain Name */
			if (len ==  0)
				FRAMERR(frame, "dhcp: abnormal length, tag=%d, len=%d\n", tag, len);
			else {
				char *domain;
				/*JOTDOWN(squirrel,
					JOT_SZ("proto", "DHCP"),
					JOT_SRC("server", frame),
					JOT_SZ("op", "offer"),
					JOT_PRINT("domainname",	 	px+offset,	len),
					0);*/
				switch (dhcp->op) {
				case 1:
					domain = (char*)malloc(len+1);
					memcpy(domain, px+offset, len);
					domain[len] = '\0';
					/*REF: wifi-2009-02-09.pcap(126) */
					sqdb_add_info(	squirrel->sqdb, 
									frame->src_mac,
									frame->bss_mac,
									"domain",
									domain, -1);
					free(domain);
					break;
				case 2:
					domain = (char*)malloc(len+1);
					memcpy(domain, px+offset, len);
					domain[len] = '\0';
					/*REF: wifi-2009-02-09.pcap(165) */
					sqdb_add_info(	squirrel->sqdb, 
									frame->dst_mac, /* server to client */
									frame->bss_mac,
									"domain",
									domain, -1);
					free(domain);
					break;
				default:
					FRAMERR(frame, "%s: %s\n", "dhcp", "fixme");
				}
			}
			break;
		case 31: /*perform router discovery*/
			{
				unsigned discovery=0;
				unsigned i;
				for (i=0; i<len; i++)
					discovery = discovery*10 + px[offset+i];
				/*JOTDOWN(squirrel,
					JOT_SZ("proto", "DHCP"),
					JOT_SRC("server", frame),
					JOT_SZ("op","offer"),
					JOT_NUM("discovery",discovery),
					0);*/
				//FRAMERR(frame, "%s: %s\n", "dhcp", "fixme");
			}
			break;
		case 53: /*0x35 - DHCP message type*/
			if (len != 1) {
				FRAMERR(frame, "dhcp: abnormal length, tag=%d, len=%d\n", tag, len);
				break;
			}
			dhcp->msg = px[offset];

			switch (dhcp->msg) {
			case 2: /*offer*/
			case 5: /*ack*/
                /* Sent from the server, assigning an IP address to the supplicant */
                if (dhcp->yiaddr != 0 && memcmp(dhcp->chaddr, "\0\0\0\0\0\0", 6) != 0) {
                    char iptext[16];
                    sprintf_s(iptext, sizeof(iptext), "%u.%u.%u.%u",
                        (dhcp->yiaddr>>24)&0xFF,
                        (dhcp->yiaddr>>16)&0xFF,
                        (dhcp->yiaddr>> 8)&0xFF,
                        (dhcp->yiaddr>> 0)&0xFF
                        );
					sqdb_add_info(	squirrel->sqdb, 
									dhcp->chaddr,
									frame->bss_mac,
									"ip",
									iptext, -1);
                }
                break;            
			case 1: /*discover*/
			case 3: /*request*/
			case 6: /*nak*/
			case 7: /* release */
			case 8: /*inform*/
				/*SAMPLE(squirrel,"DHCP", JOT_NUM("msg", dhcp->msg));*/
				break;
			default:
				FRAMERR(frame, "dhcp: ungknown msg type %d\n", dhcp->msg);
			}
			break;
		case 55: /* 0x37 - Parameter Request List */
			if (len == 0)
				FRAMERR(frame, "dhcp: abnormal length, tag=%d, len=%d\n", tag, len);
			break;
		case 0x36: /* Server Identifier*/
			if (len != 4) {
				FRAMERR(frame, "dhcp: abnormal option length\n");
				break;
			}
			dhcp->server_identifier = ex32be(px+offset);
			break;
		case 43: /* vendor info*/
			if (len ==  0)
				FRAMERR(frame, "dhcp: abnormal length, tag=%d, len=%d\n", tag, len);
			else {
				/*JOTDOWN(squirrel,
					JOT_MACADDR("ID-MAC", dhcp->chaddr),
					JOT_SZ("proto","DHCP"),
					JOT_SZ("op","Vendor-Info"),
					JOT_PRINT("info",	 	px+offset,	len),
					0);*/
				//FRAMERR(frame, "%s: %s\n", "dhcp", "fixme");
			}
			break;
		case 60: /* 0x3c - Vendor class identifier */
			/*
			 * from: http://support.microsoft.com/kb/
			 *	MSFT 5.0	Microsoft Windows 2000 options	Class that includes all Windows 2000 DHCP clients.
		     *	MSFT 98	Microsoft Windows 98 options	Class that includes all Windows 98 and Microsoft Windows Millennium Edition (Me) DHCP clients.
		     *	MSFT	Microsoft options	Class that includes all Windows 98, Windows Me, and Windows 2000 DHCP clients.
			 */
			if (len ==  0)
				FRAMERR(frame, "dhcp: abnormal length, tag=%d, len=%d\n", tag, len);
			else {
				const char *system = 0;

                SIFT_STRING("dhcp.vendor.class.id", px+offset, len);
                
				if (MATCHES("MSFT 5.0", px+offset, len)) {
					system = "WinXP";
				} else if (MATCHES("MSFT 7.0", px+offset, len)) {
					system = "Win7";
				} else if (MATCHES("MSFT 98", px+offset, len)) {
					system = "Win98";
				} else if (MATCHES("BlackBerry", px+offset, len)) {
					/* REF: sniff-2009-02-09-127.pcap(231297) */
					system = "BlackBerry";
                } else if (len > 8 && memcmp(px+offset, "dhcpcd 4", 8) == 0) {
                    system = "Linux";
                } else if (len > 8 && memcmp(px+offset, "android-", 8) == 0) {
                    system = "Android";
                } else if (len >= 12 && memcmp(px+offset, "dhcpcd-5.5.6", 12) == 0) {
                    system = "Android";
                } else {
                    system = 0;
					FRAMERR(frame, "%s: %s\n", "dhcp", "fixme");
				}
				switch (dhcp->op) {
				case 1:
					if (system) {	
						/*REF: wifi-2009-02-09.pcap(21552) */
						sqdb_add_info(	squirrel->sqdb, 
										frame->src_mac,
										frame->bss_mac,
										"system",
										system, -1);
					} else {
						char *sys;
						sys = (char*)malloc(len+1);
						memcpy(sys, px+offset, len);
						sys[len] = '\0';
						sqdb_add_info(	squirrel->sqdb, 
										frame->src_mac,
										frame->bss_mac,
										"system",
										sys, -1);
						free(sys);
					}
					break;
				default:
					FRAMERR(frame, "%s: %s\n", "dhcp", "fixme");
				}
			}
			break;
		case 61: /* 0x3d - Client identifier */
			if (len < 2)
				FRAMERR(frame, "dhcp: abnormal length, tag=%d, len=%d\n", tag, len);
			else {
				const unsigned char *clientid = px+offset+1;
				switch (px[offset]) {
				case 0:
					break;
				case 1:
					if (len != 7)
						FRAMERR(frame, "dhcp: abnormal length, tag=%d, len=%d\n", tag, len);
					else {
						if (memcmp(dhcp->chaddr, "\0\0\0\0\0\0", 6) == 0) {
							FRAMERR(frame, "untested code path\n");
							memcpy(dhcp->chaddr, clientid, 6);
							dhcp->hardware_type = 1;
							dhcp->hardware_address_length = 6;
						}
						else if (memcmp(dhcp->chaddr, clientid, 6) != 0) {
							/*JOTDOWN(squirrel,
								JOT_MACADDR("ID-MAC", dhcp->chaddr),
								JOT_SZ("proto","DHCP"),
								JOT_SZ("op","Client-ID"),
								JOT_MACADDR("new.mac", clientid),
								0);*/
							FRAMERR(frame, "%s: %s\n", "dhcp", "fixme");
						}
					}
				}
			}
			break;
		case 50: /* 0x32 - Request IP */
			if (len != 4)
				FRAMERR(frame, "dhcp: abnormal length, tag=%d, len=%d\n", tag, len);
			else {
				/*unsigned ip_address = ex32be(px+offset);*/
				char ip_text[16];
				sprintf_s(ip_text, sizeof(ip_text), "%u.%u.%u.%u",
					px[offset+0], px[offset+1], px[offset+2], px[offset+3]
					);
				/*JOTDOWN(squirrel,
					JOT_MACADDR("ID-MAC", dhcp->chaddr),
					JOT_SZ("proto","DHCP"),
					JOT_SZ("op","Request-IP"),
					JOT_IPv4("ip", ip_address),
					0);*/
				switch (dhcp->op) {
				case 1:
					/*REF: wifi-2009-02-09.pcap(126) */
					sqdb_add_info(	squirrel->sqdb, 
									frame->src_mac,
									frame->bss_mac,
									"ip",
									ip_text, -1);
					break;
				default:
					FRAMERR(frame, "%s: %s\n", "dhcp", "fixme");
					break;
				}
			}
			break;
		case 51: /* IP address lease time */
			if (len !=  4)
				FRAMERR(frame, "dhcp: abnormal length, tag=%d, len=%d\n", tag, len);
			else {
				/*unsigned lease_time = ex32be(px+offset);*/
				/*JOTDOWN(squirrel,
					JOT_SZ("proto","DHCP"),
					JOT_SRC("server", frame),
					JOT_SZ("op","offer"),
					JOT_NUM("leasetime",lease_time),
					0);*/
				//FRAMERR(frame, "%s: %s\n", "dhcp", "fixme");
			}
			break;
		case 52: /* Option Overload */
			if (len != 1)
				FRAMERR(frame, "dhcp: abnormal length, tag=%d, len=%d\n", tag, len);
			else {
				if (px[offset] & 1)
					dhcp->overload_filename = 1;
				if (px[offset] & 2)
					dhcp->overload_servername = 1;
			}
			break;
		case 57: /* Mac DHCP message sizey diskless clients to report 1500 so they don't have to reassemble?*/
			break;
		case 81:
			/*
				Code   Len    Flags  RCODE1 RCODE2   Domain Name
			   +------+------+------+------+------+------+--
			   |  81  |   n  |      |      |      |       ...
			   +------+------+------+------+------+------+--
			*/
			if (len < 3)
				FRAMERR(frame, "dhcp: abnormal length, tag=%d, len=%d\n", tag, len);
			else {
				const char *name = (const char*)px+offset+3;
				unsigned name_length = len-3;
                char nametext[128];
                sprintf_s(nametext, sizeof(nametext), "%.*s", name_length, name);

				if (len > 0) {
					/*JOTDOWN(squirrel,
						JOT_MACADDR("ID-MAC", dhcp->chaddr),
						JOT_PRINT("Hostname", name, name_length),
						JOT_SZ("proto","DHCP"),
						JOT_SZ("op","FQDN"),
						0);*/
                    while (*nametext && nametext[strlen(nametext)-1] == '.')
                        nametext[strlen(nametext)-1] = '\0';
					sqdb_add_info(	squirrel->sqdb, 
									frame->src_mac,
									frame->bss_mac,
									"name",
									nametext, -1);
					//FRAMERR(frame, "%s: %s\n", "dhcp", "fixme");
				}				
				/*if (dhcp->op != 1)
					FRAMERR(frame, "implement this code path\n");*/
			}
			break;

		case 116: /*0x74 - Auto-configure */
			if (len != 1) {
				FRAMERR(frame, "dhcp: abnormal option length\n");
				break;
			}
			switch (px[offset]) {
			case 0: dhcp->rfc2563_auto_configure = 2; break;
			case 1: dhcp->rfc2563_auto_configure = 1; break;
			default:
				FRAMERR(frame, "dhcp: bad value, tag=%d, len=%d\n", tag, len);
			}
			break;
		case 44: /* netbios over tcp/ip server */
			break;
		case 58: /* renewal time value */
			break;
		case 59: /* rebinding time value */
			break;
		case 56: /* NAK error message */
			break;
		case 251:/* Private info */
			break;
		case 28: /* broadcast address */
			break;
		default:
			FRAMERR(frame, "dhcp: tag: unknown %d (0x%02x)\n", tag, tag);
			break;
		}


		offset += len;
	}
}

static unsigned dhcp_number(const unsigned char *px, unsigned length, unsigned tag)
{
	unsigned i;
	unsigned result;
	const unsigned char *option;
	unsigned option_length;

	dhcp_get_option(px, length, tag, &option, &option_length);
	if (option_length == 0)
		return 0xFFFFFFFF;
	result = 0;
	for (i=0; i<option_length; i++)
		result = result * 256 + option[i];
	return result;
}


void squirrel_dhcp(struct Squirrel *squirrel, struct StackFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned offset;
	struct DHCP dhcp;

	memset(&dhcp, 0, sizeof(dhcp));
	if (length < 200) {
		FRAMERR(frame, "dhcp: frame too short\n");
		return;
	}

	dhcp.op = px[0];
	dhcp.hardware_type = px[1];
	dhcp.hardware_address_length = px[2];
	dhcp.hops = px[3];

	dhcp.transaction_id = ex32be(px+4);
	dhcp.seconds_elapsed = ex16be(px+8);
	dhcp.flags = ex16be(px+10);

	dhcp.ciaddr = ex32be(px+12);
	dhcp.yiaddr = ex32be(px+16);
	dhcp.siaddr = ex32be(px+20);
	dhcp.giaddr = ex32be(px+24);

	memcpy(dhcp.chaddr, px+28, 16);
	dhcp.chaddr[16] = '\0';

	memcpy(dhcp.sname, px+28+16, 64);
	dhcp.sname[64] = '\0';

	memcpy(dhcp.file, px+28+16+64, 128);
	dhcp.file[128] = '\0';

	offset = 28+16+64+128;

	if (offset+4 > length)
		return;

	if (memcmp(px+offset, "\x63\x82\x53\x63", 4) != 0)
		return;
	offset += 4;

	/* Process special options */
	dhcp.msg = dhcp_number(px, length, 53);
	switch (dhcp.msg) {
	case 8: /* inform */
		/* Process vendor specific information */
		{
			const unsigned char *spec;
			unsigned spec_length;
			const unsigned char *id;
			unsigned id_length;

			dhcp_get_option(px, length, 43, &spec, &spec_length);
			dhcp_get_option(px, length, 60, &id, &id_length);

			if (spec_length && id_length) {
				/*JOTDOWN(squirrel,
					JOT_PRINT("application",	  id, id_length),
					JOT_PRINT("info",			  spec, spec_length),
					0);*/
				//FRAMERR(frame, "%s: %s\n", "dhcp", "fixme");
			}
		}
	}



	process_dhcp_options(squirrel, frame, px, length, offset, &dhcp);

	if (dhcp.overload_filename)
		process_dhcp_options(squirrel, frame, px, 28+16+64+128, 28+16+64, &dhcp);
	if (dhcp.overload_servername)
		process_dhcp_options(squirrel, frame, px, 28+16+64, 28+16, &dhcp);

	//SAMPLE(squirrel,"BOOTP", JOT_NUM("type", dhcp.op));
	switch (dhcp.op) {
	case 1: /*BOOTP request */
		break;
	case 2: /*BOOTP reply*/ 
		switch (dhcp.msg) {
		case 2:
			break;
		case 5: /*ack*/
			break;
		case 6: /*DHCP NACK*/
			{
				const unsigned char *dst_mac;
				unsigned src_ip;

				if (dhcp.hardware_address_length != 6) {
					FRAMERR(frame, "dhcp: expected hardware address length = 6, found length = %d\n", dhcp.hardware_address_length);
					break;
				}
				if (memcmp(dhcp.chaddr, "\0\0\0\0\0\0", 6) == 0) {
					FRAMERR(frame, "dhcp: expected hardware address, but found [00:00:00:00:00:00]\n");
					break;
				} else
					dst_mac = &dhcp.chaddr[0];

				if (dhcp.server_identifier)
					src_ip = dhcp.server_identifier;
				else if (dhcp.siaddr)
					src_ip = dhcp.siaddr;
				else
					src_ip = frame->src_ipv4;

				/*JOTDOWN(squirrel,
					JOT_SZ("proto","DHCP"),
					JOT_SZ("op","NACK"),
					JOT_IPv4("src.ip", src_ip),
					JOT_MACADDR("dst.mac", dst_mac),
					0);*/
				/*REF: sniff-2009-02-09-127.pcap(1082) */
					
				//FRAMERR(frame, "%s: %s\n", "dhcp", "fixme");
			}
			break;
		case 8:
			break;
		default:
			FRAMERR(frame, "dhcp: unknown dhcp msg type %d\n", dhcp.msg);
			break;
		}
		break;
	default:
			FRAMERR(frame, "dhcp: unknown bootp op code %d\n", dhcp.op);
		break;

	}

}

