/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
#include "squirrel.h"
#include "netframe.h"
#include "formats.h"
#include "mystring.h"
#include "sprintf_s.h"
#include <string.h>

/**
 * Looks for a pattern within the payload.
 *
 * TODO: we need to swap this out for the generic pattern-search feature.
 */
unsigned
udp_contains_sz(const unsigned char *px, unsigned length, const char *sz)
{
	unsigned sz_length = (unsigned)strlen(sz);
	unsigned offset=0;

	if (length < sz_length)
		return 0;
	length -= sz_length;

	while (offset<length) {
		if (px[offset] == sz[0] && memcmp(px+offset, sz, sz_length) == 0)
			return 1;
		offset++;
	}

	return 0;
}

void squirrel_udp(struct Squirrel *squirrel, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned offset=0;
	struct {
		unsigned src_port;
		unsigned dst_port;
		unsigned length;
		unsigned checksum;
	} udp;


	if (length == 0) {
		FRAMERR(frame, "udp: frame empty\n");
		return;
	}
	if (length < 8) {
		FRAMERR(frame, "udp: frame too short\n");
		return;
	}

	udp.src_port = ex16be(px+0);
	udp.dst_port = ex16be(px+2);
	udp.length = ex16be(px+4);
	udp.checksum = ex16be(px+6);

	frame->src_port = udp.src_port;
	frame->dst_port = udp.dst_port;

	if (squirrel->filter.udp_port_count) {
		if (filter_has_port(squirrel->filter.udp_ports, squirrel->filter.udp_port_count, udp.src_port))
			frame->flags.found.filtered = 1;
		if (filter_has_port(squirrel->filter.udp_ports, squirrel->filter.udp_port_count, udp.dst_port))
			frame->flags.found.filtered = 1;
	}

	if (udp.length < 8) {
		FRAMERR_TRUNCATED(frame, "udp");
		return;
	}

	if (length > udp.length)
		length = udp.length;

	offset += 8;

	switch (frame->dst_ipv4) {
	case 0xe0000123: /* 224.0.1.35 - SLP */
		if (udp.dst_port == 427)
			;
		else
			FRAMERR(frame, "unknown port %d\n", udp.dst_port);
		return;
	}


	if (length-offset> 12 && (udp.src_port == 2190 || udp.dst_port == 2190)) {
		if (MATCHES("tivoconnect=",px+offset, 12)) {
			;//parse_tivo_broadcast(squirrel, frame, px+offset, length-offset);
			return;
		}
	}


	switch (udp.src_port) {
	case 68:
	case 67:
		squirrel_dhcp(squirrel, frame, px+offset, length-offset);
		break;
	case 53:
		squirrel_dns(squirrel, frame, px+offset, length-offset);
		break;
	case 137:
		squirrel_dns(squirrel, frame, px+offset, length-offset);
		break;
	case 138:
		//squirrel_netbios_dgm(squirrel, frame, px+offset, length-offset);
		break;
	case 389:
		//squirrel_ldap(squirrel, frame, px+offset, length-offset);
		break;
	case 631:
		if (udp.dst_port == 631) {
			; //squirrel_cups(squirrel, frame, px+offset, length-offset);
		}
		break;
	case 1900:
		if (length-offset > 9 && memcasecmp((const char*)px+offset, "HTTP/1.1 ", 9) == 0) {
			; //squirrel_upnp_response(squirrel, frame, px+offset, length-offset);
		}
		break;
	case 14906: /* ??? */
		break;
	case 4500:
		break;
	default:
		switch (udp.dst_port) {
		case 0:
			break;
		case 68:
		case 67:
			;//squirrel_dhcp(squirrel, frame, px+offset, length-offset);
			break;
		case 53:
		case 5353:
			squirrel_dns(squirrel, frame, px+offset, length-offset);
			break;
		case 137:
			squirrel_dns(squirrel, frame, px+offset, length-offset);
			break;
		case 138:
			;//squirrel_netbios_dgm(squirrel, frame, px+offset, length-offset);
			break;
		case 1900:
			if (frame->dst_ipv4 == 0xeffffffa)
				; //parse_ssdp(squirrel, frame, px+offset, length-offset);
			break;
		case 5369:
			break;
		case 29301:
			break;
		case 123:
			break;
		case 5499:
			break;
		case 2233: /*intel/shiva vpn*/
			break;
		case 27900: /* GameSpy*/
			break;
		case 9283:
			//squirrel_callwave_iam(squirrel, frame, px+offset, length-offset);
			break;
		case 161:
			//squirrel_snmp(squirrel, frame, px+offset, length-offset);
			break;
		case 192: /* ??? */
			break;
		case 389:
			//squirrel_ldap(squirrel, frame, px+offset, length-offset);
			break;
		case 427: /* SRVLOC */
			//squirrel_srvloc(squirrel, frame, px+offset, length-offset);
			break;
		case 14906: /* ??? */
			break;
		case 500:
			//squirrel_isakmp(squirrel, frame, px+offset, length-offset);
			break;
		case 2222:
            /* This is the port that Macintosh Microsoft Office send stuff out
             * in order to check for licenses of nearby machines */
            if (frame->dst_ipv4 == 0xFFFFFFFF && frame->ip_ttl == 64) {
                char iptext[16];
                sprintf_s(iptext, sizeof(iptext), "%u.%u.%u.%u",
                    (frame->src_ipv4>>24)&0xFF,
                    (frame->src_ipv4>>16)&0xFF,
                    (frame->src_ipv4>> 8)&0xFF,
                    (frame->src_ipv4>> 0)&0xFF
                    );
			    sqdb_add_info(	squirrel->sqdb, 
							    frame->src_mac,
							    frame->bss_mac,
							    "ip",
							    iptext);
			    sqdb_add_info(	squirrel->sqdb, 
							    frame->src_mac,
							    frame->bss_mac,
							    "system",
							    "MacOS");
            }
			break;
		default:
			if (frame->dst_ipv4 == 0xc0a8a89b || frame->src_ipv4 == 0xc0a8a89b)
				;
			else {
				/*if (smellslike_bittorrent_udp(px+offset, length-offset))
					;
				else
					;*/ /*
				FRAMERR(frame, "udp: unknown, [%d.%d.%d.%d]->[%d.%d.%d.%d] src=%d, dst=%d\n", 
					(frame->src_ipv4>>24)&0xFF,(frame->src_ipv4>>16)&0xFF,(frame->src_ipv4>>8)&0xFF,(frame->src_ipv4>>0)&0xFF,
					(frame->dst_ipv4>>24)&0xFF,(frame->dst_ipv4>>16)&0xFF,(frame->dst_ipv4>>8)&0xFF,(frame->dst_ipv4>>0)&0xFF,
					frame->src_port, frame->dst_port);*/
			}
		}
	}


}

