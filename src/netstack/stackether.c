/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
/*
	ETHERNET

  This decodes packets coming from an Ethernet network.

  TODO: we need to support more encapsulations, such as 802.2 SAP
  packets.
*/
#include "../squirrel.h"
#include "formats.h"
#include "netframe.h"
#include <string.h>
#include <stdio.h>

typedef unsigned char MACADDR[6];


void squirrel_ethernet_frame(struct Squirrel *squirrel, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned offset;
	unsigned ethertype;
	unsigned oui;

	if (length <= 14) {
		; /*FRAMERR(frame, "wifi.data: too short\n");*/
		return;
	}

	frame->src_mac = px+6;
	frame->dst_mac = px+0;

	offset = 12;


	/* Look for SAP header */
	if (offset + 6 >= length) {
		FRAMERR(frame, "wifi.sap: too short\n");
		return;
	}

	ethertype = ex16be(px+offset);
	offset += 2;

	switch (ethertype) {
	case 0x0800:
		squirrel_ip(squirrel, frame, px+offset, length-offset);
		break;
	case 0x0806:
		squirrel_arp(squirrel, frame, px+offset, length-offset);
		break;
	case 0x888e: /*802.11x authentication*/
		//squirrel_802_1x_auth(squirrel, frame, px+offset, length-offset);
		break;
	case 0x86dd: /* IPv6*/
		//squirrel_ipv6(squirrel, frame, px+offset, length-offset);
		break;
	case 0x809b:
		//squirrel_ipv6(squirrel, frame, px+offset, length-offset);
		break;
	case 0x872d: /* Cisco OWL */
		break;
	case 0x9000: /* Loopback */
		break;
	default:
		if (ethertype < 1518) {
			if (memcmp(px+offset, "\xaa\xaa\x03", 3) != 0) {
				return;
			}
			offset +=3 ;

			oui = ex24be(px+offset);

			if (squirrel->filter.snap_oui_count) {
				if (filter_has_port(squirrel->filter.snap_ouis, squirrel->filter.snap_oui_count, oui))
					frame->flags.found.filtered = 1;
			}

			/* Look for OUI code */
			switch (oui){
			case 0x000000:
				/* fall through below */
				break;
			case 0x004096: /* Cisco Wireless */
				return;
				break;
			case 0x00000c:
				offset +=3;
                if (offset < length) {
					;//squirrel_cisco00000c(squirrel, frame, px+offset, length-offset);
                }
				return;
			case 0x080007:
				break; /*apple*/
			default:
				FRAMERR(frame, "Unknown SAP OUI: 0x%06x\n", oui);
				return;
			}
			offset +=3;

			/* EtherType */
			if (offset+2 >= length) {
				FRAMERR(frame, "ethertype: packet too short\n");
				return;
			}

		}

		if (ethertype == length-offset && ex16be(px+offset) == 0xAAAA) {
			;
		}
		else
			FRAMERR_BADVAL(frame, "ethertype", ethertype);
	}
}
