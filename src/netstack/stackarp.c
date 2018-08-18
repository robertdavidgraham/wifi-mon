/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
/*
	ADDRESS RESOLUTION PROTOCOL

  This protocol is used to discover the local hardware address for machines
  given their IP address.

  Our goal is to report the mapping of IP address to MAC address. Some of the
  bits of data we discover will be tied to a MAC address only (such as wifi
  probes), others will be tied to an IP address.

  TODO: Eventually we'll keep a table of mappings so that we can detect when
  the mappings change, such as when one person logs off and another person
  logs on, and is given the IP address of the previous person. We need to
  create a "break" at this point, so that we don't accidentally associate 
  different people with the same IP address
*/
#include "platform.h"
#include "netframe.h"
#include "formats.h"
#include "../squirrel.h"
#include <stdio.h>
#include "sprintf_s.h"

/*
    Ethernet transmission layer (not necessarily accessible to
	 the user):
	48.bit: Ethernet address of destination
	48.bit: Ethernet address of sender
	16.bit: Protocol type = ether_type$ADDRESS_RESOLUTION
    Ethernet packet data:
	16.bit: (ar$hrd) Hardware address space (e.g., Ethernet,
			 Packet Radio Net.)
	16.bit: (ar$pro) Protocol address space.  For Ethernet
			 hardware, this is from the set of type
			 fields ether_typ$<protocol>.
	 8.bit: (ar$hln) byte length of each hardware address
	 8.bit: (ar$pln) byte length of each protocol address
	16.bit: (ar$op)  opcode (ares_op$REQUEST | ares_op$REPLY)
	nbytes: (ar$sha) Hardware address of sender of this
			 packet, n from the ar$hln field.
	mbytes: (ar$spa) Protocol address of sender of this
			 packet, m from the ar$pln field.
	nbytes: (ar$tha) Hardware address of target of this
			 packet (if known).
	mbytes: (ar$tpa) Protocol address of target.
	*/

void squirrel_arp(struct Squirrel *squirrel, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned layer2_address_type;
	unsigned layer2_address_length;
	unsigned layer3_address_type;
	unsigned layer3_address_length;
	unsigned opcode;
	unsigned ip_src;
	unsigned ip_dst;
	const unsigned char *mac_src;
	const unsigned char *mac_dst;
	char ip_text[16];

	if (length < 8) {
		FRAMERR(frame, "%s: truncated\n", "ARP");
		return;
	}

	layer2_address_type = ex16be(px+0);
	layer3_address_type = ex16be(px+2);
	layer2_address_length = px[4];
	layer3_address_length = px[5];
	opcode = ex16be(px+6);



	if (layer2_address_type != 0x0001) {
		FRAMERR(frame, "%s: unknown\n", "ARP");
	}
	if (layer2_address_length != 0x06) {
		FRAMERR(frame, "%s: unknown\n", "ARP");
		return; /* Even if the type is not Ethernet, we'll continue, but the MAC address must be 6 bytes long, or we fail*/
	}

	if (layer3_address_type != 0x0800) {
		FRAMERR(frame, "%s: unknown\n", "ARP");
		return; /* If it's not IP, then ignore it */
	}
	if (layer3_address_length != 0x04) {
		FRAMERR(frame, "%s: unknown\n", "ARP");
		return; /* If IP addresses are not 4-bytes, then leave. TODO: what about 16 bytes addresses in ARP? */
	}
	if (opcode != 1 && opcode != 2) {
		FRAMERR(frame, "%s: unknown\n", "ARP");
		return;
	}

	mac_src = px+8;
	ip_src = ex32be(px+8+layer2_address_length);
	mac_dst = px+8+layer2_address_length+layer3_address_length;
	ip_dst = ex32be(px+8+layer2_address_length+layer3_address_length+layer2_address_length);

    if (ip_src == 0)
        return;

    switch (opcode) {
    case 1:
    case 2:
		sprintf_s(ip_text, sizeof(ip_text), "%u.%u.%u.%u",
			(ip_src>>24)&0xFF,
			(ip_src>>16)&0xFF,
			(ip_src>> 8)&0xFF,
			(ip_src>> 0)&0xFF
			);
		sqdb_add_info(	squirrel->sqdb, 
						mac_src,
						frame->bss_mac,
						"ip",
						ip_text, -1);
        break;
    }


}

