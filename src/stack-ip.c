/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
#include "squirrel.h"
#include "stack-frame.h"
#include "util-extract.h"

void squirrel_ip(struct Squirrel *squirrel, struct StackFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned offset=0;
	struct {
		unsigned version;
		unsigned header_length;
		unsigned total_length;
		unsigned fragment_length;
		unsigned tos;
		unsigned id;
		unsigned flags;
		unsigned fragment_offset;
		unsigned ttl;
		unsigned protocol;
		unsigned checksum;
		unsigned src_ip;
		unsigned dst_ip;
	} ip;


	if (length == 0) {
		FRAMERR(frame, "ip: frame empty\n");
		return;
	}


	ip.version = px[0]>>4;
	ip.header_length = (px[0]&0xF) * 4;
	ip.tos = ex16be(px+1);
	ip.total_length = ex16be(px+2);
	ip.id = ex16be(px+4);
	ip.flags = px[6]&0xE0;
	ip.fragment_offset = (ex16be(px+6) & 0x3FFF) << 3;
	ip.ttl = px[8];
	ip.protocol = px[9];
	ip.checksum = ex16be(px+10);
	ip.src_ip = ex32be(px+12);
	ip.dst_ip = ex32be(px+16);

	if (ip.fragment_offset != 0)
		return;

	frame->src_ipv4 = ip.src_ip;
	frame->dst_ipv4 = ip.dst_ip;
    frame->ip_ttl = ip.ttl;

	if (ip.version != 4) {
		FRAMERR(frame, "ip: version=%d, expected version=4\n", ip.version);
		return;
	}
	if (ip.header_length < 20) {
		FRAMERR(frame, "ip: header length=%d, expected length>=20\n", ip.header_length);
		return;
	}
	if (ip.header_length > length) {
		FRAMERR(frame, "ip: header length=%d, expected length>=%d\n", length, ip.header_length);
		return;
	}

	if (ip.header_length > 20) {
		unsigned o = 20;
		unsigned max = ip.header_length;

		while (o < ip.header_length) {
			unsigned tag = px[o++];
			unsigned len;

			if (tag == 0)
				break;
			if (tag == 1)
				continue;

			if (o >= max) {
				FRAMERR(frame, "ip: options too long\n");
				break;
			}
			len = px[o++];

			if (len < 2) {
				FRAMERR(frame, "ip: invalid length field\n");
				break;
			}
			if (o+len-2 > max) {
				FRAMERR(frame, "ip: options too long\n");
				break;
			}

			switch (tag) {
			case 0x94: /* alert */
				if (len != 4)
					FRAMERR(frame, "ip: bad length, option=%d, length=%d\n", tag, len);
				if (ex16be(px+o) != 0)
					FRAMERR(frame, "ip: bad value, option=%d, length=%d\n", tag, len);
				break;
			default:
				FRAMERR(frame, "ip: unknown option=%d, length=%d\n", tag, len);
			}

			o += len-2;
		}
	}

	if (ip.total_length < ip.header_length) {
		FRAMERR(frame, "ip: total_length less than header length\n");
		return;
	}

	if (length > ip.total_length) {
		length = ip.total_length;
	}

	offset += ip.header_length;
	if (offset > length) {
		FRAMERR(frame, "ip: header too short, missing %d bytes\n", ip.header_length - length);
		return;
	}


	switch (ip.protocol) {
	case 0x01: /* ICMP */
		//squirrel_icmp(squirrel, frame, px+offset, length-offset);
		break;
	case 0x02: /* IGMP */
		//squirrel_igmp(squirrel, frame, px+offset, length-offset);
		break;
	case 0x11: /* UDP */
		squirrel_udp(squirrel, frame, px+offset, length-offset);
		break;
	case 0x06:
		squirrel_tcp(squirrel, frame, px+offset, length-offset);
		break;
	case 47: /* GRE - Generic Router Encapsulation Protocol */
		//squirrel_gre(squirrel, frame, px+offset, length-offset);
		break;
	case 50: /* ESP - Encapsulated Security Protocol */
		break;
	case 41: /* IPv6 inside IPv4 */
		//squirrel_ipv6(squirrel, frame, px+offset, length-offset);
		break;
    case 103: /* protocol independent multicasat */
        break;
	default:
		FRAMERR(frame, "ip: unknown protocol=%d\n", ip.protocol);
	}

}

