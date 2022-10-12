/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
/*
	NETBIOS NAMEING SERVICE

  This file implements the NetBIOS naming service, a DNS-like protocol
  that runs on UDP port 137.
*/
#include "util-platform.h"
#include "stack-frame.h"
#include "squirrel.h"
#include "util-extract.h"
#include <string.h>
#include <ctype.h>
#include "util-annexk.h"
#include "stack-dns.h"
#include "util-unused.h"

#define TYPECLASS(n,m) ((n)<<16|(m))
#ifndef MIN
#define MIN(a,b) ( (a)<(b) ? (a) : (b) )
#endif

extern unsigned endsWith(const void *v_basestr, const void *v_pattern);


static unsigned
translate_netbios_name(struct StackFrame *frame, const char *name, char *netbios_name, unsigned sizeof_netbios_name)
{
	unsigned j;
	unsigned k;

	UNUSEDPARM(sizeof_netbios_name);

	k=0;
	for (j=0; name[j] && name[j] != '.'; j++) {
		if (name[j] < 'A' || name[j] > 'A'+15)
			FRAMERR(frame, "netbios: bad netbios name char %c (0x%02x) \n", name[j], name[j]);
		netbios_name[k] = (char)((name[j]-'A')<<4);
		j++;
		if (name[j] < 'A' || name[j] > 'A'+15)
			FRAMERR(frame, "netbios: bad netbios name char %c (0x%02x) \n", name[j], name[j]);

		if (name[j] && name[j] != '.')
			netbios_name[k++] |= (char)((name[j]-'A')&0x0F);
	}

	/* handle trailing byte */
	if (k && (!isprint(netbios_name[k-1]) || netbios_name[k-1]== 0x20)) {
		unsigned code = netbios_name[k-1];
		k--;

		while (k && isspace(netbios_name[k-1]))
			k--;
		netbios_name[k++] = '<';
		netbios_name[k++] = "0123456789ABCDEF"[(code>>4)&0x0f];
		netbios_name[k++] = "0123456789ABCDEF"[(code>>0)&0x0f];
		netbios_name[k++] = '>';
	}


	while (name[j] && k<sizeof_netbios_name-1)
		netbios_name[k++] = name[j++];
	netbios_name[k] = '\0';

	return k;
}


static void cleanse_netbios_name(struct StackFrame *frame, const char *name, char *netbios_name, unsigned sizeof_netbios_name)
{
	unsigned j;
	unsigned k;

	UNUSEDPARM(frame);UNUSEDPARM(sizeof_netbios_name);

	k=0;
	for (j=0; j<16; j++) {
		netbios_name[k++] = name[j];
	}
	netbios_name[k] = '\0';

	/* handle trailing byte */
	if (k && (!isprint(netbios_name[k-1]) || isspace(netbios_name[k-1]))) {
		unsigned code = netbios_name[k-1];
		k--;

		while (k && isspace(netbios_name[k-1]))
			k--;
		netbios_name[k++] = '<';
		netbios_name[k++] = "0123456789ABCDEF"[(code>>4)&0x0f];
		netbios_name[k++] = "0123456789ABCDEF"[(code>>0)&0x0f];
		netbios_name[k++] = '>';
	}

	netbios_name[k] = '\0';
}


void netbios_parse_question_record(struct Squirrel *squirrel, struct StackFrame *frame, 
							const unsigned char *px, unsigned length,
							struct DNSRECORD *rec, struct DNS *dns)
{
	char name[512]; /* reserve a longer name than the max theoretical limit */
	unsigned name_length;
	char netbios_name[512];
	unsigned netbios_name_length;
	unsigned ip_address;

	UNUSEDPARM(dns);
    UNUSEDPARM(squirrel);

	name_length = dns_extract_name(frame, px, length, rec->name_offset, name, sizeof(name));

	switch (rec->type<<16 | rec->clss) {
	case TYPECLASS(0x20,1): /* type=NETBIOS, class=INTERNET*/
		if (!is_valid_opcode(dns->opcode, 0, -1)) {
			FRAMERR(frame, "%s: unknown opcode\n", "NetBIOS");
			return;
		}
		ip_address = ex32be(px+rec->rdata_offset);
			
		netbios_name_length = translate_netbios_name(frame, name, netbios_name, sizeof(netbios_name));

		/*JOTDOWN(squirrel,
			JOT_SZ("proto","NETBIOS"),
			JOT_SZ("query","netbios"),
			JOT_SRC("ip.src", frame),
			JOT_PRINT("name",		 	netbios_name,				strlen(netbios_name)),
			JOT_IPv4("address", ip_address),
			0);*/
		break;
	default:
		FRAMERR(frame, "%s: unknown [type=0x%x(%d), class=0x%x(%d)] name=%s)\n", 
				"NetBIOS",
				rec->type, rec->type, 
				rec->clss, rec->clss, 
				name);
	}
}

void netbios_parse_resource_record(struct Squirrel *squirrel, struct StackFrame *frame, 
							const unsigned char *px, unsigned length,
							struct DNSRECORD *rec, struct DNS *dns)
{
	char name[512]; /* reserve a longer name than the max theoretical limit */
	unsigned name_length;
	char name2[512]; /* reserve a longer name than the max theoretical limit */
	unsigned name2_length;
	unsigned ip_address;
	unsigned offset = rec->rdata_offset;
	//unsigned offset_max = MIN(rec->rdata_offset+rec->rdata_length, length);

	name_length = dns_extract_name(frame, px, length, rec->name_offset, name, sizeof(name));
	name2_length = translate_netbios_name(frame, name, name2, sizeof(name2));

	switch (rec->type<<16 | (rec->clss&0x7fFF)) {
	case TYPECLASS(32,1): /* type=NetBIOS, class=INTERNET */
		if (rec->rdata_length%6 != 0)
			FRAMERR(frame, "dns: data not 4-bytes long, was %d-bytes instead (class=%d, type=%d, name=%s)\n", rec->rdata_length, rec->clss, rec->type, name);

		switch (dns->opcode) {
		case 0x05: /* NAME REGISTRATION */
		case 0x08: /* NAME REFRESH, basically a re-registration */
		case 0x0f: /* MULTIHOME REGISTRATION */
		case 0x10:
			{
				unsigned offsetx;

				for (offsetx=0; offsetx<rec->rdata_length; offsetx += 6) {
					ip_address = ex32be(px+rec->rdata_offset+offsetx+2);
					/*JOTDOWN(squirrel,
						JOT_IPv4("ID-IP", ip_address),
						JOT_PRINT("name", name2, name2_length),
						JOT_SZ("type", "NetBIOS"),
						0);*/
                    {
                        char tmpname[257];
                        sprintf_s(tmpname, sizeof(tmpname), "%.*s", name2_length, name2);
                        if (endsWith(tmpname, "<00>"))
                            tmpname[strlen(tmpname)-4] = '\0';
                        if (endsWith(tmpname, "<20>"))
                            tmpname[strlen(tmpname)-4] = '\0';
                        if (endsWith(tmpname, "<1E>"))
                            continue;
                        if (endsWith(tmpname, "<1D>"))
                            continue;
                        if (endsWith(tmpname, "\x01\x02__MSBROWSE__\x02<01>"))
                            continue;
                        sqdb_add_info(	squirrel->sqdb, 
			                    frame->src_mac,
			                    frame->bss_mac,
			                    "name",
			                    tmpname, -1);
				    }
                }
			}
			break;
		case 0x06: /* RELEASE */
			/* Todo: should probably track what name they are releasing */
			break;
		default:
			FRAMERR(frame, "%s: unknown opcode\n", "NetBIOS");
		}
		break;
	case TYPECLASS(0x21,1): /* type=NBTSTAT, class=INTERNET */
		if (!is_valid_opcode(dns->opcode, 0x10, -1)) {
			FRAMERR(frame, "%s: unknown opcode\n", "NetBIOS");
			return;
		}
		{
			unsigned length2 = rec->rdata_offset + rec->rdata_length;
			unsigned number_of_names;
			unsigned j;


			offset = rec->rdata_offset;

			number_of_names = px[offset++];

			if (offset >= length || offset >= length2) {
				FRAMERR(frame, "dns: truncated\n");
				break;
			}


			/* Grab the names */
			for (j=0; j<number_of_names; j++) {
				char netbios_name[256];
				unsigned is_workgroup = px[offset+16] & 0x80;
			
				if (offset+18 > length || offset+18 > length2) {
					offset += 18;
					FRAMERR(frame, "dns: truncated\n");
					break;
				}
				
				cleanse_netbios_name(frame, (const char*)px+offset, netbios_name, sizeof(netbios_name));
				
				/*JOTDOWN(squirrel,
					JOT_SRC("ID-IP", frame),
					JOT_PRINT("netbios",	 	netbios_name,			strlen(netbios_name)),
					0);*/

				if (!is_workgroup && (endsWith(netbios_name, "<00>") || endsWith(netbios_name, "<20>"))) {
					/*JOTDOWN(squirrel,
						JOT_SRC("ID-IP", frame),
						JOT_PRINT("name",	 	netbios_name,			strlen(netbios_name)-4),
						0);*/
				}

				offset += 18;
			}

			if (offset+6 > length || offset+18 > length2) {
				FRAMERR(frame, "dns: truncated\n");
				break;
			}

			if (memcmp(px+offset, "\0\0\0\0\0\0", 6) != 0) {
				/*JOTDOWN(squirrel,
					JOT_SRC("ID-IP", frame),
					JOT_MACADDR("mac", px+offset),
					0);*/
			}
			offset += 6;
		}
		break;
	default:
		FRAMERR(frame, "%s: unknown [type=0x%x(%d), class=0x%x(%d)] name=%s)\n", 
				"NetBIOS",
				rec->type, rec->type, 
				rec->clss, rec->clss, 
				name);
	}
}

