/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
/*
	RENDEZVOUS, BONJOUR
	DNS SERVICE LOCATION RESOURCE RECORDS (SRV RR) [RFC 2782]

  This module processes "service" records. These are records with names
  that look like "_ftp._tcp.local" or "_sip._udp.example.com".

*/
#include "platform.h"
#include "netframe.h"
#include "../squirrel.h"
#include "formats.h"
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include "sprintf_s.h"
#include "stackdns.h"

#define TYPECLASS(n,m) ((n)<<16|(m))
#ifndef MIN
#define MIN(a,b) ( (a)<(b) ? (a) : (b) )
#endif



/**
 * Tests to see if the label equals the name, such as testing
 * if it equals "_tcp".
 */
static unsigned 
label_equals(const unsigned char *label, unsigned label_len, const char *sz)
{
	unsigned i;
	for (i=0; i<label_len && sz[i]; i++) {
		if (label[i] != sz[i])
			return 0;
	}
	if (i == label_len && sz[i] == '\0')
		return 1;
	else
		return 0;
}

/**
 * Given a pointer to a name in the packet, this module returns TRUE
 * when the name looks like Bonjour/mDNS/Rendezvous, and FALSE otherwise.
 *
 * Note that we are operating on the raw labels as they exist in the
 * packet, and not some "cooked" form. Therefore, we have to follow
 * the label compression and other such oddities.
 */
unsigned smellslike_srv_record(const unsigned char *px, unsigned length, unsigned offset)
{
	unsigned recurse_count = 0;
	unsigned seen_underscore = 0; /* TRUE if the last label began with an underscore, FALSE if it didn't */


	while (offset < length) {
		unsigned len;

		/* Test to see if this is the ending label, which is a label
		 * with a value of zero */
		if (px[offset] == 0x00)
			break;


		/* Test for a compression tag, which is a value larger than 63
		 * bytes. A compression tag means that we jump somewhere else
		 * in the packet, up to the first 16k bytes */
		if (px[offset] & 0xC0) {
			/* Test for deep recursion */
			if (recurse_count > 100)
				return 0;
			else
				recurse_count++;

			/* The new offset is encoded in two bytes, so test to make
			 * sure the 2nd byte is also within the packet */
			if (offset+2 > length)
				return 0;

			/* Create the new offset from the lower 14 bits of the 
			 * number (the 2 high order bits are used up indicating
			 * that this was a length field instead of a label */
			offset = ex16be(px+offset)&0x3FFF;

			/* Now re-start at the new offset */
			continue;
		}
	
		
		/* If the other conditions aren't true, then we have a normal
		 * label. Therefore, we use this byte as the length, followed
		 * by the name within the label */
		len = px[offset++];

		/* Make sure the entire label fits within the packet */
		if (offset+len > length)
			return 0;

		/* Test to see if the label begins with the '_' underscore 
		 * character. We are looking for something like "_http._tcp",
		 * which is an arbitrary service label, followed by either
		 * '_tcp' or '_udp'. */
		if (px[offset] == '_') {

			if (label_equals(px+offset, len, "_udp") || label_equals(px+offset, len, "_tcp")) {
				if (seen_underscore)
					return 1;
			}
			seen_underscore = 1;
		} else
			seen_underscore = 0;

		offset += len;
	}

	return 0;
}

enum {
	SRV_UNKNOWN=0,
	SRV_HTTP,
	SRV_FTP,
	SRV_TIVO_VIDEOS,
};

struct NameValue {
	const char *name;
	unsigned value;
};

struct NameValue services[] = {
	{"_http", SRV_HTTP},
	{"_ftp", SRV_FTP},
	{"_tivo-videos", SRV_TIVO_VIDEOS},
	{0, 0}
};

unsigned nv_lookup(const struct NameValue *list, const unsigned char *name, unsigned name_length)
{
	unsigned i;

	for (i=0; list[i].name; i++) {
		unsigned j;
		const char *list_name = list[i].name;

		for (j=0; list_name[j] == name[j] && j<name_length && list_name[j]; j++)
			;

		if (list_name[j] == '\0' && j == name_length)
			return list[i].value;
	}
	return 0;
}

/**
 * This parses a raw name from a packet and returns an enumerated type
 * for the service name.
 */
unsigned 
get_service(const unsigned char *px, unsigned length, unsigned offset, const unsigned char **r_service, unsigned *r_service_length)
{
	unsigned recurse_count = 0;
	unsigned offset_of_serv = 0;

	while (offset < length) {
		unsigned len;

		/* Test to see if this is the ending label, which is a label
		 * with a value of zero */
		if (px[offset] == 0x00)
			break;


		/* Test for a compression tag, which is a value larger than 63
		 * bytes. A compression tag means that we jump somewhere else
		 * in the packet, up to the first 16k bytes */
		if (px[offset] & 0xC0) {
			/* Test for deep recursion */
			if (recurse_count > 100)
				return 0;
			else
				recurse_count++;

			/* The new offset is encoded in two bytes, so test to make
			 * sure the 2nd byte is also within the packet */
			if (offset+2 > length)
				return 0;

			/* Create the new offset from the lower 14 bits of the 
			 * number (the 2 high order bits are used up indicating
			 * that this was a length field instead of a label */
			offset = ex16be(px+offset)&0x3FFF;

			/* Now re-start at the new offset */
			continue;
		}
	
		
		/* If the other conditions aren't true, then we have a normal
		 * label. Therefore, we use this byte as the length, followed
		 * by the name within the label */
		len = px[offset++];

		/* Make sure the entire label fits within the packet */
		if (offset+len > length)
			return 0;

		/* Test to see if the label begins with the '_' underscore 
		 * character. We are looking for something like "_http._tcp",
		 * which is an arbitrary service label, followed by either
		 * '_tcp' or '_udp'. */
		if (px[offset] == '_') {
			if (label_equals(px+offset, len, "_udp") || label_equals(px+offset, len, "_tcp")) {
				if (offset_of_serv) {
					*r_service = px + offset_of_serv + 1;
					*r_service_length = px[offset_of_serv];
					return 0;
				}
			}
			offset_of_serv = offset-1;
		} else
			offset_of_serv = 0;

		offset += len;
	}

	return 0;
}


void bonjour_txt_flush(struct Squirrel *squirrel, struct NetFrame *frame, const unsigned char *px, unsigned length,
					   struct DNSRECORD *rec)
{
	const unsigned char *bonjour = (const unsigned char*)"";
	unsigned bonjour_length = 0;
	unsigned offset = rec->rdata_offset;
	unsigned offset_max = MIN(rec->rdata_offset+rec->rdata_length, length);

	get_service(px, length, rec->name_offset, &bonjour, &bonjour_length);

	/* For all the <name=value> pairs in the record */
	while (offset < offset_max) {
		unsigned len = px[offset++];
		const unsigned char *tag;
		unsigned tag_length;
		const unsigned char *value;
		unsigned value_length;
		unsigned max2 = length;

		if (max2 > offset + len)
			max2 = offset + len;

		tag = px+offset;
		for (tag_length=0; offset+tag_length<max2 && tag[tag_length]!='='; tag_length++)
			;
		offset+=tag_length;
		if (offset < max2 && px[offset] == '=')
			offset++;
		while (offset < max2 && isspace(px[offset]))
			offset++;
		value = px+offset;
		value_length = (max2-offset);
		offset = max2;

		/* Process the name value pair */
		/*JOTDOWN(squirrel,
			JOT_SRC("ID-IP", frame),
			JOT_PRINT("Service",	 	bonjour,				bonjour_length),
			JOT_PRINT("tag",		 	tag,					tag_length),
			JOT_PRINT("value",	 	value,					value_length),
			0);*/
	}
}

void dnssrv_parse_resource_record(struct Squirrel *squirrel, struct NetFrame *frame, 
							const unsigned char *px, unsigned length,
							struct DNSRECORD *rec, struct DNS *dns)
{
	char name[512]; /* reserve a longer name than the max theoretical limit */
	unsigned name_length;
	char name2[512]; /* reserve a longer name than the max theoretical limit */
	unsigned name2_length;
	unsigned offset = rec->rdata_offset;
	unsigned offset_max = MIN(rec->rdata_offset+rec->rdata_length, length);
	unsigned port;
	const unsigned char *service_name = (const unsigned char*)"";
	unsigned service_length = 0;
	unsigned ip_address;

	/* Retrieve just the label for the service name, such as _http or _ftp */
	get_service(px, length, rec->name_offset, &service_name, &service_length);

	name_length = dns_extract_name(frame, px, length, rec->name_offset, name, sizeof(name));
	

	switch (rec->type<<16 | (rec->clss & 0x7Fff)) {
	case TYPECLASS(12,1): /* type=PTR(pointer), class=INTERNET*/
		if (!is_valid_opcode(dns->opcode, 0x00, 0x10, -1)) {
			FRAMERR(frame, "%s: unknown opcode\n", "DNS");
			return;
		}
		break;
	case TYPECLASS(16,1): /* type=TXT(text), class=INTERNET*/
		if (!is_valid_opcode(dns->opcode, 0x00, 0x10, -1)) {
			FRAMERR(frame, "%s: unknown opcode\n", "DNS");
			return;
		}
		bonjour_txt_flush(squirrel, frame, px, length, rec);
		break;
	case TYPECLASS(33,1): /* type=SRV, class=INTERNET*/
		if (!is_valid_opcode(dns->opcode, 0x00, 0x10, -1)) {
			FRAMERR(frame, "%s: unknown opcode: %d\n", "DNS-SD", dns->opcode);
			return;
		}
		/*
		+--------+--------+
		|    Priority     |
		+--------+--------+
		|     Weight      |
		+--------+--------+
		|      Port       |
		+--------+--------+
		|      Hostname ...
		+--....
		*/

		if (offset_max - offset < 7) {
			FRAMERR(frame, "%s: truncated\n", "DNS-SD");
			return;
		}

		port = ex16be(px+offset+4);
		
		name2_length = dns_extract_name(frame, px, length, offset+6, name2, sizeof(name2));
		ip_address = dns_resolve_alias(frame, px, length, dns, name2, 0);

		/*JOTDOWN(squirrel,
			JOT_IPv4("ID-IP", ip_address),
			JOT_PRINT("Service", service_name, service_length),
			JOT_NUM("Port", port),
			0);
		JOTDOWN(squirrel,
			JOT_IPv4("ID-IP", ip_address),
			JOT_PRINT("Service", service_name, service_length),
			JOT_PRINT("Hostname", name2, name2_length),
			0);
		JOTDOWN(squirrel,
			JOT_IPv4("ID-IP", ip_address),
			JOT_PRINT("Service", service_name, service_length),
			JOT_PRINT("Friendly", name, name_length),
			0);
		JOTDOWN(squirrel,
			JOT_IPv4("ID-IP", ip_address),
			JOT_PRINT("name", name, name_length),
			JOT_SZ("type", "Bonjour"),
			0);*/
        {
            char tmpname[257];
            sprintf_s(tmpname, sizeof(tmpname), "%.*s", name_length, name);
            if (strchr(tmpname, '.')) {
                char *p = strchr(tmpname, '.');
                *p = '\0';
            }
            sqdb_add_info(	squirrel->sqdb, 
			        frame->src_mac,
			        frame->bss_mac,
			        "name",
			        tmpname, -1);
        }

		break;
	default:
		FRAMERR(frame, "dns: unknown type=%d (class=%d, name=%s)\n", rec->type, rec->clss, name);
	}
}


