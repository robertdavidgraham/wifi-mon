/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
/*
	BONJOUR/RENDEZVOUS/mDNS/DNS-SD/etc.

  This module is based upon the DNS module.

  DNS is overloaded for many services. One of those is the 
  "Bonjour" or "multicast-DNS" or "service-discovery" protocols.

  The DNS module parse resource records, tests them to see if 
  they match the Bonjour service, then sends those resource
  records to this module for further processing.

*/
#include "platform.h"
#include "netframe.h"
#include "../squirrel.h"
#include "formats.h"
#include "hexval.h"
#include <string.h>
#include <ctype.h>
#include "sprintf_s.h"
#include "stackdns.h"

#define TYPECLASS(n,m) ((n)<<16|(m))
#ifndef MIN
#define MIN(a,b) ( (a)<(b) ? (a) : (b) )
#endif

static unsigned endsWith(const void *v_basestr, const void *v_pattern)
{
	const char *basestr = (const char *)v_basestr;
	const char *pattern = (const char *)v_pattern;
	size_t base_length = strlen(basestr);
	size_t pattern_length = strlen(pattern);

	if (base_length < pattern_length)
		return 0;
	return memcmp(basestr+base_length-pattern_length, pattern, pattern_length) == 0;

}
static unsigned startsWith(const void *v_basestr, const void *v_pattern)
{
	const char *basestr = (const char *)v_basestr;
	const char *pattern = (const char *)v_pattern;
	size_t base_length = strlen(basestr);
	size_t pattern_length = strlen(pattern);

	if (base_length < pattern_length)
		return 0;
	return memcmp(basestr, pattern, pattern_length) == 0;

}

void bonjour_parse_question_record(struct Squirrel *squirrel, struct NetFrame *frame, 
							const unsigned char *px, unsigned length,
							struct DNSRECORD *rec, struct DNS *dns)
{
	char name[512]; /* reserve a longer name than the max theoretical limit */
	unsigned name_length;

	UNUSEDPARM(dns);

	name_length = dns_extract_name(frame, px, length, rec->name_offset, name, sizeof(name));

	switch (rec->type<<16 | rec->clss) {
	case TYPECLASS(1,1): /* type=A(IPv4 address), class=INTERNET*/
		break;
	case TYPECLASS(16,1): /* type=TXT(text), class=INTERNET*/
		break;
	case TYPECLASS(0x21,1): /* type=SRV(Service Location), class=INTERNET*/
		if (endsWith(name, "._presence._tcp.local")) {
			unsigned i;
			for (i=0; i<name_length; i++) {
				if (name[i] == '@')
					break;
			}
			if (i<name_length && name[i] == '@') {
				/*unsigned tmp_len = i++;*/
				/*JOTDOWN(squirrel,
					JOT_SRC("ID-IP", frame),
					JOT_PRINT("username",name, tmp_len),
					0);*/
				while (i<name_length && name[i] != '.')
					i++;
				/*JOTDOWN(squirrel,
					JOT_SRC("ID-IP", frame),
					JOT_PRINT("computername",name+tmp_len+1, i-tmp_len-1),
					0);*/
			}
		} /*else
			FRAMERR(frame, "%s: unknown\n", "mDNS");
			*/
		break;
	default:
		FRAMERR(frame, "%s: unknown [type=0x%x(%d), class=0x%x(%d)] name=%s)\n", 
				"mDNS",
				rec->type, rec->type, 
				rec->clss, rec->clss, 
				name);
	}
}

void bonjour_parse_resource_record(struct Squirrel *squirrel, struct NetFrame *frame, 
							const unsigned char *px, unsigned length,
							struct DNSRECORD *rec, struct DNS *dns)
{
	char name[512]; /* reserve a longer name than the max theoretical limit */
	unsigned name_length;
	char name2[512]; /* reserve a longer name than the max theoretical limit */
	unsigned name2_length;
	unsigned ip_address;
	unsigned offset = rec->rdata_offset;
	unsigned offset_max = MIN(rec->rdata_offset+rec->rdata_length, length);

	name_length = dns_extract_name(frame, px, length, rec->name_offset, name, sizeof(name));

    if (rec->type == 41) /* EDNS0 */
        return;

	switch (rec->type<<16 | (rec->clss&0x7fFF)) {
	case TYPECLASS(1,1): /* type=A(IPv4 address), class=FLUSH(mDNS/Bonjour)*/
		if (!is_valid_opcode(dns->opcode, 0x00, 0x10, -1)) {
			FRAMERR(frame, "%s: unknown opcode\n", "mDNS");
			return;
		}
		ip_address = ex32be(px+rec->rdata_offset);
		if (rec->rdata_length != 4)
			FRAMERR(frame, "dns: data not 4-bytes long, was %d-bytes instead (class=%d, type=%d, name=%s)\n", rec->rdata_length, rec->clss, rec->type, name);
        if (endsWith(name, ".local"))
            name_length -= 6;
        {
            char tmpname[257];
            sprintf_s(tmpname, sizeof(tmpname), "%.*s", name_length, name);

            /* Looks like:
             * "Robert-Graham-iPhone.local"
             * So, we want to mark this as an "iPhone" and save the name "Robert-Graham"
             */
            if (endsWith(tmpname, "iPhone")) {
                sqdb_add_info(	squirrel->sqdb, 
			            frame->src_mac,
			            frame->bss_mac,
			            "system",
			            "iPhone", -1);
                if (strlen(tmpname) > 6) {
                    tmpname[strlen(tmpname)-6] = '\0';
                    while (tmpname[0] && ispunct(tmpname[strlen(tmpname)-1]))
                        tmpname[strlen(tmpname)-1] = '\0';
                }
            }

            sqdb_add_info(	squirrel->sqdb, 
			        frame->src_mac,
			        frame->bss_mac,
			        "name",
			        tmpname, -1);


            /* Try to save the IP address */
            if (ip_address == frame->src_ipv4) {
                if (frame->ip_ttl == 64 || frame->ip_ttl == 128 || frame->ip_ttl == 255) {
                    char textip[16];
                    sprintf_s(textip, sizeof(textip), "%u.%u.%u.%u",
                        (ip_address>>24)&0xFF,
                        (ip_address>>16)&0xFF,
                        (ip_address>> 8)&0xFF,
                        (ip_address>> 0)&0xFF
                        );
                    sqdb_add_info(	squirrel->sqdb, 
			                frame->src_mac,
			                frame->bss_mac,
			                "ip",
			                textip, -1);

                }
            }
        }

		/*JOTDOWN(squirrel,
			JOT_IPv4("ID-IP", ip_address),
			JOT_PRINT("name", name, name_length),
			0);*/
		break;
	case TYPECLASS(12,1): /* type=PTR(pointer), class=INTERNET*/
		if (smellslike_srv_record(px, length, rec->name_offset))
			dnssrv_parse_resource_record(squirrel, frame, px, length, rec, dns);
		else if (endsWith(name, ".ip6.arpa")) {
			/* Extract 16-byte IPv6 address from the weird text encoding
			 * For example, the 'name' might look like the following string:
			 * "2.D.B.B.9.D.E.F.F.F.3.E.9.1.2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.E.F.ip6.arpa"
			 */
			unsigned j, k;
			unsigned char ipv6[16];
			for (j=0, k=0; j<16 && name[k]; j++) {
				while (name[k] && !isxdigit(name[k]))
					k++;
				ipv6[16-j-1] = (unsigned char)(hexval(name[k])<<0);
				k++;

				while (name[k] && !isxdigit(name[k]))
					k++;
				ipv6[16-j-1] |= hexval(name[k])<<4;
				k++;
			}

			/* Now get the name it points to */
			name2_length = dns_extract_name(frame, px, length, offset, name2, sizeof(name2));

			/*JOTDOWN(squirrel,
				JOT_IPv6("ID-IP", ipv6, 16),
				JOT_PRINT("name", name2, name2_length),
				0);
			JOTDOWN(squirrel,
				JOT_PRINT("ID-DNS", name2, name2_length),
				JOT_IPv6("ID-IP", ipv6, 16),
				0);*/
		} else if (endsWith(name, ".in-addr.arpa")) {
			/* Extract a 4-byte IPv4 address 
			 * Example: "18.0.0.10.in-addr.arpa"*/
			unsigned ipv4=0;
			unsigned i;
			unsigned j=0;

			for (i=0; i<4; i++) {
				unsigned num = 0;

				for (; name[j] && name[j] != '.'; j++) {
					if ('0' <= name[j] && name[j] <= '9')
						num = num * 10 + name[j]-'0';
				}
				while (name[j] == '.')
					j++;
				ipv4 |= num<<(i*8);
			}
			/* Now get the name it points to */
			name2_length = dns_extract_name(frame, px, length, offset, name2, sizeof(name2));

			/*JOTDOWN(squirrel,
				JOT_IPv4("ID-IP", ipv4),
				JOT_PRINT("name", name2, name2_length),
				0);
			JOTDOWN(squirrel,
				JOT_PRINT("ID-DNS", name2, name2_length),
				JOT_IPv4("ID-IP", ipv4),
				0);*/


		} else
			FRAMERR(frame, "%s: unknown PTR record\n", "mDNS");
		break;
	case TYPECLASS(0x10,1): /* type=TXT(text), class=INTERNET*/
		if (smellslike_srv_record(px, length, rec->name_offset))
			dnssrv_parse_resource_record(squirrel, frame, px, length, rec, dns);
		else if (startsWith(name, "_kerberos.")) {
			unsigned my_offset = offset;
			unsigned len = rec->rdata_length;
			if (len && my_offset<length) {
				unsigned len2 = px[my_offset];
				if  (len2 > len-1)
					len2 = len-1;
				my_offset++;
				/*JOTDOWN(squirrel,
					JOT_SRC("ID-IP", frame),
					JOT_PRINT("kerberos-realm", px+my_offset, len2),
					0);*/
			} else
				FRAMERR(frame, "%s: unknown TXT record\n", "mDNS");
		} else
			FRAMERR(frame, "%s: unknown TXT record\n", "mDNS");
		break;
	case TYPECLASS(0x1c,1): /*type=AAAA(IPv6 address), class=FLUSH(mDNS/Bonjour) */
		if (!is_valid_opcode(dns->opcode, 0x10, 0x00, -1)) {
			FRAMERR(frame, "%s: unknown opcode\n", "mDNS");
			return;
		}
		{
			/*const unsigned char *ipv6_address = px+rec->rdata_offset;*/
			if (rec->rdata_length != 16)
				FRAMERR(frame, "dns: data not 16-bytes long, was %d-bytes instead (class=%d, type=%d, name=%s)\n", rec->rdata_length, rec->clss, rec->type, name);
            else {
			    /*JOTDOWN(squirrel,
				    JOT_IPv6("ID-IP", ipv6_address,				16),
				    JOT_PRINT("name", name, name_length),
				    0);*/
            }
		}
		break;
	case TYPECLASS(0x0d,1): /*type=HINFO(host information), class=INTERNET */
		if (!is_valid_opcode(dns->opcode, 0x00, 0x10, -1)) {
			FRAMERR(frame, "%s: unknown opcode\n", "mDNS");
			return;
		}
		{
			unsigned j=0;
			const unsigned char *cpu;
			unsigned cpu_length;
			const unsigned char *os;
			unsigned os_length;

			j = rec->rdata_offset;

			cpu = px+j+1;
			cpu_length = px[j];
			j += cpu_length + 1;

			os = px+j+1;
			os_length = px[j];

			/*JOTDOWN(squirrel,
				JOT_PRINT("Bonjour", name, name_length),
				JOT_PRINT("OS", os,	os_length),
				0);
			JOTDOWN(squirrel,
				JOT_PRINT("Bonjour", name,name_length),
				JOT_PRINT("CPU", cpu, cpu_length),
				0);*/
		}
		break;
	case TYPECLASS(33,1): /*type=SRV, class=INTERNET */
		dnssrv_parse_resource_record(squirrel, frame, px, length, rec, dns);
		break;
	case TYPECLASS(10,1): /*type=NULL, class=INTERNET */
		if (!is_valid_opcode(dns->opcode, 0x10, -1)) {
			FRAMERR(frame, "%s: unknown opcode\n", "mDNS");
			return;
		}
		/* I'm not sure what this is for. I first found it within broadcasts from
		 * iChat on the apple where it's used to contain a raw JPEG file that
		 * shows a person's image */
		if (offset_max - offset > 4 && ex32be(px+offset) == 0xffd8ffe0) {
			//parse_jpeg_ichat_image(squirrel, frame, px+offset, offset_max-offset);
		} if (endsWith(name, "@iPhone._presence._tcp.local")) {
			/*unsigned username_length = strchr(name, '@') - name;*/
			/*JOTDOWN(squirrel,
				JOT_SRC("ID-IP", frame),
				JOT_PRINT("username", name, username_length),
				0);
			JOTDOWN(squirrel,
				JOT_SRC("ID-IP", frame),
				JOT_SZ("icon", "iPhone"),
				0);*/

		} else
			FRAMERR(frame, "%s: unknown [type=0x%x(%d), class=0x%x(%d)] name=%s\n", 
					"mDNS",
					rec->type, rec->type, 
					rec->clss, rec->clss, 
					name);

		break;
    case TYPECLASS(0x2f,1):
        /* REF: mdns-nsec-record.pcap*/ 
        break;
	default:
		FRAMERR(frame, "%s: unknown [type=0x%x(%d), class=0x%x(%d)] name=%s\n", 
				"mDNS",
				rec->type, rec->type, 
				rec->clss, rec->clss, 
				name);
	}
}

