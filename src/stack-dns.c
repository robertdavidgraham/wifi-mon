/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
/*
	DOMAIN NAME SYSTEM, NETBIOS NAMING, and 
	BONJOUR/RENDEZVOUS/mDNS, and DynDNS.

  DNS is overloaded to provide a number of interesting services.

  First of all, traditional DNS tells us a lot about what systems the
  computer wants connectivity. This can tell us some of the machines
  in a mobile computer's home network.

  Second, NETBIOS is naming service used by Microsoft Windows 
  networking. A client desktop will use this protocol to find
  the servers it wants to connect to, including 'Exchange' e-mail
  servers. This gives us a small map of the home netwrok of a 
  roving notebook computer. Note that these broadcasts will be
  sent out as soon as a user opens his notebook and connects
  to a wifi hotspot, before they have a chance to start their
  VPN service.

  Third, "multicast DNS" is a local broadcast mechanism that
  helps applications find each other. For example, Apple's 
  iTunes uses mDNS to find other iTunes servers so that people 
  can listen to each other's music. mDNS is built into Apple's
  Mac OS X, but is also included as a component of many 
  applications on Windows and Linux. mDNS tells us the hostname
  of a computer, as well as interesting names. For example,
  the iTunes use of mDNS often tells us the user's full
  real-life name.

  Lastly, the DynDNS functionality can tell us a name associated
  with a machine.



*/
#include "stack-dns.h"
#include "util-platform.h"
#include "stack-frame.h"
#include "squirrel.h"
#include "util-extract.h"
#include "util-annexk.h"
#include "util-stratom.h"
#include "util-unused.h"

#include <string.h>
#include <ctype.h>
#include <stdarg.h>

#ifndef MIN
#define MIN(a,b) ( (a)<(b) ? (a) : (b) )
#endif

	enum {
		OP_QUERY=0,
		OP_IQUERY=1,
	};

/**
 * This function extracts a DNS name from the packet and formats it according
 * to DNS rules. Essentially, this means that if a '.' dot character appears inside
 * of a label, then we'll show  '\.' escaped dot. Likewise, if the '\' escape
 * character appears inside of a label, we'll '\\' escape it as well. Otherwise,
 * we'll show all binary and spaces as they are natively in the stream.
 */
unsigned 
dns_extract_name(struct StackFrame *frame, const unsigned char *px, unsigned length, unsigned offset, char *name, unsigned sizeof_name)
{
	int recurse_count = 0;
	unsigned name_offset = 0;

	name[0] = '\0';

	/* For all labels ... */
	while (offset < length) {
		unsigned len;

		/* The 'empty' label ends the DNS name */
		if (px[offset] == 0x00)
			break;

		/* Look for a Lempel-Ziv compression, which points backwards in the packet
		 * to some other repeated name, as much as 16k into the packet */
		if (px[offset] & 0xC0) {

			/* Check for repeated recursion. We can point to another label,
			 * or to annother pointer. Indeed, a vulnerability in older
			 * DNS implementations is where if the pointer pointed to itself,
			 * then the DNS would go into an infinite loop endlessly following
			 * that pointer */
			if (recurse_count > 100) {
				FRAMERR(frame, "dns: name: recursion exceeded %d\n", recurse_count);
				break;
			}
			recurse_count++;

			/* This is actually a 2-byte field, so we need to check for the 
			 * extra byte has not run past the end of the packet */
			if (offset+2 > length) {
				FRAMERR(frame, "dns: name: not enough bytes\n");
				strcpy_s(name, sizeof_name, "(err)");
				return 5;
			}

			/* Extract the lower 14-bits and use that as the new offset. Note that
			 * this means we can use this compression features that point to a name
			 * past the 16k boundary, but that isn't really a big problem because
			 * packets really never get that big. */
			offset = ex16be(px+offset)&0x3FFF;

			continue;
		} 
		
		/* Otherwise, we have a normal label. The first step is to grab the 
		 * length of this label and make sure we haven 't gone past the end
		 * of the packet */
		len = px[offset++];
		if (offset >= length) {
			FRAMERR(frame, "dns: name: not enough bytes\n");
			strcpy_s(name, sizeof_name, "(err)");
			return 5;
		}
		if (offset+len > length) {
			FRAMERR(frame, "dns: name: not enough bytes\n");
			strcpy_s(name, sizeof_name, "(err)");
			return 5;
		}

		/* If there were already a label in the name, make sure that there
		 * is the '.' character between the previoius label an this label. */
		if (name_offset > 0) {
			if (name_offset+1 >= sizeof_name) {
				FRAMERR(frame, "dns: name: too long\n");
				strcpy_s(name, sizeof_name, "(err)");
				return 5;
			}
			name[name_offset++] = '.';
		}

		/* Make sure there is enough space left in the name, as well as enough
		 * psace for the NUL terminating character */
		if (name_offset+len+1 >= sizeof_name) {
			FRAMERR(frame, "dns: name: too long\n");
			strcpy_s(name, sizeof_name, "(err)");
			return 5;
		}

		/* Copy over the name */
		memcpy(name+name_offset, px+offset, len);
		name_offset += len;
		name[name_offset] = '\0';

		/* Now go onto the next label in the DNS name */
		offset += len;
	}

	return name_offset;
}

unsigned 
dns_resolve_alias(struct StackFrame *frame, const unsigned char *px, unsigned length, struct DNS *dns, const char *alias, int depth)
{
	unsigned i;

	for (i=dns->question_count; i<dns->record_count; i++) {
		struct DNSRECORD *rec = &dns->records[i];
		char name[256];
		unsigned name_length;

		name_length = dns_extract_name(frame, px, length, rec->name_offset, name, sizeof(name));

		if ((rec->type != 1 && rec->type != 5)|| (rec->clss&0x7FFF) != 1)
			continue;

		if (strcasecmp_s(alias, name) == 0) {
			switch (rec->type) {
			case 1:
				return ex32be(px+rec->rdata_offset);
			case 5:
				name_length = dns_extract_name(frame, px, length, rec->rdata_offset, name, sizeof(name));
				if (depth > 10)
					FRAMERR(frame, "dns: too much recursion, alias=\"%s\"\n", alias);
				else
					return dns_resolve_alias(frame, px, length, dns, name, depth+1);
			}
		}
	}

	/*FRAMERR(frame, "dns: could not resolve IP for alias=\"%s\"\n", alias);*/

	return 0;
}


/*TODO: currently, nobody references this function*/
void dns_dynamic_update(struct Squirrel *squirrel, struct StackFrame *frame, const unsigned char *px, unsigned length, struct DNS *dns)
{
	unsigned i;

    UNUSEDPARM(squirrel);

	for (i=0; i<dns->answer_count; i++) {
		char name[256];
		unsigned name_length;
		unsigned x;
		struct DNSRECORD *rec = &dns->answers[i];

		name_length = dns_extract_name(frame, px, length, rec->name_offset, name, sizeof(name));

		x = rec->clss<<16 | rec->type;
		
		//SAMPLE(squirrel,"DynDNS", JOT_NUM("Prereq", x));

		switch (rec->type) {
		case 0x0001: /*A*/
			switch (rec->clss) {
			case 0x0001: /*INTERNET*/
				{
					/*unsigned ip_address = ex32be(px+rec->rdata_offset);*/

					if (rec->rdata_length != 4)
						FRAMERR(frame, "dns: data not 4-bytes long, was %d-bytes instead (class=%d, type=%d, name=%s)\n", rec->rdata_length, rec->clss, rec->type, name);


					/*JOTDOWN(squirrel,
						JOT_IPv4("ID-IP", ip_address),
						JOT_PRINT("name",		 	name,				name_length),
						0);*/

					/*JOTDOWN(squirrel,
						JOT_SZ("proto","NETBIOS"),
						JOT_SZ("op","register"),
						JOT_SRC("ip.src", frame),
						JOT_PRINT("name",		 	name,				name_length),
						JOT_IPv4("address", ip_address),
						0);*/
				}
				break;
			default:
				FRAMERR(frame, "dns: unknown class=%d (type=%d, name=%s)\n", rec->clss, rec->type, name);
			}
			break;

		}
	}
}

const unsigned char *find_mac(const unsigned char *px, unsigned length, unsigned offset, const unsigned char **r_name, unsigned *r_name_length)
{
	unsigned len;

	if (offset >= length)
		return 0;

	len = px[offset];
	if (len > 64)
		return 0;

	offset++;
	if (length > offset+len)
		length = offset+len;


	*r_name = px+offset;
	*r_name_length = 0;
	while (offset < length && px[offset] != '[') {
		(*r_name_length)++;
		offset++;
	}

	while (*r_name_length && isspace((*r_name)[(*r_name_length)-1]))
		(*r_name_length)--;

	if (offset +19  <= length && px[offset] == '[') {
		const unsigned char *result = px+offset;
		return result;
	}
	return 0;
}

unsigned endsWith(const void *v_basestr, const void *v_pattern)
{
	const char *basestr = (const char *)v_basestr;
	const char *pattern = (const char *)v_pattern;
	size_t base_length = strlen(basestr);
	size_t pattern_length = strlen(pattern);

	if (base_length < pattern_length)
		return 0;
	return memcmp(basestr+base_length-pattern_length, pattern, pattern_length) == 0;

}

#ifndef MIN
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif

#define TYPECLASS(n,m) ((n)<<16|(m))

static void skip_name(const unsigned char *px, unsigned length, unsigned *r_offset)
{
	while (*r_offset < length) {
		if (0xC0 & px[*r_offset]) {
			(*r_offset) += 2;
			return;
		}
		if (0x00 == px[*r_offset]) {
			(*r_offset) += 1;
			return;
		}
		*r_offset += 1 + px[*r_offset];
	}
}

/**
 * This is a temporary hack to limit the 'opcodes' that the
 * resource record can process */
unsigned is_valid_opcode(int first, ...)
{
	va_list marker;

	va_start(marker, first);
	
	for (;;) {
		int opcode = va_arg(marker, int);

		if (opcode == -1)
			return 0; /* reach end of list without finding opcode */

		if (first == opcode)
			return 1; /* valid opcode */

	}

	va_end(marker);
	return 0;
}

/*
All RRs have the same top level format shown below:

                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                                               /
    /                      NAME                     /
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     CLASS                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TTL                      |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                   RDLENGTH                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
    /                     RDATA                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
NAME            an owner name, i.e., the name of the node to which this
                resource record pertains.
TYPE            two octets containing one of the RR TYPE codes.
CLASS           two octets containing one of the RR CLASS codes.
TTL             a 32 bit signed integer that specifies the time interval
                that the resource record may be cached before the source
                of the information should again be consulted.  Zero
                values are interpreted to mean that the RR can only be
                used for the transaction in progress, and should not be
                cached.  For example, SOA records are always distributed
                with a zero TTL to prohibit caching.  Zero values can
                also be used for extremely volatile data.
RDLENGTH        an unsigned 16 bit integer that specifies the length in
                octets of the RDATA field.
RDATA           a variable length string of octets that describes the
                resource.  The format of this information varies
                according to the TYPE and CLASS of the resource record.
*/


/**
 * This is the main function of the DNS parser.
 *
 * This is where the each DNS 'answer' (or 'additional' or 'authoritative') 
 * record is parsed. Mostly, we ignore the return code, though some functions
 * pay attention to and provide slightly different information depending
 * upon the opcode.
 */
static void 
dns_parse_resource_record(struct Squirrel *squirrel, struct StackFrame *frame, 
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

	/* MULTICAST DNS (mDNS): handle the multicast DNS records differently
	 * from normal DNS records. */
	if (!dns->is_response && frame->dst_port == 5353) {
		bonjour_parse_resource_record(squirrel, frame, px, length, rec, dns);
		return; 
	} else if (dns->is_response && (frame->src_port == 5353 || (frame->dst_port == 5353 && frame->src_port != 53))) {
		bonjour_parse_resource_record(squirrel, frame, px, length, rec, dns);
		return;
	}

	/* NETBIOS: handle NetBIOS records differently from normal DNS records */
	if (!dns->is_response && frame->dst_port == 137) {
		netbios_parse_resource_record(squirrel, frame, px, length, rec, dns);
		return; 
	} else if (dns->is_response && frame->src_port == 137) {
		netbios_parse_resource_record(squirrel, frame, px, length, rec, dns);
		return;
	}


	/* First, let's extract a pretty version of the name */
	name_length = dns_extract_name(frame, px, length, rec->name_offset, name, sizeof(name));
	
	if (rec->type == 0x8001)
		FRAMERR(frame, "TODO\n");

	if (rec->clss == 0xfe)
		return;

	/* RFC2671 - Extension Mechanisms for DNS (EDNS0) */
	if (rec->type == 41) {
		/* Regress: defcon2008/dump000.pca(12541) */
		/* TODO: parse this */
		return;
	}

	/* Haven't implemented dynamic update yet
	 * TODO: */
	if (dns->opcode == 21 || dns->opcode == 5)
		return;

	switch (rec->type<<16 | rec->clss) {
	case TYPECLASS(1,0x8001): /* type=A(IPv4 address), class=INTERNET(cache flush) */
		bonjour_parse_resource_record(squirrel, frame, px, length, rec, dns);
		break;
	case TYPECLASS(1,1): /* type=A(IPv4 address), class=INTERNET */
		if (!is_valid_opcode(dns->opcode, 0x10, 5, -1)) {
			FRAMERR(frame, "%s: unknown opcode=%d\n", "DNS", dns->opcode);
			return;
		}

		ip_address = ex32be(px+rec->rdata_offset);
		if (rec->rdata_length != 4)
			FRAMERR(frame, "dns: data not 4-bytes long, was %d-bytes instead (class=%d, type=%d, name=%s)\n", rec->rdata_length, rec->clss, rec->type, name);

		/*JOTDOWN(squirrel,
			JOT_PRINT("ID-DNS", name,	name_length),
			JOT_IPv4("address",	ip_address),
			0);*/
		break;
	case TYPECLASS(2,1): /* type=NS, class=INTERNET */
		if (!is_valid_opcode(dns->opcode, 0x10, -1)) {
			FRAMERR(frame, "%s: unknown opcode=%d\n", "DNS", dns->opcode);
			return;
		}
		name2_length = dns_extract_name(frame, px, length, rec->rdata_offset, name2, sizeof(name2));
		ip_address = dns_resolve_alias(frame, px, length, dns, name2, 0);

		/*JOTDOWN(squirrel,
			JOT_PRINT("ID-DNS",	name, name_length),
			JOT_PRINT("Name-Server", name2, name2_length),
			JOT_IPv4("address", ip_address),
			0);*/
		break;
	case TYPECLASS(5,1): /*type=CNAME(aliased canonical name), class=INTERNET */
		if (!is_valid_opcode(dns->opcode, 0x10, 5, -1)) {
			FRAMERR(frame, "%s: unknown opcode=%d\n", "DNS", dns->opcode);
			return;
		}
		name2_length = dns_extract_name(frame, px, length, rec->rdata_offset, name2, sizeof(name2));

		ip_address = dns_resolve_alias(frame, px, length, dns, name2, 0);

		if (ip_address != 0) {
			/*JOTDOWN(squirrel,
				JOT_PRINT("ID-DNS", name,	name_length),
				JOT_IPv4("alias",ip_address),
				0);*/
            ;
		}
		/*JOTDOWN(squirrel,
			JOT_PRINT("ID-DNS", name,	name_length),
			JOT_PRINT("alias", name2, name2_length),
			0);*/
		break;
	case TYPECLASS(6,1): /*type=SOA, class=INTERNET*/
		if (!is_valid_opcode(dns->opcode, 0x10, -1)) {
			FRAMERR(frame, "%s: unknown opcode=%d\n", "DNS", dns->opcode);
			return;
		}
		/*
		 * Authoritative Name Server
		 */
		name2_length = dns_extract_name(frame, px, length, offset, name2, sizeof(name2));
		/*JOTDOWN(squirrel,
			JOT_PRINT("ID-DNS",	name, name_length),
			JOT_SZ("SOA", "Start of zone authority"),
			JOT_PRINT("Name-Server", name2, name2_length),
			0);*/
		ip_address = dns_resolve_alias(frame, px, length, dns, name2, 0);
        if (ip_address) {
		    /*JOTDOWN(squirrel,
			    JOT_PRINT("ID-DNS",	name, name_length),
			    JOT_SZ("SOA", "Start of zone authority"),
			    JOT_PRINT("Name-Server", name2, name2_length),
			    JOT_IPv4("address", ip_address),
			    0);*/
            ;
        }
		skip_name(px, length, &offset);

		/* Contact */
		if (offset < offset_max) {
			name2_length = dns_extract_name(frame, px, length, offset, name2, sizeof(name2));
			/*JOTDOWN(squirrel,
				JOT_PRINT("ID-DNS",	name, name_length),
				JOT_SZ("SOA", "Start of zone authority"),
				JOT_PRINT("Contact", name2, name2_length),
				0);*/
			skip_name(px, length, &offset);
		}

		break;
	case TYPECLASS(10,1): /* type=NULL, class=INTERNET*/
		/* Regress: defcon2008-dns2.pcap(100803): name=Vaaaaiaqaac.tunnel.fastcoder.net */
		/* I'm not sure what this is, other than passing data as Null records.
		 * This would be a good thing for an intrusion-detection system to trigger
		 * on. */
		break;
	case TYPECLASS(12,0x8001): /*type=PTR, class=INTERNET */
		bonjour_parse_resource_record(squirrel, frame, px, length, rec, dns);
		break;
	case TYPECLASS(12,1): /*type=PTR(pointer reverse lookup), class=INTERNET */
		if (!is_valid_opcode(dns->opcode, 0x10, -1)) {
			FRAMERR(frame, "%s: unknown opcode=%d\n", "DNS", dns->opcode);
			return;
		}
		if (name_length > 6 && memcmp(name+name_length-6, ".local", 6) == 0) {

			/*JOTDOWN(squirrel,
				JOT_SRC("ID-IP", frame),
				JOT_PRINT("Service", name,name_length),
				0);*/

			/* Extract MAC address */
			{
				const unsigned char *p_name;
				unsigned name_lengthX;
				const unsigned char *p_mac = find_mac(px, MIN(length, rec->rdata_offset+rec->rdata_length), rec->rdata_offset, &p_name, &name_lengthX);
				if (p_mac) {
					/*JOTDOWN(squirrel,
						JOT_SRC("ID-IP", frame),
						JOT_PRINT("mac",		 	p_mac,						19),
						0);
					JOTDOWN(squirrel,
						JOT_SRC("ID-IP", frame),
						JOT_PRINT("name",		 	p_name,						name_length),
						0);*/
				}
			}

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
				JOT_PRINT("ID-DNS", name2, name2_length),
				JOT_IPv4("ID-IP", ipv4),
				JOT_SRC("dnssrv", frame),
				0);*/
		} else
			; //FRAMERR(frame, "dns: unknown PTR record\n");
		break;
	case TYPECLASS(13,0x8001): /*type=HINFO, class=INTERNET */
		bonjour_parse_resource_record(squirrel, frame, px, length, rec, dns);
		break;
	case TYPECLASS(15,1): /*type=MX, class=INTERNET */
		/* Regress: defcon2008-dns2.pcap(18661) */
		break;
	case TYPECLASS(16,0x8001):		/*type=TXT, class=INTERNET(cache flush)*/
		bonjour_parse_resource_record(squirrel, frame, px, length, rec, dns);
		break;
	case TYPECLASS(16,1):		/*type=TXT, class=INTERNET */
		if (!is_valid_opcode(dns->opcode, 0x10, 5, -1)) {
			FRAMERR(frame, "%s: unknown opcode=%d\n", "DNS", dns->opcode);
			return;
		}

		if (strcasecmp_s(name, "current.cvd.clamav.net") == 0) {
			/* This is a single string containing a version string, like:
			 * 0.91.1:44:3855:1186270141:1
			 */
			break;
		} else if (starts_with("_DM-NOTIFICATION.", name, (unsigned)strlen(name))) {
			/* Regress: defcon2008\dump001.pcap(87082) */
			/* TODO */
			break;
		} else if (endsWith(name, "._workstation._tcp.local")) {
			/* Regress: defcon2008-dns2.pcap(56127): "mike-desktop [00:0c:29:f6:58:ca]._workstation._tcp.local" */
			break;
		} else if (endsWith(name, ".asn.cymru.com")) {
			/* Regress: defcon2008-dns2.pcap(98958) */
			/* This is a system for mapping IP to ASN numbers:
			 * http://www.team-cymru.org/Services/ip-to-asn.html */
			break;
		} else if (endsWith(name, ".wrs.trendmicro.com")) {
			/* Regress: defcon2008-dns2.pcap(184904) */
			/* Appears to check whether IP addresses are trustworthy */
			break;
		} else {
			FRAMERR(frame, "%s: unknown TXT record %s", "DNS", name);
		}
		break;
	case TYPECLASS(0x1c,1): /*type=AAAA(IPv6 address), class=INTERNET*/
	case TYPECLASS(0x1c,255): /*type=AAAA(IPv6 address), class=INTERNET*/
		if (!is_valid_opcode(dns->opcode, 0x10, 5, -1)) {
			FRAMERR(frame, "%s: unknown opcode=%d\n", "DNS", dns->opcode);
			return;
		}
		switch (dns->opcode) {
		case 0x10:
			{
				/*const unsigned char *ipv6_address = px+rec->rdata_offset;*/
				if (rec->rdata_length != 16)
					FRAMERR(frame, "dns: data not 16-bytes long, was %d-bytes instead (class=%d, type=%d, name=%s)\n", rec->rdata_length, rec->clss, rec->type, name);

				/*JOTDOWN(squirrel,
					JOT_SZ("proto","DNS"),
					JOT_SZ("op","lookup"),
					JOT_SRC("ip.src", frame),
					JOT_PRINT("name", name, name_length),
					JOT_IPv6("address", ipv6_address,				16),
					0);*/
			}
		case 5: /* dynamic update*/
			/* Regress: defcon2008-dns2.pcap(7958) */
			break;
		default:
			FRAMERR(frame, "%s: unknown opcode=%d\n", "DNS", dns->opcode);
		}
		break;
	case TYPECLASS(33,1): /*type=SRV, class=INTERNET */
		if (!is_valid_opcode(dns->opcode, 0x10, -1)) {
			FRAMERR(frame, "%s: unknown opcode=%d\n", "DNS", dns->opcode);
			return;
		}

		if (rec->rdata_length < 7)
			FRAMERR(frame, "dns: unknown type=%d (class=%d, name=%s)\n", rec->type, rec->clss, name);
		else {
			/*unsigned port = px[rec->rdata_offset+4]<<8 | px[rec->rdata_offset+5];*/
			name2_length = dns_extract_name(frame, px, length, rec->rdata_offset+6, name2, sizeof(name2));
			ip_address = dns_resolve_alias(frame, px, length, dns, name2, 0);

			if (ip_address != 0) {
				/*JOTDOWN(squirrel,
					JOT_PRINT("ID-DNS", name,	name_length),
					JOT_PRINT("Server", name2,	name2_length),
					JOT_NUM("Port", port),
					JOT_IPv4("IPv4",ip_address),
					0);*/
            } else {
				/*JOTDOWN(squirrel,
					JOT_PRINT("ID-DNS", name,	name_length),
					JOT_PRINT("Server", name2,	name2_length),
					JOT_NUM("Port", port),
					0);*/
                ;
            }
		}
		break;
	default:
		FRAMERR(frame, "dns: unknown type=%d (class=%d, name=%s)\n", rec->type, rec->clss, name);
	}
}

static void 
dns_parse_question_record(struct Squirrel *squirrel, struct StackFrame *frame, 
						  const unsigned char *px, unsigned length, 
						  struct DNSRECORD *rec, struct DNS *dns)
{
	char name[512]; /* reserve a longer name than the max theoretical limit */
	unsigned name_length;


	/* If this is actually a bonjour packet, then pass it off to the
	 * Bonjour module */
	if (!dns->is_response && frame->dst_port == 5353)
		bonjour_parse_question_record(squirrel, frame, px, length, rec, dns);
	else if (dns->is_response && frame->src_port == 5353) 
		bonjour_parse_question_record(squirrel, frame, px, length, rec, dns);

	/* First, let's extract a pretty version of the name */
	name_length = dns_extract_name(frame, px, length, rec->name_offset, name, sizeof(name));

	switch (rec->type<<16 | rec->clss) {
	case TYPECLASS(1,1): /* type=A(IPv4 address), class=INTERNET*/
		if (!is_valid_opcode(dns->opcode, 0, 0x10, -1)) {
			FRAMERR(frame, "%s: unknown opcode=%d\n", "DNS", dns->opcode);
			return;
		}
		/*JOTDOWN(squirrel,
			JOT_SZ("proto","DNS"),
			JOT_SZ("query","A"),
			"ip.src", dns->is_response?REC_FRAMEDST:REC_FRAMESRC,  frame, -1,
			JOT_PRINT("name", name, name_length),
			0);*/
		break;
	case TYPECLASS(2,1): /* type=NS(name-server), class=INTERNET*/
		if (!is_valid_opcode(dns->opcode, 0x10, -1)) {
			FRAMERR(frame, "%s: unknown opcode=%d\n", "DNS", dns->opcode);
			return;
		}
		/*JOTDOWN(squirrel,
			JOT_SZ("proto","DNS"),
			JOT_SZ("query","NS"),
			"ip.src", dns->is_response?REC_FRAMEDST:REC_FRAMESRC,  frame, -1,
			JOT_PRINT("name", name, name_length),
			0);*/
		break;
	case TYPECLASS(6,1): /* type=SOA(Start of Authority), class=INTERNET*/
		if (!is_valid_opcode(dns->opcode, 0x10, -1)) {
			FRAMERR(frame, "%s: unknown opcode=%d\n", "DNS", dns->opcode);
			return;
		}
		/*JOTDOWN(squirrel,
			JOT_SZ("proto","DNS"),
			JOT_SZ("query","SOA"),
			"ip.src", dns->is_response?REC_FRAMEDST:REC_FRAMESRC,  frame, -1,
			JOT_PRINT("name", name,	name_length),
			0);*/
		break;
	case TYPECLASS(10,1): /* type=NULL, class=INTERNET*/
		/* Regress: defcon2008-dns2.pcap(100803): name=Vaaaaiaqaac.tunnel.fastcoder.net */
		/* I'm not sure what this is, other than passing data as Null records.
		 * This would be a good thing for an intrusion-detection system to trigger
		 * on. */
		break;
	case TYPECLASS(12,1): /* type=PTR(pointer, aka. reverse), class=INTERNET*/
		if (!is_valid_opcode(dns->opcode, 0x10, -1)) {
			FRAMERR(frame, "%s: unknown opcode=%d\n", "DNS", dns->opcode);
			return;
		}
		/*JOTDOWN(squirrel,
			JOT_SZ("proto","DNS"),
			JOT_SZ("op","reverse"),
			"ip.src",	dns->is_response?REC_FRAMEDST:REC_FRAMESRC, frame, -1,
			JOT_PRINT("name",		 	name,						name_length),
			0);*/
		break;
	case TYPECLASS(13,1): /* type=HINFO, class=INTERNET*/
		/* Regress: defcon2008-dns2.pcap(292428) */
		break;
	case TYPECLASS(15,1): /* type=MX, class=INTERNET*/
		/* Regress: defcon2008-dns2.pcap(18661) */
		break;
	case TYPECLASS(16,1): /* type=TXT(text), class=INTERNET*/
		/* CASE: I see these in mDNS. A machine sends out a query for a
		 * record to the multi-cast address right before it then multi-casts
		 * the answer. I don't think there is anything useful to extract here
		 * at this time */

		if (!is_valid_opcode(dns->opcode, OP_QUERY, 0x10, -1)) {
			FRAMERR(frame, "%s: unknown opcode=%d\n", "DNS", dns->opcode);
			return;
		}
		break;
	case TYPECLASS(35,1): /* type=NAPTR(naming authority pointer), class=INTERNET*/
		if (!is_valid_opcode(dns->opcode, OP_QUERY, 0x10, -1)) {
			FRAMERR(frame, "%s: unknown opcode=%d\n", "DNS", dns->opcode);
			return;
		}
		/* Reference: defcon2008-dns2.pcap(277617) */
		break;
	case TYPECLASS(0x1c,1): /* type=AAAA(IPv6 address), class=INTERNET*/
		if (!is_valid_opcode(dns->opcode, 0x10, -1)) {
			FRAMERR(frame, "%s: unknown opcode=%d\n", "DNS", dns->opcode);
			return;
		}
		/*JOTDOWN(squirrel,
			JOT_SZ("proto","DNS"),
			JOT_SZ("query","AAAA"),
			"ip.src", dns->is_response?REC_FRAMEDST:REC_FRAMESRC,  frame, -1,
			JOT_PRINT("name", name, name_length),
			0);*/
		break;
	case TYPECLASS(0x1c,0x8001): /* type=AAAA(IPv6 address), class=mDNS-FLUSH*/
		if (!is_valid_opcode(dns->opcode, -1)) {
			FRAMERR(frame, "%s: unknown opcode=%d\n", "DNS", dns->opcode);
			return;
		}
		/* TODO: move this to the mDNS-Bonjour parser */
		/*JOTDOWN(squirrel,
			JOT_SZ("proto","MDNS"),
			JOT_SZ("query","AAAA"),
			"ip.src", dns->is_response?REC_FRAMEDST:REC_FRAMESRC,  frame, -1,
			JOT_PRINT("flush", name, name_length),
			0);*/
		break;
	case TYPECLASS(0x21,1): /* type=SRV(Service Location), class=INTERNET*/
		if (!is_valid_opcode(dns->opcode, OP_QUERY, 0x10, -1)) {
			FRAMERR(frame, "%s: unknown opcode=%d\n", "DNS", dns->opcode);
			return;
		}
		/*JOTDOWN(squirrel,
			JOT_SZ("proto","DNS"),
			JOT_SZ("query","srv"),
			"ip.src", dns->is_response?REC_FRAMEDST:REC_FRAMESRC,  frame, -1,
			JOT_PRINT("name",		 	name,						name_length),
			0);*/
		break;
	/*case TYPECLASS(255,1):*/ /* type=ANY, class=INTERNET*/
	case TYPECLASS(255,0x8001): /* type=ANY, class=FLUSH(mDNS/Bonjour)*/
		if (!is_valid_opcode(dns->opcode, -1)) {
			FRAMERR(frame, "%s: unknown opcode=%d\n", "DNS", dns->opcode);
			return;
		}
		/*JOTDOWN(squirrel,
			JOT_SZ("proto","DNS"),
			JOT_SZ("op","flush"),
			"ip.src",	dns->is_response?REC_FRAMEDST:REC_FRAMESRC, frame, -1,
			JOT_PRINT("name",		 	name,						name_length),
			0);*/
		if (endsWith(name, "._ipp._tcp.local")) {
			/*JOTDOWN(squirrel,
				"Bonjour",	dns->is_response?REC_FRAMEDST:REC_FRAMESRC, frame, -1,
				JOT_PRINT("Printer", name, name_length-strlen("._ipp._tcp.local")),
				0);*/
        } else if (endsWith(name, ".local")) {
			/*JOTDOWN(squirrel,
				"ID-IP",	dns->is_response?REC_FRAMEDST:REC_FRAMESRC, frame, -1,
				JOT_PRINT("name",		 	name,						name_length-strlen(".local")),
				0);*/
        } else
			FRAMERR(frame, "%s: unknown value: %s\n", "dns", name);

		break;
	case TYPECLASS(255,1): /* type=ANY, class=INTERNET*/
		if (!is_valid_opcode(dns->opcode, 0, 0x10, -1)) {
			FRAMERR(frame, "%s: unknown opcode=%d\n", "DNS", dns->opcode);
			return;
		}
		/*JOTDOWN(squirrel,
			JOT_SZ("proto","DNS"),
			JOT_SZ("query","ANY"),
			"ip.src", dns->is_response?REC_FRAMEDST:REC_FRAMESRC,  frame, -1,
			JOT_PRINT("name", name, name_length),
			0);*/
		break;
	default:
		FRAMERR(frame, "dns: unknown [type=0x%x(%d), class=0x%x(%d)] name=%s)\n", 
				rec->type, rec->type, 
				rec->clss, rec->clss, 
				name);
	}
}

void squirrel_dns(struct Squirrel *squirrel, struct StackFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned offset;
	struct DNS dns[1];
	unsigned record_count;
	unsigned total_records;
	unsigned i;

	/* Count the number of DNS packets we process. This includes
	 * all types of DNS */
	//squirrel->statistics.dns++;

	memset(dns, 0, sizeof(dns[0]));

	if (length < 12) {
		/* Regress: defcon2008-dns2.pcap(95639) */
		; //FRAMERR(frame, "dns: frame too short\n");
		return;
	}


	/* Parse the DNS header, the 'fixed' portion of the packet
	 * before the variable length records 
		+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
		|                      ID                       |
		+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
		|QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
		+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
		|                    QDCOUNT                    |
		+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
		|                    ANCOUNT                    |
		+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
		|                    NSCOUNT                    |
		+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
		|                    ARCOUNT                    |
		+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
	ID              A 16 bit identifier assigned by the program that
					generates any kind of query.  This identifier is copied
					the corresponding reply and can be used by the requester
					to match up replies to outstanding queries.
	QR              A one bit field that specifies whether this message is a
					query (0), or a response (1).
	OPCODE          A four bit field that specifies kind of query in this
					message.  This value is set by the originator of a query
					and copied into the response.  The values are:
					0               a standard query (QUERY)
					1               an inverse query (IQUERY)
					2               a server status request (STATUS)
					3-15            reserved for future use
	AA              Authoritative Answer - this bit is valid in responses,
					and specifies that the responding name server is an
					authority for the domain name in question section.

					Note that the contents of the answer section may have
					multiple owner names because of aliases.  The AA bit
					corresponds to the name which matches the query name, or
					the first owner name in the answer section.
	TC              TrunCation - specifies that this message was truncated
					due to length greater than that permitted on the
					transmission channel.
	RD              Recursion Desired - this bit may be set in a query and
					is copied into the response.  If RD is set, it directs
					the name server to pursue the query recursively.
					Recursive query support is optional.
	RA              Recursion Available - this be is set or cleared in a
					response, and denotes whether recursive query support is
					available in the name server.
	Z               Reserved for future use.  Must be zero in all queries
					and responses.
	RCODE           Response code - this 4 bit field is set as part of
					responses.  The values have the following
					interpretation:
					0               No error condition
					1               Format error - The name server was
									unable to interpret the query.
					2               Server failure - The name server was
									unable to process this query due to a
									problem with the name server.
					3               Name Error - Meaningful only for
									responses from an authoritative name
									server, this code signifies that the
									domain name referenced in the query does
									not exist.
					4               Not Implemented - The name server does
									not support the requested kind of query.
					5               Refused - The name server refuses to
									perform the specified operation for
									policy reasons.  For example, a name
									server may not wish to provide the
									information to the particular requester,
									or a name server may not wish to perform
									a particular operation (e.g., zone
					6-15            Reserved for future use.
	QDCOUNT         an unsigned 16 bit integer specifying the number of
					entries in the question section.
	ANCOUNT         an unsigned 16 bit integer specifying the number of
					resource records in the answer section.
	NSCOUNT         an unsigned 16 bit integer specifying the number of name
					server resource records in the authority records
					section.
	ARCOUNT         an unsigned 16 bit integer specifying the number of
					resource records in the additional records section.
	*/

	dns->id = ex16be(px+0);
	dns->is_response = ((px[2]&0x80) != 0);
	dns->opcode = (px[2]>>3)&0x01F;
	dns->flags = ex16be(px+2)&0x7F0;
	dns->rcode = px[3]&0x0F;

	dns->question_count = ex16be(px+4);
	dns->answer_count = ex16be(px+6);
	dns->authority_count = ex16be(px+8);
	dns->additional_count = ex16be(px+10);

	/* Remember a total count of the records. There are a lot of corrupted packets
	 * with data after the counted records, so we need to stop parsing once all
	 * the counted records have been parsed. */
	total_records = dns->question_count + dns->answer_count + dns->authority_count + dns->additional_count;

	offset = 12;
	record_count = 0;

    if (!dns->is_response && frame->dst_port == 137) {
        if (frame->ip_ttl == 64 || frame->ip_ttl == 128 || frame->ip_ttl == 255) {
            char textip[16];
            sprintf_s(textip, sizeof(textip), "%u.%u.%u.%u",
                (frame->src_ipv4>>24)&0xFF,
                (frame->src_ipv4>>16)&0xFF,
                (frame->src_ipv4>> 8)&0xFF,
                (frame->src_ipv4>> 0)&0xFF
                );
            sqdb_add_info(	squirrel->sqdb, 
			        frame->src_mac,
                          frame->wifi.bss_mac,
			        "ip",
			        textip, -1);
        }
    }

	/* After parsing the fixed header, we no PRE-PROCESS the variable length records.
	 * All we want to do at this point is to find their locations within the packet.
	 * The reason we want to pre-process these is that some records will refer to
	 * other records in the same packet. A good example are CNAME records 
	 * that require looking up other records in order to fully resolve. We can
	 * do the resolution easier if we can preprocess the list first */
	while (offset < length && record_count < 100) {
		struct DNSRECORD *rec = &dns->records[record_count];

		/* Even if there is remaining data in the packet, do not parse past
		 * the total count of all the records */
		if (record_count >= total_records) {
			//SAMPLE(squirrel,"dns", JOT_NUM("too-many-records", total_records));
			break;
		}

		/* NAME
		 * The first part of a DNS record is the variable length name. The name
		 * consists of a sequence of LABELS. Each label starts with a tag. The 
		 * tag can be one of three things:
		 *	- a value of zero, which ends the name
		 *	- a length from 1-63, which means we need to continue processing
		 *    more labels
		 *  - a two-byte 'pointer' to the remainder of the name, which means that
		 *	  we stop pre-processing the name. We don't actually parse out the
		 *	  full name at this stage in the code (so we won't follow that pointer),
		 *	  we are just concerned with skipping the name at this point. */
		rec->name_offset = offset;
		while (offset < length) {

			/* Test for end label */
			if (px[offset] == 0x00) {
				offset++;
				break;
			}

			/* Test for compression 'pointer' */
			if (px[offset] & 0xC0) {
				offset += 2;
				break;
			}

			/* Skip the 'length' number of bytes, plus the length byte itself */
			offset += px[offset] + 1;

			if (offset > length) {
				FRAMERR(frame, "dns: past end of packet\n");
				return;
			}
		}

		/* Now parse out the 'type' and 'class' fields. These are the
		 * 4 bytes immediately following the name */
		if (offset + 4 > length) {
			FRAMERR(frame, "dns: past end of packet\n");
			return;
		}
		rec->type = ex16be(px+offset+0);
		rec->clss = ex16be(px+offset+2);
		offset += 4;
		record_count++;


		/* If this is a 'question' record, then we don't do any further processing.
		 * Since question records are just asking for data, they don't contain
		 * any data themselves. Otherwise, if the record will contain data that
		 * we need to also parse */
		if (record_count <= dns->question_count)
			continue;
		
		/* This bit of code parses out the remainder of the data in the record. For
		 * the most part, we just need to parse the 'length' field for the record
		 * data, remember it for use later, then skip the remainder of this record
		 * and continue processing the next record */
		if (offset + 6 > length) {
			/* Regress: defcon2008-dns2.pcap(88069) */
			FRAMERR(frame, "dns: past end of packet\n");
			return;
		}
		rec->ttl = ex32be(px+offset+0);
		rec->rdata_length = ex16be(px+offset+4);
		offset += 6;
		rec->rdata_offset = offset;
		offset += rec->rdata_length;

		if (offset > length) {
			FRAMERR(frame, "dns: past end of packet\n");
			return;
		}
	}
	dns->record_count = record_count;

	/* We stored the records in one large array, but there are four kinds
	 * of records (questions, answers, authority, additional). We figure out
	 * which records belong to which type according to the counts */
	if (dns->question_count > record_count) {
		dns->question_count = record_count;
		FRAMERR(frame, "%s: bad record count\n", "DNS");
	}
	if (dns->answer_count > record_count - dns->question_count) {
		dns->answer_count = record_count - dns->question_count;
		/* Regress: defcon2008-dns2.pcap(158112) */
		; //FRAMERR(frame, "%s: bad record count\n", "DNS");
	}
	if (dns->authority_count > record_count - dns->question_count - dns->answer_count) {
		dns->authority_count = record_count - dns->question_count - dns->answer_count;
		FRAMERR(frame, "%s: bad record count\n", "DNS");
	}
	if (dns->additional_count > record_count - dns->question_count - dns->answer_count - dns->authority_count) {
		dns->additional_count = record_count - dns->question_count - dns->answer_count - dns->authority_count;
		FRAMERR(frame, "%s: bad record count\n", "DNS");
	}
	dns->questions = &dns->records[0];
	dns->answers = &dns->records[dns->question_count];
	dns->authorities = &dns->records[dns->question_count + dns->answer_count];
	dns->additionals = &dns->records[dns->question_count + dns->answer_count + dns->authority_count];

	/* 
	 * First, we parse out all the question records. These don't contain any data
	 * themselves, but they do give us interesting information about what a client
	 * is looking for. Also, some protocols, such as NetBIOS and mDNS/Bonjour will
	 * tell us additional information about the client.
	 */
	if (dns->is_response && dns->rcode == 0)
	for (i=0; i<dns->question_count; i++) {
		struct DNSRECORD *rec = &dns->questions[i];
		dns_parse_question_record(squirrel, frame, px, length, rec, dns);
	}

	/* Now parse all the resource records after the questions */
	for (i=0; i<dns->answer_count; i++) {
		struct DNSRECORD *rec = &dns->answers[i];
		dns_parse_resource_record(squirrel, frame, px, length, rec, dns);
	}
	for (i=0; i<dns->authority_count; i++) {
		struct DNSRECORD *rec = &dns->authorities[i];
		dns_parse_resource_record(squirrel, frame, px, length, rec, dns);
	}
	for (i=0; i<dns->additional_count; i++) {
		struct DNSRECORD *rec = &dns->additionals[i];
		dns_parse_resource_record(squirrel, frame, px, length, rec, dns);
	}

#if 0
	switch (dns->opcode) {
	case 0x00: /*query request*/
	case 0x10: /*query response */

		switch (dns->rcode) {
		case 0:
		case 3: /* No such name */
			SAMPLE(squirrel,"DNS", JOT_NUM("rcode", dns->rcode));
			break;
		case 2: /* Server error */
			SAMPLE(squirrel,"DNS", JOT_NUM("rcode", dns->rcode));
			break;
		default:
			FRAMERR(frame, "dns: unknown rcode=%d (opcode=%d)\n", dns->rcode, dns->opcode);
		}
		break;
	case 0x06: /*release*/
		switch (dns->rcode) {
		case 0:
			for (i=0; i<dns->additional_count; i++) {
				char name[256];
				unsigned name_length;
				struct DNSRECORD *rec = &dns->additionals[i];

				if (rec->type == 0x8001)
					FRAMERR(frame, "test\n");

				name_length = dns_extract_name(frame, px, length, rec->name_offset, name, sizeof(name));

				switch (rec->type) {
				case 0x0020: /*NETBIOS */
					switch (rec->clss) {
					case 0x0001: /*INTERNET*/
						{
							unsigned ip_address = ex32be(px+rec->rdata_offset+2);
							char netbios_name[256];

							if (rec->rdata_length != 6)
								FRAMERR(frame, "dns: data not 4-bytes long, was %d-bytes instead (class=%d, type=%d, name=%s)\n", rec->rdata_length, rec->clss, rec->type, name);

							translate_netbios_name(frame, name, netbios_name, sizeof(netbios_name));

							/*JOTDOWN(squirrel,
								JOT_SZ("proto","NETBIOS"),
								JOT_SZ("op","release"),
								JOT_DST("ip.src", frame),
								JOT_PRINT("name",		 	netbios_name,				strlen(netbios_name)),
								JOT_IPv4("address", ip_address),
								0);*/

							/*JOTDOWN(squirrel,
								JOT_IPv4("ID-IP", ip_address),
								JOT_PRINT("netbios",	 	netbios_name,				strlen(netbios_name)),
								0);*/

						}
						break;
					default:
						FRAMERR(frame, "dns: unknown class=%d (type=%d, name=%s)\n", rec->clss, rec->type, name);
					}
					break;
				default:
					FRAMERR(frame, "dns: unknown type=%d (class=%d, name=%s)\n", rec->type, rec->clss, name);
				}
			}
		}
		break;
	case 0x05: /*netbios registration request*/
		if (frame->dst_port == 53)
			dns_dynamic_update(squirrel, frame, px, length, dns);
		else
			process_request_update(squirrel, frame, px, length, dns);
		break;
	case 0x08:
		for (i=0; i<dns->additional_count; i++)
			DECODEANSWER(squirrel, frame, px, length, dns, &dns->additionals[i], "refresh");
		break;
	case 0x01: /*inverse query request*/
	case 0x11: /*inverse query reqsponse*/
	case 0x02: /*status request*/
	case 0x12: /*status response*/
	case 0x04: /*notify request*/
	case 0x14: /*notify response*/
	case 0x15: /*update response*/
	case 0x0f: /*multi-home registration*/
		for (i=0; i<dns->additional_count; i++)
			DECODEANSWER(squirrel, frame, px, length, dns, &dns->additionals[i], "multi-home");
		break;
	default:
		FRAMERR(frame, "dns: unknown opcode %d\n", dns->opcode);
	}
#endif
}

