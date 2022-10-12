/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
#include "squirrel.h"
#include "stack-frame.h"
#include "util-extract.h"
#include "sift.h"
#include "util-annexk.h"
#include "util-unused.h"
#include <ctype.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

#ifndef bool
#define bool int
#endif
#ifndef true
#define true 1
#endif
#ifndef false
#define false 0
#endif

typedef void *(*FERRET_PARSER)(void);

enum {
	TCP_FIN=1,
	TCP_SYN=2,
	TCP_RST=4,
	TCP_PSH=8,
	TCP_ACK=16,
	TCP_URG=32,
};

enum {
	TCP_LOOKUP,
	TCP_CREATE,
	TCP_DESTROY,
};

static void tcp_syn(struct Squirrel *squirrel, struct StackFrame *frame)
{
	UNUSEDPARM(squirrel);UNUSEDPARM(frame);
}
static void tcp_synack(struct Squirrel *squirrel, struct StackFrame *frame)
{
	UNUSEDPARM(squirrel);UNUSEDPARM(frame);
}
static void tcp_fin(struct Squirrel *squirrel, struct StackFrame *frame)
{
	UNUSEDPARM(squirrel);UNUSEDPARM(frame);
}


/**
 * Runs a heuristic over the packet data to see if it looks like the HTTP 
 * protocol. This is because we can't rely upon HTTP running on port 80,
 * it can run on any arbitrary port */
static int 
smellslike_httprequest(const unsigned char *data, unsigned length)
{
	unsigned i;
	unsigned method;
	unsigned url;

	for (i=0; i<length && isspace(data[i]); i++)
		;
	method = i;
	while (i<length && !isspace(data[i]))
		i++;
	if (i>10)
		return 0;
	while (i<length && isspace(data[i]))
		i++;
	url = i;
	while (i<length && data[i] != '\n')
		i++;

	if (i>0 && data[i] == '\n') {
		i--;

		if (i>0 && data[i] == '\r')
			i--;

		if (i>10 && memcasecmp((const char*)&data[i-7], "HTTP/1.0", 8) == 0)
			return 1;
		if (i>10 && memcasecmp((const char*)&data[i-7], "HTTP/1.1", 8) == 0)
			return 1;
		if (i>10 && memcasecmp((const char*)&data[i-7], "HTTP/0.9", 8) == 0)
			return 1;
		
	}

	return 0;
}

int smellslike_msn_messenger(const unsigned char *data, unsigned length)
{
	unsigned i=0;
	unsigned method;
	unsigned method_length=0;
	unsigned parms;
	unsigned non_printable_count = 0;
	unsigned line_length;

	if (smellslike_httprequest(data, length))
		return 0;


	method = i;
    while (i<length && !isspace(data[i])) {
        i++;
        method_length++;
    }
	while (i<length && data[i] != '\n' && isspace(data[i]))
		i++;
	parms = i;
	while (i<length && data[i] != '\n')
		i++;
	line_length = i;

	for (i=0; i<length; i++)
		if (!(isprint(data[i]) || isspace(data[i])))
			non_printable_count++;


	if (method_length == 3 && data[line_length] == '\n' && non_printable_count == 0)
		return 1;

	return 0;
}



/**
 * Run various heuristics on the TCP connection in order to figure out a likely
 * protocol parser for it.
 */
FERRET_PARSER tcp_smellslike(const unsigned char *px, unsigned length, unsigned src_port, unsigned dst_port)
{
    UNUSEDPARM(px);
    UNUSEDPARM(length);
    UNUSEDPARM(src_port);
    UNUSEDPARM(dst_port);
	/*if (smellslike_httprequest(px, length))
		return (FERRET_PARSER)parse_http_request;*/

	/*if ((src_port == 5190 || dst_port == 5190) && length > 6 && px[0] == 0x2a && 1 <= px[1] && px[1] <= 5)
		return (FERRET_PARSER)parse_aim_oscar;*/

	/* I'm not sure why, but I saw AIM traffic across port 443, but not SSL
	 * encrypted. I assume that the AIM client does this in order to avoid
	 * being firewalled. */
	/*if ((src_port == 443 || dst_port == 443) && length > 6 && px[0] == 0x2a && 1 <= px[1] && px[1] <= 5 && smellslike_aim_oscar(px, length))
		return (FERRET_PARSER)parse_aim_oscar;*/


	return NULL;
}



/**
 * This function processes acknowledgements. The primary idea behind this
 * function is to see if we've missed any packets on a TCP connection,
 * such as when monitoring wireless networks. When we miss packets,
 * we have to figure out how to repair our TCP state. One easy
 * way is to simply delete the connect and start over again.
 */
static void 
tcp_ack_data(struct Squirrel *squirrel, struct StackFrame *frame, unsigned seqno)
{
    UNUSEDPARM(squirrel);
    UNUSEDPARM(frame);
    UNUSEDPARM(seqno);
}


unsigned tcp_hash(unsigned ip_src, unsigned ip_dst, unsigned port_src, unsigned port_dst)
{
	unsigned result;

	result = ip_src;
	result ^= ip_dst*2;
	result ^= port_src;
	result ^= port_dst*2;

	result &= 4096-1;
	return result;
}

unsigned track_connection(struct Squirrel *squirrel, unsigned ip_src, unsigned ip_dst, unsigned port_src, unsigned port_dst, unsigned seqno, unsigned do_track)
{
	unsigned index;
	struct TCPENTRY **r_record;
	index = tcp_hash(ip_src, ip_dst, port_src, port_dst);

	r_record = &squirrel->connections[index];

	while (*r_record) {
		struct TCPENTRY *r = *r_record;

		if (r->ip_src == ip_src && r->ip_dst == ip_dst && r->port_src == port_src && r->port_dst == port_dst)
			break;

		r_record = &(r->next);
	}


	if (*r_record == NULL) {
		struct TCPENTRY *r;
		
		/* If 'do_track' is set, then it forces us to create a new entry.
		 * Otherwise, if the connection doens't exist, we don't track it */
		if (!do_track)
			return 0;

		r = (struct TCPENTRY *)malloc(sizeof(*r));
		memset(r, 0, sizeof(*r));
		r->ip_src = ip_src;
		r->ip_dst = ip_dst;
		r->port_src = (unsigned short)port_src;
		r->port_dst = (unsigned short)port_dst;
		r->first_seqno = seqno;
		r->next = NULL;
	
		*r_record = r;
	}

	(*r_record)->packet_count++;
	
	if ((seqno-(*r_record)->first_seqno) > 20000)
		return 0;
	if ((*r_record)->packet_count > 20)
		return 0;
	return 1;
}


bool find_string(const unsigned char *px, unsigned length, const char *str, unsigned *offset)
{
    size_t str_length = strlen(str);
    unsigned i;
    int c = toupper(str[0]);

    if (str_length > length)
        return false;
    else
        length -= str_length;

    for (i=0; i<=length; i++) {
        if (toupper(px[i]) == c) {
            if (memcasecmp(px+i, str, str_length) == 0) {
                if (offset)
                    *offset = (unsigned)(i + str_length);
                return true;
            }
        }
    }
    return false;
}

static unsigned next_integer(const unsigned char *px, unsigned length, unsigned *offset)
{
    unsigned result = 0;
    unsigned i = *offset;

    while (i < length && !isdigit(px[i]))
        i++;

    while (i < length && isdigit(px[i])) {
        result = result * 10 + (px[i] - '0');
        i++;
    }
    *offset = i;
    return result;
}

void squirrel_http_useragent(struct Squirrel *squirrel, struct StackFrame *frame, const unsigned char *px, unsigned length)
{
    unsigned osver;
    char iptext[16];
    unsigned ip = frame->src_ipv4;
    char systemtext[32];

    if (frame->ip_ttl != 64 && frame->ip_ttl != 128 && frame->ip_ttl != 255)
        return;

    sprintf_s(iptext, sizeof(iptext), "%u.%u.%u.%u",
        (ip>>24)&0xFF, (ip>>16)&0xFF, (ip>>8)&0xFF, (ip>>0)&0xFF
        );

    sqdb_add_info(	squirrel->sqdb, 
					frame->src_mac,
					frame->bss_mac,
					"ip",
					iptext, -1);

    //User-Agent: CaptiveNetworkSupport/1.0 wispr
    if (find_string(px, length, "CaptiveNetworkSupport/1.0 wispr", 0)) {
        sqdb_add_info(	squirrel->sqdb, 
						frame->src_mac,
						frame->bss_mac,
						"ip",
						iptext, -1);
        sqdb_add_info(	squirrel->sqdb, 
						frame->src_mac,
						frame->bss_mac,
						"system",
						"iPod", -1);
    }

    //User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30; .NET CLR 3.0.04506.648; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729)
    if (find_string(px, length, "; Windows NT 5.1; ", 0)) {
        sqdb_add_info(	squirrel->sqdb, 
						frame->src_mac,
						frame->bss_mac,
						"system",
						"WinXP", -1);
    }

    //User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.3) Gecko/20091007 Ubuntu/9.10 (karmic) Firefox/3.5.3\r\n
    if (find_string(px, length, "Linux", 0)) {
        if (find_string(px, length, " Linux i686;", &osver)) {
            sqdb_add_info(	squirrel->sqdb, 
						    frame->src_mac,
						    frame->bss_mac,
						    "cpu",
						    "x86", -1);

            while (osver < length && isspace(px[osver]))
                osver++;
            if (length-osver >= 3 && isalpha(px[osver]) && isalpha(px[osver+1]) && !isalpha(px[osver+2])) {
                char lang[3];
                lang[0] = px[osver+0];
                lang[1] = px[osver+1];
                lang[2] = '\0';
                sqdb_add_info(	squirrel->sqdb, 
						        frame->src_mac,
						        frame->bss_mac,
						        "lang",
						        lang, -1);
            }

        }
        if (find_string(px, length, " Ubuntu/", &osver)) {
            unsigned ver_major;
            unsigned ver_minor = 0;

            ver_major = next_integer(px, length, &osver);
            if (px[osver] == '.')
                ver_minor = next_integer(px, length, &osver);
            sprintf_s(systemtext, sizeof(systemtext), "Unbuntu/%u.%u", ver_major, ver_minor);
            sqdb_add_info(	squirrel->sqdb, 
						    frame->src_mac,
						    frame->bss_mac,
						    "system",
						    systemtext, -1);

        }
    }

    //User-Agent: Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_5_8; en-us) AppleWebKit/531.9 (KHTML, like Gecko) Version/4.0.3 Safari/531.9\r\n
    if (find_string(px, length, "(Macintosh; ", 0)) {
        if (find_string(px, length, " AppleWebKit/", 0) || find_string(px, length, "Firefox/", 0)) {
            if (find_string(px, length, " Mac OS X 10_", &osver) || find_string(px, length, " Mac OS X 10.", &osver)) {
                unsigned ver_minor;
                unsigned ver_minor_sub=0;

               	sqdb_add_info(	squirrel->sqdb, 
						        frame->src_mac,
						        frame->bss_mac,
						        "ip",
						        iptext, -1);

                ver_minor = next_integer(px, length, &osver);
                if (px[osver] == '.' || px[osver] == '_')
                    ver_minor_sub = next_integer(px, length, &osver);
                
                sprintf_s(systemtext, sizeof(systemtext), "MacOS/10.%u.%u", ver_minor, ver_minor_sub);
               	sqdb_add_info(	squirrel->sqdb, 
						        frame->src_mac,
						        frame->bss_mac,
						        "system",
						        systemtext, -1);

            }
        }
    }

    //User-Agent: Mozilla/5.0 (iPhone; U; CPU iPhone OS 3_0_1 like Mac OS X; en-us) AppleWebKit/528.18 (KHTML, like Gecko) Mobile/7A400\r\n
    if (find_string(px, length, "(iPhone; ", 0)) {
        if (find_string(px, length, " AppleWebKit/", 0)) {
            if (find_string(px, length, " iPhone OS ", &osver)) {
                unsigned ver_major;
                unsigned ver_minor;
                unsigned ver_minor_sub;

               	sqdb_add_info(	squirrel->sqdb, 
						        frame->src_mac,
						        frame->bss_mac,
						        "ip",
						        iptext, -1);

                ver_major = next_integer(px, length, &osver);
                ver_minor = next_integer(px, length, &osver);
                ver_minor_sub = next_integer(px, length, &osver);
                
                sprintf_s(systemtext, sizeof(systemtext), "iPhone/%u.%u.%u", ver_major, ver_minor, ver_minor_sub);
               	sqdb_add_info(	squirrel->sqdb, 
						        frame->src_mac,
						        frame->bss_mac,
						        "system",
						        systemtext, -1);

            }
        }
    }

}

void squirrel_http(struct Squirrel *squirrel, struct StackFrame *frame, const unsigned char *px, unsigned length)
{
    unsigned u, n;

    if (length > 5) {
        if (memcmp(px, "GET ", 4) == 0 || memcmp(px, "POST ", 5) == 0)
            ;
        else
            return;
    }

    if (!find_string(px, length, "User-Agent:", &u))
        return;

    while (u < length && isspace(px[u]) && px[u] != '\n')
        u++;

    for (n=u; n<length && px[n] != '\n'; n++)
        ;
    if (px[n] != '\n')
        return;
    while (n > u && isspace(px[n-1]))
        n--;

    squirrel_http_useragent(squirrel, frame, px+u, n-u);

}


/**
 * This is the primary function called to analyze a bit of data from a 
 * TCP connection.
 */
static void 
tcp_data(struct Squirrel *squirrel, struct StackFrame *frame, const unsigned char *px, unsigned length, unsigned seqno, unsigned ackno)
{
    UNUSEDPARM(ackno);
	if (squirrel->filter.something_tcp || frame->flags.found.filtered == 0) {
		if (squirrel->filter.is_ssh) {
			if (length > 6 && memcmp(px, "SSH-2.0", 4)==0) {
				if (track_connection(squirrel, frame->src_ipv4, frame->dst_ipv4, frame->src_port, frame->dst_port, seqno, 1))
					frame->flags.found.filtered = 1;
			}
		}
	}

    if (frame->dst_port == 80) {
        squirrel_http(squirrel, frame, px, length);
    }

}
void squirrel_tcp(struct Squirrel *squirrel, struct StackFrame *frame, const unsigned char *px, unsigned length)
{
	struct {
		unsigned src_port;
		unsigned dst_port;
		unsigned seqno;
		unsigned ackno;
		unsigned header_length;
		unsigned flags;
		unsigned window;
		unsigned checksum;
		unsigned urgent;
	} tcp;


	if (length == 0) {
		FRAMERR(frame, "tcp: frame empty\n");
		return;
	}
	if (length < 20) {
		FRAMERR(frame, "tcp: frame too short\n");
		return;
	}

/*
	    0                   1                   2                   3   
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Source Port          |       Destination Port        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Sequence Number                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Acknowledgment Number                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Data |           |U|A|P|R|S|F|                               |
   | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
   |       |           |G|K|H|T|N|N|                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Checksum            |         Urgent Pointer        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             data                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

	tcp.src_port = ex16be(px+0);
	tcp.dst_port = ex16be(px+2);
	tcp.seqno = ex32be(px+4);
	tcp.ackno = ex32be(px+8);
	tcp.header_length = px[12]>>2;
	tcp.flags = px[13];
	tcp.window = ex16be(px+14);
	tcp.checksum = ex16be(px+16);
	tcp.urgent = ex16be(px+18);

	frame->src_port = tcp.src_port;
	frame->dst_port = tcp.dst_port;

	if (squirrel->filter.something_tcp) {
		unsigned do_track=0;


		if (filter_has_port(squirrel->filter.tcp_ports, squirrel->filter.tcp_port_count, tcp.src_port))
			do_track = 1;
		if (filter_has_port(squirrel->filter.tcp_ports, squirrel->filter.tcp_port_count, tcp.dst_port))
			do_track = 1;


		if (track_connection(squirrel, frame->src_ipv4, frame->dst_ipv4, tcp.src_port, tcp.dst_port, tcp.seqno, do_track))
			frame->flags.found.filtered = 1;
	}


	if (tcp.header_length < 20) {
		FRAMERR(frame, "tcp: header too short, expected length=20, found length=%d\n", tcp.header_length);
		return;
	}
	if (tcp.header_length > length) {
		FRAMERR(frame, "tcp: header too short, expected length=%d, found length=%d\n", tcp.header_length, length);
		return;
	}
	if ((tcp.flags & 0x20) && tcp.urgent > 0) {
		FRAMERR(frame, "tcp: found %d bytes of urgent data\n", tcp.urgent);
		return;
	}

	if (tcp.header_length > 20) {
		unsigned o = 20;
		unsigned max = tcp.header_length;

		while (o < tcp.header_length) {
			unsigned tag = px[o++];
			unsigned len;

			if (tag == 0)
				break;
			if (tag == 1)
				continue;

			if (o >= max) {
				FRAMERR(frame, "tcp: options too long\n");
				break;
			}
			len = px[o++];

			if (len < 2) {
				FRAMERR(frame, "tcp: invalid length field\n");
				break;
			}
			if (o+len-2 > max) {
				FRAMERR(frame, "tcp: options too long\n");
				break;
			}

            SIFT_UNSIGNED("tcp.option_kind", tag);
			switch (tag) {
			case 0x02: /* max seg size */
				if (len != 4)
					FRAMERR(frame, "tcp: unknown length: option=%d, length=%d\n", tag, len);
				break;
			case 0x04: /* SACK permitted */
				if (len != 2)
					FRAMERR(frame, "tcp: unknown length: option=%d, length=%d\n", tag, len);
				break;
			case 0x05: /* SACK */
				break;
			case 0x08: /*timestamp*/
				break;
			case 0x03: /*window scale*/
				break;
            case 0x1e: /* multipath TCP */
                break;
			default:
				FRAMERR(frame, "tcp: unknown option=%d, length=%d\n", tag, len);
			}

			o += len-2;
		}
	}



	/* Process an "acknowledgement". Among other things, this will identify
	 * when packets have been missed: if the other side claims to have
	 * received a packet, but we never saw it, then we know that it was
	 * dropped somewhere on the network (probably because we are getting
	 * a weak signal via wireless). */
	if (tcp.flags & TCP_ACK) {
		tcp_ack_data(squirrel, frame, tcp.ackno);
	}

	switch (tcp.flags & 0x3F) {
	case TCP_SYN:
		tcp_syn(squirrel, frame);
		break;
	case TCP_SYN|TCP_ACK:
		tcp_synack(squirrel, frame);
		break;
	case TCP_FIN:
	case TCP_FIN|TCP_ACK:
	case TCP_FIN|TCP_ACK|TCP_PSH:
		tcp_fin(squirrel, frame);
		break;
	case TCP_ACK:
	case TCP_ACK|TCP_PSH:
		if (length > tcp.header_length)
			tcp_data(squirrel, frame, px+tcp.header_length, length-tcp.header_length, tcp.seqno, tcp.ackno);
		break;
	case TCP_RST:
	case TCP_RST|TCP_ACK:
		break;
	case 0x40|TCP_ACK:
		break;
	case TCP_RST|TCP_ACK|TCP_FIN:
	case TCP_RST|TCP_ACK|TCP_PSH:
		break;
	default:
		FRAMERR(frame, "tcp: unexpected combo of flags: 0x%03x\n", tcp.flags);
	}
}

