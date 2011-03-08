/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
#ifndef __NETFRAME_H
#define __NETFRAME_H
#ifdef __cplusplus
extern "C" {
#endif

enum {
	ADDRESS_IP_v4=0,
	ADDRESS_IP_v6=6,
	ADDRESS_IPX=10,
	ADDRESS_ATALK_EDDP=20
};

struct NetFrame
{
	unsigned ipver;
	unsigned layer2_protocol;
	unsigned original_length;
	unsigned captured_length;
	unsigned time_secs;
	unsigned time_usecs;
	unsigned frame_number;
	union {
		struct {
			unsigned bad_fcs:1;
			unsigned filtered:1;
			unsigned repeated:1;
			unsigned ivs:1;
		} found;
		unsigned clear;
	} flags;
	const char *filename;
	const unsigned char *src_mac;
	const unsigned char *dst_mac;
	const unsigned char *bss_mac;
	unsigned			 bss_direction;
	const char *netbios_source;
	const char *netbios_destination;
	unsigned src_ipv4;
	unsigned dst_ipv4;
	unsigned src_port;
	unsigned dst_port;
	unsigned char src_ipv6[16];
	unsigned char dst_ipv6[16];
	int dbm;
    unsigned ip_ttl;
    const unsigned char *px;
};

void FRAMERR(struct NetFrame *frame, const char *msg, ...);

#define FRAMERR_UNKNOWN_UNSIGNED(frame, name, value) FRAMERR(frame, "%s: unknown value: 0x%x (%d)\n", name, value, value);
#define FRAMERR_BADVAL(frame, name, value) FRAMERR(frame, "%s: unknown value: 0x%x (%d)\n", name, value, value);
#define FRAMERR_TRUNCATED(frame, name) FRAMERR(frame, "%s: truncated\n", name);
#define FRAMERR_UNPARSED(frame, name, value) FRAMERR(frame, "%s: unparsed value: 0x%x (%d)\n", name, value, value);


#ifdef __cplusplus
}
#endif
#endif /*__NETFRAME_H*/
