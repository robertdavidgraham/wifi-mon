/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
#ifndef STACK_FRAME_H
#define STACK_FRAME_H
#ifdef __cplusplus
extern "C" {
#endif
struct Squirrel;

enum {
	ADDRESS_IP_v4=0,
	ADDRESS_IP_v6=6,
	ADDRESS_IPX=10,
	ADDRESS_ATALK_EDDP=20
};

struct StackFrame
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
	const char *netbios_source;
	const char *netbios_destination;
	unsigned src_ipv4;
	unsigned dst_ipv4;
	unsigned src_port;
	unsigned dst_port;
	unsigned char src_ipv6[16];
	unsigned char dst_ipv6[16];
    struct wifi {
        const unsigned char *bss_mac;
        unsigned             bss_direction;
        int dbm;
        int dbm_noise;
        unsigned channel;
    } wifi;
    unsigned ip_ttl;
    const unsigned char *px;
};

void FRAMERR(struct StackFrame *frame, const char *msg, ...);

#define FRAMERR_UNKNOWN_UNSIGNED(frame, name, value) FRAMERR(frame, "%s: unknown value: 0x%x (%d)\n", name, value, value);
#define FRAMERR_BADVAL(frame, name, value) FRAMERR(frame, "%s: unknown value: 0x%x (%d)\n", name, value, value);
#define FRAMERR_TRUNCATED(frame, name) FRAMERR(frame, "%s: truncated\n", name);
#define FRAMERR_UNPARSED(frame, name, value) FRAMERR(frame, "%s: unparsed value: 0x%x (%d)\n", name, value, value);


void
stack_parse_frame(struct Squirrel *squirrel,
                  struct StackFrame *frame,
                  const unsigned char *px, unsigned length);

#ifdef __cplusplus
}
#endif
#endif /*__NETFRAME_H*/
