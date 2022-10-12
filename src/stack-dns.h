/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
#ifndef __DNS_H
#define __DNS_H
#ifdef __cplusplus
extern "C" {
#endif
struct Squirrel;
struct StackFrame;
struct DNSRECORD
{
	unsigned name_offset;
	unsigned type;
	unsigned clss;
	unsigned ttl;
	unsigned rdata_offset;
	unsigned rdata_length;
};
struct DNS {
	unsigned id;
	unsigned is_response;
	unsigned opcode;
	unsigned rcode;
	unsigned flags;
	unsigned question_count;
	unsigned answer_count;
	unsigned authority_count;
	unsigned additional_count;

	struct DNSRECORD records[256];
	unsigned record_count;

	struct DNSRECORD *questions;
	struct DNSRECORD *answers;
	struct DNSRECORD *authorities;
	struct DNSRECORD *additionals;
};

/**
 * Tests a DNS name to see if it looks like a SRV name [RFC 2782]. This would be
 * a service name (like _sip, _ftp, _tivo-videos) followed by a protocol
 * name (like _tcp or _udp).
 */
unsigned smellslike_srv_record(const unsigned char *px, unsigned length, unsigned offset);

enum {
	RR_QUESTION,
	RR_ANSWER,
	RR_ADDITIONAL,
	RR_AUTHORITATIVE,
};
void bonjour_parse_question_record(struct Squirrel *ferret, struct StackFrame *frame, const unsigned char *px, unsigned length,
						  struct DNSRECORD *rec, struct DNS *dns);
void bonjour_parse_resource_record(struct Squirrel *ferret, struct StackFrame *frame, const unsigned char *px, unsigned length,
						  struct DNSRECORD *rec, struct DNS *dns);
void bonjour_parse_record(struct Squirrel *ferret, struct StackFrame *frame, const unsigned char *px, unsigned length,
						  struct DNS *dns, struct DNSRECORD *rec, unsigned type);

void bonjour_txt_flush(struct Squirrel *ferret, struct StackFrame *frame, const unsigned char *px, unsigned length,
					struct DNSRECORD *rec);

unsigned 
dns_extract_name(struct StackFrame *frame, const unsigned char *px, unsigned length, unsigned offset, char *name, unsigned sizeof_name);


unsigned is_valid_opcode(int first, ...);

unsigned 
dns_resolve_alias(struct StackFrame *frame, const unsigned char *px, unsigned length, struct DNS *dns, const char *alias, int depth);

void dnssrv_parse_resource_record(struct Squirrel *ferret, struct StackFrame *frame, 
							const unsigned char *px, unsigned length,
							struct DNSRECORD *rec, struct DNS *dns);


void netbios_parse_resource_record(struct Squirrel *ferret, struct StackFrame *frame, 
							const unsigned char *px, unsigned length,
							struct DNSRECORD *rec, struct DNS *dns);

#ifdef __cplusplus
}
#endif
#endif /*__DNS_H*/
