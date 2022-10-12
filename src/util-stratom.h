#ifndef __VC6_H
#define __VC6_H
#include <stdio.h>
#include <errno.h>



unsigned MATCHES(const char *sz, const unsigned char *px, unsigned length);

unsigned starts_with(const char *prefix, const void *px, unsigned length);
int index_of(const char *substr, const unsigned char *value, unsigned value_length);

#if _MSC_VER<=1200
void strncpy_s(void *dst, unsigned dst_len, const void *src, unsigned src_len);
#endif

struct Atom {
	const unsigned char *px;
	unsigned offset;
	unsigned len;
};

/** 
 * Ferret parses TCP streams a single byte at a time. In most cases,
 * the buffers it is looking for are located in the current packet.
 * In some cases, however, they will span a packet boundary and need
 * to be reassembled. In such cases, we will do 'late' reassembly.
 * This means that in the normal case, we will simply point to the
 * strings in the buffer. Only when parsing 'runs off the end' of a 
 * packet will we actually allocate a buffer and copy the string off
 * into that buffer. We only have ONE string like this at a time while
 * parsing TCP. Once we finish parsing the string, we must either
 * parse-and-forget it, or allocate-and-remember it. There are other
 * data structures that can handle the remembering of strings and
 * automatic disposal.
 */
struct StringReassembler {
	/** Points either into the packet, or the allocated backing store */
	const unsigned char *the_string;

	/** The length of the string */
	unsigned length;

	/** When we have to allocate memory for a string, that memory will
	 * be held here */
	unsigned char *backing_store;
};

struct Atom atom_next(struct StringReassembler *str, unsigned *r_offset);
unsigned atom_is_number(struct Atom atom);
unsigned atom_to_number(struct Atom atom);
unsigned atom_equals_ignorecase(struct Atom atom, const char *str);

#endif /*__VC6_H */
