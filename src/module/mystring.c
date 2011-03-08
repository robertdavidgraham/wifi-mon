/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
/*
	VARIOUS STRING HANDLING FUNCTIONS

  String functions in C are in flux as the industry standardizes on
  newer, more secure, functions. Thus, the traditiona C runtime library
  can no longer be considered portable. Therefore, we are implementing
  our own functions here instead.
*/
#include "mystring.h"
#include <errno.h>
#include <string.h>
#include <ctype.h>

#if defined(_MSC_VER) && _MSC_VER <= 1200
#define STRCPY_S_DEFINE
#endif
#if __GNUC__
#define STRCPY_S_DEFINE
#endif

#ifdef STRCPY_S_DEFINE
int strcpy_s(
   char *dst,
   size_t dst_size,
   const char *src
)
{
	size_t src_size;

	if (dst==NULL || src==NULL)
		return EINVAL;
	
	src_size = strlen(src);

	if (src_size + 1 > dst_size)
		return ERANGE;

	memcpy(dst, src, src_size);
	dst[src_size] = '\0';

	return 0;
}
void strncpy_s(void *dst, unsigned dst_len, const void *src, unsigned src_len)
{
	unsigned n = dst_len-1;
	if (n > src_len)
		n = src_len;
	memcpy(dst, src, n);
	((unsigned char*)dst)[n] = '\0';
}
#endif


unsigned MATCHES(const char *sz, const unsigned char *px, unsigned length)
{
	unsigned i;

	for (i=0; i<length && sz[i]; i++)
		if (toupper(px[i]) != toupper(sz[i]))
			return 0;
	if (i != length || sz[i] != '\0')
		return 0;
	return 1;
}

unsigned starts_with(const char *prefix, const void *v_px, unsigned length)
{
	unsigned i;
	const unsigned char *px = (const unsigned char *)v_px;

	if (strlen(prefix) > length)
		return 0;

	for (i=0; i<length && prefix[i]; i++) {
		if (prefix[i] != toupper(px[i]))
			return 0;
	}
	if (prefix[i] == '\0')
		return 1;
	return 0;
}

int index_of(const char *prefix, const unsigned char *px, unsigned length)
{
	unsigned i;

	for (i=0; i<length && prefix[i]; i++) {
		if (px[i] == prefix[0]) {
			if (starts_with(prefix, px+i, length-i))
				return (int)i;
		}
	}
	return -1;
}



struct Atom 
atom_next(struct StringReassembler *str, unsigned *r_offset)
{
	unsigned offset=*r_offset;
	const unsigned char *px = str->the_string;
	unsigned length = str->length;
	struct Atom atom = {0};

	atom.px = str->the_string;

	/* skip leading whitespace */
	while (offset < length && isspace(px[offset]))
		offset++;

	if (offset >= length)
		return atom;

	/* Parse out string until next whitespace */
	atom.offset = offset;
	while (offset < length && !isspace(px[offset]))
		offset++;
	atom.len = offset-atom.offset;

	/* Remove trailing whitespace */
	while (offset < length && isspace(px[offset]))
		offset++;

	/* Return the results */
	*r_offset = offset;
	return atom;
}

unsigned atom_is_number(struct Atom atom)
{
	unsigned i;
	const unsigned char *px = atom.px+atom.offset;
	unsigned length = atom.len;

	if (length == 0)
		return 0;

	for (i=0; i<length; i++)
		if (!isdigit(px[i]))
			return 0;
	
	return 1;
}

unsigned atom_to_number(struct Atom atom)
{
	unsigned result = 0;
	unsigned i;
	const unsigned char *px = atom.px+atom.offset;
	unsigned length = atom.len;

	if (length == 0)
		return 0;

	for (i=0; i<length; i++) {
		if (!isdigit(px[i]))
			break;
		result =  result * 10 + (px[i]-'0');
	}
	
	return result;
}

unsigned atom_equals_ignorecase(struct Atom atom, const char *str)
{
	unsigned i;
	const unsigned char *px = atom.px+atom.offset;
	unsigned length = atom.len;

	if (length == 0)
		return 0;

	for (i=0; i<length; i++) {
		if (str[i] == '\0')
			return 0;
		if (toupper(str[i]) != toupper(px[i]))
			return 0;
	}

	if (str[i] != '\0')
		return 0;

	return 1;
}
