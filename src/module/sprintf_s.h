#ifndef SPRINTF_S_H
#define SPRINTF_S_H
#include <stdio.h>
#include <string.h>

/*
 * GCC
 */
#ifdef __GNUC__
#define sprintf_s snprintf
#define strcasecmp_s strcasecmp
int 
memcasecmp(const void *lhs, const void *rhs, size_t length);

/*
 * Microsoft C
 */
#elif defined(_MSC_VER) && _MSC_VER <= 1200
#define sprintf_s _snprintf
#define strcasecmp_s _stricmp
#define memcasecmp memicmp
#elif defined(_MSC_VER) && _MSC_VER >= 1600
#define strcasecmp_s _stricmp
#define memcasecmp _memicmp
#define strdup _strdup
#else
#error unknown compiler
#endif

/*
 * unknown
 */
#else
#error unknown compiler
#endif
