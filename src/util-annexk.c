#include "util-annexk.h"
#include <ctype.h>

#ifdef __GNUC__
/** Case-insensitive memcmp() */
int 
memcasecmp(const void *lhs, const void *rhs, size_t length)
{
    size_t i;
    for (i=0; i<length; i++) {
        if (tolower(((char*)lhs)[i]) != tolower(((char*)rhs)[i]))
            return -1;
    }
    return 0;
}
#endif
