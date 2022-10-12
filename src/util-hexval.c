#include "util-hexval.h"


unsigned hexval(int c)
{
	if ('0'<=c && c<='9')
		return (unsigned)c-'0';
	else if ('a'<=c && c<='f')
		return (unsigned)c-'a'+10;
	else if ('A'<=c && c<='F')
		return (unsigned)c-'A'+10;
	else
		return 0xFFFFFFFF;
}
