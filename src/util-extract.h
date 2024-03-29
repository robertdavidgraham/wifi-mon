/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
#ifndef UTIL_EXTRACT_H
#define UTIL_EXTRACT_H



#define ex32be(px)  (unsigned)(	*((unsigned char*)(px)+0)<<24 \
					|	*((unsigned char*)(px)+1)<<16 \
					|	*((unsigned char*)(px)+2)<< 8 \
					|	*((unsigned char*)(px)+3)<< 0 )
#define ex32le(px)  (unsigned)(	*((unsigned char*)(px)+0)<< 0 \
					|	*((unsigned char*)(px)+1)<< 8 \
					|	*((unsigned char*)(px)+2)<<16 \
					|	*((unsigned char*)(px)+3)<<24 )
#define ex16be(px)  (unsigned short)(	*((unsigned char*)(px)+0)<< 8 \
					|	*((unsigned char*)(px)+1)<< 0 )
#define ex16le(px)  (unsigned short)(	*((unsigned char*)(px)+0)<< 0 \
					|	*((unsigned char*)(px)+1)<< 8 )

#define ex24be(px)  (unsigned)(	*((unsigned char*)(px)+0)<<16 \
					|	*((unsigned char*)(px)+1)<< 8 \
					|	*((unsigned char*)(px)+2)<< 0 )
#define ex24le(px)  (unsigned)(	*((unsigned char*)(px)+0)<< 0 \
					|	*((unsigned char*)(px)+1)<< 8 \
					|	*((unsigned char*)(px)+2)<<16 )

#define ex64be(px)  ( (((unsigned) __int64)ex32be(px))<<32L) + ((unsigned __int64)ex32be((px)+4)) )
#define ex64le(px)  ( \
    ex32le(px) | (uint64_t)ex32be((px)+4)<<32ULL \
    )

#endif /*__FORMATS_H*/
