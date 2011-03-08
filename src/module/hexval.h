/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
#ifndef __HEXVAL_H
#define __HEXVAL_H
#ifdef __cplusplus
extern "C" {
#endif

/**
 * Returns a number between 0 and 15, the hex value
 * of the given character
 */
unsigned hexval(int c);

#ifdef __cplusplus
}
#endif
#endif /*__HEXVAL_H*/
