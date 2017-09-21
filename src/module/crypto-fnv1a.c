/*
 * fnv1a.c :  routines to create checksums derived from FNV-1a
 *
 * ====================================================================
 *    Licensed to the Apache Software Foundation (ASF) under one
 *    or more contributor license agreements.  See the NOTICE file
 *    distributed with this work for additional information
 *    regarding copyright ownership.  The ASF licenses this file
 *    to you under the Apache License, Version 2.0 (the
 *    "License"); you may not use this file except in compliance
 *    with the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing,
 *    software distributed under the License is distributed on an
 *    "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *    KIND, either express or implied.  See the License for the
 *    specific language governing permissions and limitations
 *    under the License.
 * ====================================================================
 */

#define APR_WANT_BYTEFUNC

#include <assert.h>
#include <stdio.h>
#include <string.h>


#include "crypto-fnv1a.h"

/**
 * See http://www.isthe.com/chongo/tech/comp/fnv/ for more info on FNV-1
 */

/* FNV-1 32 bit constants taken from
 * http://www.isthe.com/chongo/tech/comp/fnv/
 */
#define FNV1_PRIME_32 0x01000193
#define FNV1_BASE_32 2166136261U

/* FNV-1a core implementation returning a 32 bit checksum over the first
 * LEN bytes in INPUT.  HASH is the checksum over preceding data (if any).
 */
unsigned
fnv1a_32(unsigned hash, const void *input, size_t len)
{
    const unsigned char *data = input;
    const unsigned char *end = data + len;
    
    for (; data != end; ++data)
    {
        hash ^= *data;
        hash *= FNV1_PRIME_32;
    }
    
    return hash;
}

