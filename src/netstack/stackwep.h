/* Copyright (c) 2008 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
#ifndef __STACKWEP_H
#define __STACKWEP_H
#ifdef __cplusplus
extern "C" {
#endif

struct WepKey {
	unsigned len;
	const char *key;
};


/**
 * Attempt to decrypt the WiFi packet using any of the 
 * keys in the list of keys.
 * Returns a positive integer (the index of the key, where
 * '1' is the first key) if successful.
 * Returns 0 if not successful.
 */
unsigned wep_decrypt(
	struct WepKey *wep_keys, unsigned wep_key_count,
	const unsigned char *px, unsigned length, 
	unsigned char *new_px, unsigned *r_new_length);

int 
wep_decrypt_packet(unsigned char *buf, unsigned len, 
			unsigned in_keylen, const unsigned char *in_wepkey);

#ifdef __cplusplus
}
#endif
#endif /*__STACKWEP_H*/
