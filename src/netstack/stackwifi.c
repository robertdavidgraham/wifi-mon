/* Copyright (c) 2007 by Errata Security, All Rights Reserved
 * Programer(s): Robert David Graham [rdg]
 */
#include "../squirrel.h"
#include "formats.h"
#include "netframe.h"
#include "../sqdb/sqdb.h"
#include "stackwep.h"
#include "../module/crypto-fnv1a.h"

//#include "val2string.h"	/* for translating OUIs */

#include <string.h>
#include <stdio.h>
#include <stdarg.h>

typedef unsigned char MACADDR[6];

/**
 * This structure represents data parsed from various wifi management
 * packets, including data from the variable fields.
 */
struct	WIFI_MGMT {
	int frame_control;
	int duration;
	MACADDR destination;
	MACADDR source;
	MACADDR bss_id;
	int frag_number;
	int seq_number;

	unsigned char *ssid;
	size_t ssid_length;

	unsigned channel;
};


struct InformationElement {
	const unsigned char *px;
	unsigned length;
};


/**
 * Copy a rates field from a packet (unordered list, up to 255, possible
 * duplicates, unknown rates) to a field (ordered, max 16 entires, no
 * duplicates, filter out unknown rates)
 */
static struct SQDB_RateList
ie_to_rate_list(struct InformationElement ie)
{
	int max_found_rate = 256; /* 256 > any possible rate in the packet, which is a 1-byte value */
	struct SQDB_RateList rate_list[1];
	memset(rate_list, 0, sizeof(rate_list[1]));

	for (;;) {
		int found_rate = -1;
		unsigned i;

		/* Find highest rate not already in our list */
		for (i=0; i<ie.length; i++) {
			int r = (int)ie.px[i];

			if (found_rate < r && r < max_found_rate)
				found_rate = r;
		}

		/* If no rates are left, then we are done copying */
		if (found_rate == -1)
			break;

		/* Copy over the rate. Make sure that
		 * there is a enough space to hold it and that a fuzzer isn't
		 * trying to overflow the buffer */
		if (rate_list->count < sizeof(rate_list->rates)/sizeof(rate_list->rates[0])) {
			rate_list->rates[rate_list->count++] = found_rate;
		}

		/* Now mark this as the max rate we'll accept for the next
		 * rate we pull from the packet */
		max_found_rate = found_rate;
	}

	return rate_list[0];
}

/**
 * Convert a big-endian number stored in an information element into
 * an integer. Note that an integer is larger than the number of bytes
 * we can hold, then we will just be getting the last 4-bytes of whatever
 * value the field contains. If the upper bytes are all zero, this will
 * get the correct value, otherwise, it will be slightly incorrect.
 */
static unsigned
ie_to_unsigned(struct InformationElement ie)
{
	unsigned result = 0;
	unsigned i;

	for (i=0; i<ie.length && i<256; i++) {
		result <<= 8;
		result |= ie.px[i];
	}

	return result;
}

/**
 * Convert a string fround in an information element (probably the SSID)
 * into an internal string. If the packet string is longer than the internal
 * string, then we shorten it by removing bytes in the middle rather than
 * simply truncating it.
 */
static struct SQDB_String
ie_to_string(struct InformationElement ie)
{
	struct SQDB_String ssid;
	unsigned length_to_copy;

	memset(&ssid, 0, sizeof(ssid));

	/* Find the length */
	length_to_copy = ie.length;
	if (length_to_copy > sizeof(ssid.value))
		length_to_copy = sizeof(ssid.value);

	/* Copy it over */
	memcpy(ssid.value, ie.px, length_to_copy);
	ssid.length = length_to_copy;

	/* Remove leading NUL bytes */
	while (ssid.length && ssid.value[0] == '\0') {
		memmove(ssid.value, ssid.value+1, ssid.length-1);
		ssid.length--;
	}

	/* Remove trailing NUL bytes */
	while (ssid.length && ssid.value[ssid.length-1] == '\0') {
		ssid.length--;
	}

	/* If the SSID is too long, then create a string where
	 * we've removed bytes from the middle instead of simply truncating.
	 * Also, mark the middle with the string "..".
	 * Thus, if given a 16-byte string "0123456789ABCDEF" trying to fit
	 * in an 8-byte buffer, the resulting string would be "012..DEF".
	 */
	if (ie.length > sizeof(ssid.value)) {
		unsigned half_way = sizeof(ssid.value)/2;

		memcpy(	ssid.value + half_way,
				ie.px + ie.length - half_way,
				half_way);
		ssid.value[half_way-1] = '.';
		ssid.value[half_way] = '.';
	}

	/* Fill the rest with 'X', since this is length encoded, 
	 * we should never see 'X' appear in output */
	memset(ssid.value+ssid.length, 'X', sizeof(ssid.value)-ssid.length);

	return ssid;
}

/**
 */
static struct SQDB_String
ie_decode_cisco_name(struct InformationElement ie)
{
	struct SQDB_String ssid;
	unsigned length_to_copy;

	memset(&ssid, 0, sizeof(ssid));

    if (ie.length < 26)
        return ssid;

	/* Find the length */
	length_to_copy = 16;
	if (length_to_copy > sizeof(ssid.value))
		length_to_copy = sizeof(ssid.value);

	/* Copy it over */
	memcpy(ssid.value, ie.px+10, length_to_copy);
	ssid.length = length_to_copy;

	/* Remove leading NUL bytes */
	while (ssid.length && ssid.value[0] == '\0') {
		memmove(ssid.value, ssid.value+1, ssid.length-1);
		ssid.length--;
	}

	/* Remove trailing NUL bytes */
	while (ssid.length && ssid.value[ssid.length-1] == '\0') {
		ssid.length--;
	}

	/* If the SSID is too long, then create a string where
	 * we've removed bytes from the middle instead of simply truncating.
	 * Also, mark the middle with the string "..".
	 * Thus, if given a 16-byte string "0123456789ABCDEF" trying to fit
	 * in an 8-byte buffer, the resulting string would be "012..DEF".
	 */
	if (ie.length > sizeof(ssid.value)) {
		unsigned half_way = sizeof(ssid.value)/2;

		memcpy(	ssid.value + half_way,
				ie.px + ie.length - half_way,
				half_way);
		ssid.value[half_way-1] = '.';
		ssid.value[half_way] = '.';
	}

	/* Fill the rest with 'X', since this is length encoded, 
	 * we should never see 'X' appear in output */
	memset(ssid.value+ssid.length, 'X', sizeof(ssid.value)-ssid.length);

	return ssid;
}


/**
 * Get an informaiton element from the stream
 */
struct InformationElement
get_information_element(const unsigned char *px, unsigned offset, unsigned length, unsigned in_tag, ...)
{
	/* An Informatin Element is "tag-length-value" encoded. The first byte is the tag,
	 * the second byte is the length, the remaining bytes are the value
	 * +--------+--------+--------...
	 * |   tag  | length |  value
	 * +--------+--------+--------...
	 * 
	 * There are also vendor-specific Information Elements where the tag is 221
	 * +--------+--------+--------+--------+--------+--------...
	 * |   221  | length |           oui            |  value
	 * +--------+--------+--------+--------+--------+--------...
	 *
	 * There are also the Microsoft-specific information elements with an OUI of 0x0050F2
	 * +--------+--------+--------+--------+--------+--------+--------...
	 * |   221  | length |  0x00  |  0x50  |  0xF2  | subtag |  value
	 * +--------+--------+--------+--------+--------+--------+--------...
	 */
	unsigned in_vendor = 0;
	unsigned in_subtag = 0;
	struct InformationElement result;
	va_list marker;

	/* Extract Vendor-specific parameters */
	va_start(marker, in_tag);
	if (in_tag == 221) {
		in_vendor = va_arg(marker, unsigned);
		if (in_vendor == 0x0050f2)
			in_subtag = va_arg(marker, unsigned);
	}
	va_end(marker);



	/*  Default "not found" result */
	result.px = 0;
	result.length = 0;

	/* For all remaining Information-Elements ... */
	while (offset + 2 < length) {
		unsigned tlv_tag = px[offset++];
		unsigned tlv_length = px[offset++];
		unsigned tlv_offset = offset;

		if (tlv_length > length-offset)
			tlv_length = length-offset; /* Error: TLV length went past end of packet */
		
		offset += tlv_length;
		
		/* See if this tag matches */
		if (tlv_tag != in_tag)
			continue;

		/* See if the vendor OUI matches for vendor tags */
		if (in_tag == 221) {
			unsigned oui;

			if (tlv_length < 3)
				continue; /* Error: Vendor tags must be at lest 3 bytes long for the OUI field */

			oui = (px[tlv_offset+0] << 16) 
				| (px[tlv_offset+1] << 8)
				| (px[tlv_offset+2] << 0);

			if (oui != in_vendor)
				continue;

			/* Remove the OUI field from the tag */
			tlv_offset += 3;
			tlv_length -= 3;

			/* See if we have a Microsoft/WPA element */
			if (oui == 0x0050F2) {
				unsigned subtag;

				if (tlv_length < 1)
					continue; /* Error: not enough space for subtag */

				subtag = px[tlv_offset];
				
				if (subtag != in_subtag)
					continue;

				/* Skip the subtag */
				tlv_offset++;
				tlv_length--;
			}
		}

		/* We have a valid Information Element, so return it */
		result.px = px + tlv_offset;
		result.length = tlv_length;
		break;
	}

	return result;
}

unsigned smellslike_80211n(const unsigned char *px, unsigned offset, unsigned length)
{
	struct InformationElement ie;

	ie = get_information_element(px, offset, length, 0);
	return 0;
}



#define REMAINING(offset,length) ((offset<length)?(length-offset):(0))

/**
 * Figure out the crypto flags from a Microsoft WME-WPA element
 * The parameter 'ie' points into the field within the 
 * captured packet. This function is called while parsing
 * the incoming packet.
 */
static unsigned
ie_wpa1wme_to_crypto_flags(struct SQDB *sqdb, struct NetFrame *frame, const unsigned char *bssid, struct InformationElement ie)
{
	const unsigned char *px = ie.px;
	unsigned length = ie.length;
	unsigned offset = 0;
	unsigned version;
	unsigned cipher_suite;
	unsigned result = 0;
	unsigned number_of_cipher_suites;

	/* Grab the version field */
	if (REMAINING(offset,length) < 2) {
		/* Probably because the field was not found */
		return 0;
	}
	version = px[offset];
	offset += 2;
	if (version != 1) {
		FRAMERR(frame, "%s: Information Element unknown version\n", "WPA-WME");
		return 0;
	}

	/* MULTICAST cipher suite (which we ignore right now) */
	if (REMAINING(offset,length) < 4) {
		FRAMERR(frame, "%s: Information Element truncated\n", "WPA-WME");
		return 0;
	}
	cipher_suite = ex32be(px+offset);
	offset += 4;

	/* UNICAST cipher suite(s)*/
	if (REMAINING(offset,length) < 2) {
		FRAMERR(frame, "%s: Information Element truncated\n", "WPA-WME");
		return 0;
	}
	number_of_cipher_suites = ex16le(px+offset);
	offset += 2;

	regmac_base_crypto(sqdb, bssid, ENC_TYPE_WPA);

	while (number_of_cipher_suites) {
		/* REF: wifi-2009-02-09.pcap(30) for more than one cipher suite */
		if (REMAINING(offset,length) < 4) {
			FRAMERR(frame, "%s: Information Element truncated\n", "WPA-WME");
			break;
		}
		cipher_suite = ex32be(px+offset);
		switch (cipher_suite) {
		case 0x50f202: /* TKIP */
			regmac_base_crypto(sqdb, bssid, CIPHER_TYPE_TKIP);
			break;
		case 0x50f204: /* AES */
			regmac_base_crypto(sqdb, bssid, CIPHER_TYPE_AES);
			break;
		default:
			FRAMERR(frame, "%s: Information Element unknown cipher\n", "WPA-WME");
		}
		offset += 4;
		number_of_cipher_suites--;
	}
	
	/* AUTHENTICATION ciphers */
	if (REMAINING(offset,length) < 2) {
		FRAMERR(frame, "%s: Information Element truncated\n", "WPA-WME");
		return 0;
	}
	number_of_cipher_suites = ex16le(px+offset);
	offset += 2;


	while (number_of_cipher_suites) {
		if (REMAINING(offset,length) < 4) {
			FRAMERR(frame, "%s: Information Element truncated\n", "WPA-WME");
			break;
		}
		cipher_suite = ex32be(px+offset);
		switch (cipher_suite) {
		case 0x50f201: /* WPA */
			/* REF: wifi-2009-02-09.pcap(46) */		
			regmac_base_crypto(sqdb, bssid, AUTH_TYPE_MGMT);
			break;
		case 0x50f202: /* PSK */
			regmac_base_crypto(sqdb, bssid, AUTH_TYPE_PSK);
			break;
		case 0x409600:
			/* REF: wifi-2009-02-09.pcap(406348) */		
			break;
        case 0xa0f800:
            /* REF: wpa-a0f800.pcap(1) */
            break;
		default:
			FRAMERR(frame, "%s: Information Element unknown cipher\n", "WPA-WME");
		}
		offset += 4;
		number_of_cipher_suites--;
	}
	

	return result;
}

/**
 * Figure out the crypto flags from the WPA2/802.11i RSN 
 * Information Element. 
 * The parameter 'ie' points into the field within the 
 * captured packet. This function is called while parsing
 * the incoming packet.
 */
static unsigned
ie_wpa2rsn_to_crypto_flags(struct SQDB *sqdb, struct NetFrame *frame, const unsigned char *bssid, struct InformationElement ie)
{
	const unsigned char *px = ie.px;
	unsigned length = ie.length;
	unsigned offset = 0;
	unsigned version;
	unsigned cipher_suite;
	unsigned result = 0;
	unsigned number_of_cipher_suites;

	/* Grab the version field */
	if (REMAINING(offset,length) < 2) {
		/* Probably because the field was not found */
		return 0;
	}
	version = (px[offset]) | (px[offset+1]<<8);
	offset += 2;
	if (version != 1) {
		/* REF: wifi-2009-02-09.pcap(406654) */		
		//FRAMERR(frame, "%s: Information Element unknown version\n", "WPA-RSN");
		return 0;
	}

	/* MULTICAST cipher suite (which we ignore right now) */
	if (REMAINING(offset,length) < 4) {
		FRAMERR(frame, "%s: Information Element truncated\n", "WPA-RSN");
		return 0;
	}
	cipher_suite = ex32be(px+offset);
	offset += 4;

	/* UNICAST cipher suite(s)*/
	if (REMAINING(offset,length) < 2) {
		FRAMERR(frame, "%s: Information Element truncated\n", "WPA-RSN");
		return 0;
	}
	number_of_cipher_suites = ex16le(px+offset);
	offset += 2;

	regmac_base_crypto(sqdb, bssid, ENC_TYPE_WPA2);

	while (number_of_cipher_suites) {
		/* REF: wifi-2009-02-09.pcap(30) for more than one cipher suite */
		if (REMAINING(offset,length) < 4) {
			FRAMERR(frame, "%s: Information Element truncated\n", "WPA-RSN");
			break;
		}
		cipher_suite = ex32be(px+offset);
		switch (cipher_suite) {
		case 0x0fac02: /* TKIP  */
			regmac_base_crypto(sqdb, bssid, CIPHER_TYPE_TKIP);
			break;
		case 0x0fac04: /* AES (CCM) */
			regmac_base_crypto(sqdb, bssid, CIPHER_TYPE_AES);
			break;
		default:
			FRAMERR(frame, "%s: Information Element unknown cipher\n", "WPA-RSN");
		}
		offset += 4;
		number_of_cipher_suites--;
	}
	
	/* AUTHENTICATION ciphers */
	if (REMAINING(offset,length) < 2) {
		FRAMERR(frame, "%s: Information Element truncated\n", "WPA-RSN");
		return 0;
	}
	number_of_cipher_suites = ex16le(px+offset);
	offset += 2;

	while (number_of_cipher_suites) {
		if (REMAINING(offset,length) < 4) {
			FRAMERR(frame, "%s: Information Element truncated\n", "WPA-RSN");
			break;
		}
		cipher_suite = ex32be(px+offset);
		switch (cipher_suite) {
		case 0x0fac02: /* PSK */
			regmac_base_crypto(sqdb, bssid, AUTH_TYPE_PSK);
			break;
		case 0x0fac01: /* WPA */
			regmac_base_crypto(sqdb, bssid, AUTH_TYPE_MGMT);
			break;
		case 0x409600: /* aironet */
			/* REF: wifi-2009-02-09.pcap(406605)*/
			break;
		default:
			FRAMERR(frame, "%s: Information Element unknown cipher\n", "WPA-RSN");
		}
		offset += 4;
		number_of_cipher_suites--;
	}
	

	return result;
}

/**
 * Different wifi packets put the source/destination MAC address in
 * different places. This function normalizes the WiFi packet, and
 * attaches the addresses to the "NetFrame" struction as if the packet
 * were a normal Ethernet. 
 * 
 * This is sorta a strange design decision. One decision would be to
 * locate this code near where each type of packet is parsed. Another
 * (chosen here) is to co-locate the code according to what data it
 * is extracting.
 */
void squirrel_get_mac_address(struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned direction;

	/* Make sure we have enoug hspace */
	if (length < 2)
		return;

	/*
	 * [DIRECTION]
	 * This field indicates which direction the packet is going.
	 * 00 - [>dst<][<src>][bssid]
	 * 01 - [bssid][<src>][>dst<]
	 *      From WIRED to WIFI via ACCESS-POINT.
	 * 10 - [>dst<][bssid][<src>]
	 * 11 - [RECVR][XMITR][<dst>][<src>]
	 */
	direction = px[1]&0x03;
	switch (direction) {
	case 0:
		frame->dst_mac  = px+4;
		frame->src_mac  = px+10;
		frame->bss_mac	= px+16;
		break;
	case 1:
		frame->bss_mac	= px+4;
		frame->src_mac  = px+10;
		frame->dst_mac  = px+16;
		break;
	case 2:
		frame->dst_mac  = px+4;
		frame->bss_mac	= px+10;
		frame->src_mac  = px+16;
		break;
	case 3:
		frame->bss_mac = (const unsigned char*)"\0\0\0\0\0\0";
		frame->dst_mac   = px+16;
		frame->src_mac   = px+24;
		break;
	}

}

/**
 * We want to fingerprint the probe packets from a source for a couple reasons.
 * One reason is that the same source may produce probes with slightly varying
 * information elements. We want to save a copy of each type of probes in the 
 * packets we associate with a source. Secondly, the information elemetns can
 * be a useful way to fingerprint a device, as all devices of a certain type
 * may have the same information element fingerprint.
 */
static unsigned
hash_information_elements(const unsigned char *px, unsigned offset, unsigned length)
{
    /* Kludge alert!
     * So sometimes we've got the CRC in the IE field which can throw things off.
     * Removing the last 4 bytes from the field should still give us the same
     * hashes, so we are going to do that. */
    if (length - offset > 4)
        length -= 4;
    
    return fnv1a_32(0, px + offset, length - offset);
}


/**
 * This packet is sent out by wireless-stations looking for access-points.
 * It can either be probing for a specific SSID, or it could probe for
 * no particular SSID, in order to get silent SSIDs to respond.
 *
 * We want to remember the SSID's that a station is probing for, because
 * this can tell us about the identity of that station.
 * 
 * The "probe response" to this request will contain the 
 * same information as in Beacon packets, except they will be
 * unicasted back to the requester rather than broadcast.
 */
void squirrel_wifi_proberequest(struct Squirrel *squirrel, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned offset;
	unsigned direction;

	/* VALIDATE: enough data in packet */
	if (length < 24) {
		FRAMERR(frame, "wifi: truncated\n");
		return;
	}

	/* VALIDATE: proper direction field */
	direction = px[1]&3;
	if (direction != 0) {
		FRAMERR(frame, "unknown direction %d\n", direction);
		return;
	}

	
	/* VALIDATE: Make sure destination and BSSID are broadcasts.
	 * OOPS: Maybe not. It appears that some machines will send a prob
	 * packet directly to an access-point rather than to the broadcast
	 * address, presumably because it wants to check to see if the 
	 * access-point is still alive.
	 * REF: wifi-2009-02-09.pcap(2478) */
	/*if (memcmp(frame->dst_mac, "\xff\xff\xff\xff\xff\xff", 6) != 0)
		FRAMERR(frame, "wifi.probe: destination %02x:%02x:%02x:%02x:%02x:%02x\n", 
			frame->dst_mac[0], frame->dst_mac[1], frame->dst_mac[2], 
			frame->dst_mac[3], frame->dst_mac[4], frame->dst_mac[5]
			);
	if (memcmp(frame->bss_mac, "\xff\xff\xff\xff\xff\xff", 6) != 0)
		FRAMERR(frame, "wifi.probe: destination %02x:%02x:%02x:%02x:%02x:%02x\n", 
			frame->bss_mac[0], frame->bss_mac[1], frame->bss_mac[2], 
			frame->bss_mac[3], frame->bss_mac[4], frame->bss_mac[5]
			);
	*/

	/* Skip fixed header. After this point, the remainder will
	 * be TLV fields */
	offset = 24; 


	/*
	 * Set some parameters we see about this station
	 */
	{
		struct SQDB_RateList rates1;
		struct SQDB_RateList rates2;
		struct SQDB_String ssid;
        struct SquirrelPacket pkt[1];

        pkt->length = length;
        pkt->secs = frame->time_secs;
        pkt->usecs = frame->time_usecs;
        pkt->px = px;
        pkt->linktype = frame->layer2_protocol;
        pkt->type = hash_information_elements(px, offset, length);

		ssid = ie_to_string(get_information_element(px, offset, length, 0x00));
		rates1 = ie_to_rate_list(get_information_element(px, offset, length, 0x01));
		rates2 = ie_to_rate_list(get_information_element(px, offset, length, 0x32));

		sqdb_add_probe_request(squirrel->sqdb,
                               frame->src_mac, ssid,
                               rates1, rates2,
                               pkt);
		regmac_transmit_power(squirrel->sqdb, frame->src_mac, frame->dbm, frame->time_secs);
	}
}


void squirrel_wifi_associate_request(struct Squirrel *squirrel, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned direction;
	unsigned flags;
	unsigned listen_interval;
	unsigned offset;
	struct InformationElement ie;

	/* VALIDATE: enough data in packet */
	if (length < 28) {
		FRAMERR(frame, "wifi: truncated\n");
		return;
	}

	/* VALIDATE: proper direction field */
	direction = px[1]&3;
	if (direction != 0) {
		FRAMERR(frame, "unknown direction %d\n", direction);
		return;
	}

	/* Extract addresses */
	frame->dst_mac = px+4;
	frame->src_mac = px+10;
	frame->bss_mac = px+16;
	regmac_transmit_power(squirrel->sqdb, frame->src_mac, frame->dbm, frame->time_secs);

	/* Parse data fields */
	flags = ex16le(px+24);
	listen_interval = ex16le(px+26);

	/* This is called for both Association and re-Assocation, but they have
	 * slightly different formats */
	if (px[0] == 0x20)
		offset = 34; /* Reassociation */
	else
		offset = 28; /* Association */


	/* In all the samples I've seen, this flag was set.*/
	if ((flags & 1) == 0) {
		/* Oops, receiver isn't an access-point */
		FRAMERR(frame, "associate response: not ap\n");
		return;
	}


	/*
	 * Register the fact that we've seen this base station and its probable
	 * SSID.
	 */
	regmac_base(squirrel->sqdb, frame->bss_mac, frame->dst_mac);

	/*
	 * Register the fact that we've seen this client, that the client was
	 * attempting to access this base station, and that the client wanted
	 * to contact this SSID
	 */
	regmac_station_ctrl(squirrel->sqdb, frame->bss_mac, frame->src_mac, DIR_STA_TO_BASE);

	/*
	 * Extract the SSID from the information element
	 */
	ie = get_information_element(px, offset, length, 0x00);
	if (ie.px) {
		struct SQDB_String ssid;
		ssid = ie_to_string(ie);
		regmac_base_ssid(squirrel->sqdb, frame->bss_mac, &ssid);
	}

    /*
     * Record this event
     */
    regmac_event(squirrel->sqdb, 
        EVENT_ASSOC,
        frame->bss_mac, frame->src_mac,
        EVENT_ASSOC_REQ, frame);


}

void squirrel_wifi_associate_response(struct Squirrel *squirrel, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned direction;
	unsigned flags;
	unsigned status;
	unsigned id;
	unsigned offset;
	struct InformationElement ie;

	/* VALIDATE: enough data in packet */
	if (length < 30) {
		FRAMERR(frame, "wifi: truncated\n");
		return;
	}

	/* VALIDATE: proper direction field */
	direction = px[1]&3;
	if (direction != 0) {
		FRAMERR(frame, "unknown direction %d\n", direction);
		return;
	}

	frame->dst_mac = px+4;
	frame->src_mac = px+10;
	frame->bss_mac = px+16;

	flags = ex16le(px+24);
	status = ex16le(px+26);
	id = ex16le(px+28);
	offset = 30;

	if ((flags & 1) == 0) {
		/* Oops, sender isn't an access-point */
		FRAMERR(frame, "associate response: not ap\n");
		return;
	}

	switch (status) {
	case 0: /*OK*/
		/* REF: sniff-2009-02-09-127.pcap(4)*/
		break;
	default:
		FRAMERR(frame, "wifi.data: unknown status: 0x%04x\n", status);
		return;
	}


	regmac_transmit_power(squirrel->sqdb, frame->src_mac, frame->dbm, frame->time_secs);
	regmac_base(squirrel->sqdb, frame->bss_mac, frame->src_mac);
	regmac_station_ctrl(squirrel->sqdb, frame->bss_mac, frame->dst_mac, DIR_BASE_TO_STA);

	/* SSID: probably doesn't exist */
	ie = get_information_element(px, offset, length, 0x00);
	if (ie.px) {
		struct SQDB_String ssid;
		ssid = ie_to_string(ie);
		regmac_base_ssid(squirrel->sqdb, frame->bss_mac, &ssid);
	}

	/* SUPPORTED RATES: probably exists */
	ie = get_information_element(px, offset, length, 0x01);
	if (ie.px) {
		struct SQDB_RateList rates;
		rates = ie_to_rate_list(ie);
		regmac_base_rates(squirrel->sqdb, frame->bss_mac, &rates, 0);
	}
	ie = get_information_element(px, offset, length, 0x32); 
	if (ie.px) {
		struct SQDB_RateList rates;
		rates = ie_to_rate_list(ie);
		regmac_base_rates(squirrel->sqdb, frame->bss_mac, 0, &rates);
	}

    /*
     * Record this event
     */
    regmac_event(squirrel->sqdb, 
        EVENT_ASSOC,
        frame->bss_mac, frame->dst_mac,
        EVENT_ASSOC_RSP, frame);

}

void squirrel_wifi_authentication(struct Squirrel *squirrel, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned auth_type=0;
	unsigned direction;
	unsigned dir;
	unsigned status;

	/* VALIDATE: enough data in packet */
	if (length < 30) {
		FRAMERR(frame, "wifi: truncated\n");
		return;
	}

	/* VALIDATE: proper direction field */
	direction = px[1]&3;
	if (direction != 0) {
		FRAMERR(frame, "unknown direction %d\n", direction);
		return;
	}

	frame->dst_mac = px+4;
	frame->src_mac = px+10;
	frame->bss_mac = px+16;
	regmac_transmit_power(squirrel->sqdb, frame->src_mac, frame->dbm, frame->time_secs);


	/*
	 * Only look at packets coming from the base/access-point, because that
	 * tells us what authentication they require
	 */
	dir = regmac_base_resolve_direction(squirrel->sqdb, frame->bss_mac, frame->src_mac, frame->dst_mac);

	/*
	 * If the status isn't "OK", the drop this
	 */
	status = ex16le(px+28);
	switch (status) {
	case 0: /*OK*/
		break;
	case 0x000d: /* auth type not supported */
		return;
	default:
		FRAMERR(frame, "auth: unknown status 0x%04x\n", status);
		return;
	}



	switch (ex16le(px+24)) {
	case 0x0000: /* Open */
		/* This is how virtually every system works, even if WEP or WPA
		 * is used later on */
		auth_type = AUTH_TYPE_OPEN;	
		break;
	case 0x0001: /* Shared Key */
		/* REF: wifi-2009-02-09.pcap(240458) for more than one cipher suite */
		auth_type = AUTH_TYPE_SKA;
		break;
	case 0x0080: /* Network EAP (Extensible Authentication Protocol) */
		/* walking-08.cap(124) */
		auth_type = AUTH_TYPE_EAP;
		break;
	default:
		FRAMERR(frame, "wifi.data: unknown authentication: 0x%04x\n", ex16le(px+24));
		return;
	}

	regmac_base_crypto(squirrel->sqdb, frame->bss_mac, auth_type);

    /*
     * Record this event
     */
    if (dir == DIR_STA_TO_BASE) {
        regmac_event(squirrel->sqdb, 
            EVENT_ASSOC,
            frame->bss_mac, frame->src_mac,
            EVENT_AUTH_REQ, frame);
    } else if (dir == DIR_BASE_TO_STA) {
        regmac_event(squirrel->sqdb, 
            EVENT_ASSOC,
            frame->bss_mac, frame->dst_mac,
            EVENT_AUTH_RSP, frame);
    } else
        FRAMERR(frame, "unknown\n");
}

/**
 * This is some newer packet, I think with 802.11n.
 * I think at least one thing it does is do a block acknowledgement
 * of multiple packets
 */
void squirrel_wifi_mgmt_action(struct Squirrel *squirrel, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned action_type;
	unsigned direction;

	/* VALIDATE: enough data in packet */
	if (length < 26) {
		FRAMERR(frame, "wifi: truncated\n");
		return;
	}

	/* VALIDATE: proper direction field */
	direction = px[1]&3;
	if (direction != 0) {
		FRAMERR(frame, "unknown direction %d\n", direction);
		return;
	}

	/* Extract the addresses */
	frame->dst_mac = px+4;
	frame->src_mac = px+10;
	frame->bss_mac = px+16;
	regmac_transmit_power(squirrel->sqdb, frame->src_mac, frame->dbm, frame->time_secs);

	action_type = px[24];
	switch (action_type) {
	case 0x03: /* Category code = Block ACK */
		/* Ref: wifi-2009-02-09.pcap(14379) */
		break;
	default:
		FRAMERR(frame, "wifi.data: unknown action category code: 0x%04x\n", action_type);
	}

	if (memcmp(frame->src_mac, frame->bss_mac, 6) != 0) {
		/* Ref: wifi-2009-02-09.pcap(14385) */
		regmac_station_ctrl(squirrel->sqdb, frame->bss_mac, frame->src_mac, DIR_STA_TO_BASE);
	} else if (memcmp(frame->dst_mac, frame->bss_mac, 6) != 0) {
		/* Ref: wifi-2009-02-09.pcap(14379) */
		regmac_station_ctrl(squirrel->sqdb, frame->bss_mac, frame->dst_mac, DIR_BASE_TO_STA);
	} else {
		FRAMERR(frame, "%s: unexpected contents\n", "mgmt.action");
	}

}

void squirrel_wifi_deauthentication(struct Squirrel *squirrel, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned reason;
	unsigned direction;
	unsigned dir;

	/* Additional data */
	if (length < 26) {
		FRAMERR(frame, "wifi: truncated\n");
		return;
	}

	/* Packet direction check */
	direction = px[1]&3;
	switch (direction) {
	case 0:
		break;
	case 1:
	case 2:
	case 3:
		FRAMERR(frame, "deauth: unknown direction %d\n", direction);
		break;
	}

	/* Extract addresses */
	frame->dst_mac = px+4;
	frame->src_mac = px+10;
	frame->bss_mac = px+16;

	/*
	 * Only look at packets coming from the base/access-point, because that
	 * tells us what authentication they require
	 */
	dir = regmac_base_resolve_direction(squirrel->sqdb, frame->bss_mac, frame->src_mac, frame->dst_mac);

    /*
     * Record this event
     */
    if (dir == DIR_BASE_TO_STA) {
        regmac_event(squirrel->sqdb, 
            EVENT_DEAUTH,
            frame->bss_mac, frame->dst_mac,
            EVENT_DEAUTH_FROM_AP, frame);
    } else if (dir == DIR_STA_TO_BASE) {
        regmac_event(squirrel->sqdb, 
            EVENT_DEAUTH,
            frame->bss_mac, frame->src_mac,
            EVENT_DEAUTH_FROM_STA, frame);
    }

	reason = ex16le(px+24);
	switch (reason) {
	case 0x0001: /* Unspecified reason */
		/* REF: sniff-2009-02-09-127.pcap(2912) */
		if (dir == DIR_BASE_TO_STA)
			regmac_station_ctrl(squirrel->sqdb, frame->bss_mac, frame->dst_mac, dir);
		else if (dir == DIR_STA_TO_BASE)
			regmac_station_ctrl(squirrel->sqdb, frame->bss_mac, frame->src_mac, dir);
		else
			FRAMERR(frame, "deauth: unknow direction\n");
		break;
	case 0x0002: /* Previous authentication no longer valid */
		/* Sent from AP to STA telling it that it's previous authentication has expired 
		 * REF: sniff-2009-02-09-127.pcap(2516) */
        if (dir == DIR_BASE_TO_STA) {
			regmac_station_ctrl(squirrel->sqdb, frame->bss_mac, frame->dst_mac, dir);                
        } else if (dir == DIR_STA_TO_BASE) {
			regmac_station_ctrl(squirrel->sqdb, frame->bss_mac, frame->src_mac, dir);
        } else
			FRAMERR(frame, "deauth: unknow direction\n");
		break;
	case 0x0003: /* Station leaving (or has left) ESSID/BSSID */
		/* Sent from STA to AP telling it that it is about to leave the system */
		if (dir == DIR_STA_TO_BASE)
			regmac_station_ctrl(squirrel->sqdb, frame->bss_mac, frame->src_mac, dir);
        else
			FRAMERR(frame, "deauth: unknow direction\n");
		break;
	case 0x0004: /* Disassociated due to inactivity */
		/* Sent from AP to STA telling it that it is being disconnected because it's inactive */
		if (dir == DIR_BASE_TO_STA)
			regmac_station_ctrl(squirrel->sqdb, frame->bss_mac, frame->dst_mac, dir);
		else
			FRAMERR(frame, "deauth: unknow direction\n");
		break;
	case 0x0006:
		/* Sent from AP to STA telling it that it is not authenticated */
		/* REF: sniff-2009-02-09-127.pcap */
		if (dir == DIR_BASE_TO_STA)
			regmac_station_ctrl(squirrel->sqdb, frame->bss_mac, frame->dst_mac, dir);
		else
			FRAMERR(frame, "deauth: unknow direction\n");
		break;
	case 0x0007: /* ?? */
		/* REF: wifi-2009-02-09.pcap(16481) */
		/* These packets are confusing, they need more study */
		break;
	case 0x000f: /* ?? */
		/* REF: wifi-2009-02-09.pcap(379754) 
		 * Deauthentication 4-way handshake timeout */
		if (dir == DIR_BASE_TO_STA)
			regmac_station_ctrl(squirrel->sqdb, frame->bss_mac, frame->dst_mac, dir);
		else
			FRAMERR(frame, "deauth: unknow direction\n");
		break;
	default:
		FRAMERR(frame, "wifi.data: unknown deauth reason: 0x%04x\n", reason);
	}

	regmac_transmit_power(squirrel->sqdb, frame->src_mac, frame->dbm, frame->time_secs);
}

void squirrel_wifi_disassociate(struct Squirrel *squirrel, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned reason;
	unsigned direction;
	unsigned dir;

	/* Additional data */
	if (length < 26) {
		FRAMERR(frame, "wifi: truncated\n");
		return;
	}

	/* Packet direction check */
	direction = px[1]&3;
	switch (direction) {
	case 0:
		break;
	case 1:
	case 2:
	case 3:
		FRAMERR(frame, "deauth: unknown direction %d\n", direction);
		break;
	}

	/* Extract Addresses */
	frame->dst_mac = px+4;
	frame->src_mac = px+10;
	frame->bss_mac = px+16;
	regmac_transmit_power(squirrel->sqdb, frame->src_mac, frame->dbm, frame->time_secs);

	/*
	 * Only look at packets coming from the base/access-point, because that
	 * tells us what authentication they require
	 */
	dir = regmac_base_resolve_direction(squirrel->sqdb, frame->bss_mac, frame->src_mac, frame->dst_mac);

	reason = ex16le(px+24);
	switch (reason) {
	case 0x0008: /* Station leaving (or has left) ESSID/BSSID */
		/* Sent from STA to AP telling it that it is about to leave the system 
		 * REF: sniff-2009-02-09-127.pcap(274351) */
		if (dir == DIR_STA_TO_BASE)
			regmac_station_ctrl(squirrel->sqdb, frame->bss_mac, frame->src_mac, dir);
		else
			FRAMERR(frame, "deauth: unknow direction\n");
		break;
	case 0x0001: /* ??? */
		/* REF: sniff-2009-02-10-127.pcap(1133074) */
		FRAMERR(frame, "wifi.data: unknown deauth reason: 0x%04x\n", reason);
		break;
	default:
		FRAMERR(frame, "wifi.data: unknown deauth reason: 0x%04x\n", reason);
	}
}

/**
 * This function is called by a wireless-station to inform the access-point
 * that is about to go to sleep for a short period of time. The access-point
 * will buffer incoming packets and save them to transmit to the
 * wireless-station when it wakes up. The periods for which it goes to sleep
 * are measured in tenths-of-a-second.
 */
void squirrel_wifi_ctrl_power_save_poll(struct Squirrel *squirrel, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned direction;

	/* VALIDATE: enough data in packet */
	if (length < 16) {
		FRAMERR(frame, "wifi: truncated\n");
		return;
	}

	/* VALIDATE: proper direction field */
	direction = px[1]&3;
	if (direction != 0) {
		FRAMERR(frame, "unknown direction %d\n", direction);
		return;
	}

	/* Get MAC addresses */
	frame->bss_mac = px+4;
	frame->dst_mac = px+4;
	frame->src_mac = px+10;

	regmac_transmit_power(squirrel->sqdb, frame->src_mac, frame->dbm, frame->time_secs);

	/* Remember the fact that we saw this station connected to this
	 * BSSID */
	regmac_station_ctrl(squirrel->sqdb, frame->bss_mac, frame->src_mac, DIR_STA_TO_BASE);
}

/**
 * This packet is sent before a data back asking permission to send.
 * By doing this, it prevents accidental collisions at the access-point when
 * two wireless-stations cannot see each other (hidden-node problem).
 */
void squirrel_wifi_ctrl_frame(struct Squirrel *squirrel, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned direction;
	const unsigned char *transmitter;
	const unsigned char *receiver;
	unsigned receiver_type;
	unsigned transmitter_type;
	const unsigned char *substation_mac;
	const unsigned char *access_point_mac;

	/* VALIDATE: enough data in packet */
	if (length < 16) {
		FRAMERR(frame, "wifi: truncated\n");
		return;
	}

	/* VALIDATE: proper direction field */
	direction = px[1]&3;
	if (direction != 0) {
		FRAMERR(frame, "unknown direction %d\n", direction);
		return;
	}

	/* We don't necessarily know which one is a base-station and 
	 * which one is the client. We have to look up these types
	 * first */
	receiver = px+4;
	transmitter = px+10;
	regmac_transmit_power(squirrel->sqdb, transmitter, frame->dbm, frame->time_secs);

	receiver_type = sqdb_station_type(squirrel->sqdb, receiver);
	transmitter_type = sqdb_station_type(squirrel->sqdb, transmitter);

	if (receiver_type == STATION_TYPE_UNKNOWN || receiver_type == STATION_TYPE_MULTICAST) {
		switch (transmitter_type) {
		case STATION_TYPE_BASE:
			receiver_type = STATION_TYPE_STA;
			break;
		case STATION_TYPE_STA:
			receiver_type = STATION_TYPE_BASE;
			break;
		}
	}
	if (transmitter_type == STATION_TYPE_UNKNOWN) {
		switch (receiver_type) {
		case STATION_TYPE_BASE:
			transmitter_type = STATION_TYPE_STA;
			break;
		case STATION_TYPE_STA:
			transmitter_type = STATION_TYPE_BASE;
			break;
		}
	}

	switch (transmitter_type) {
		const unsigned char *bssid;
	case STATION_TYPE_BASE:
		substation_mac = receiver;
		access_point_mac = transmitter;

		if (receiver_type == STATION_TYPE_MULTICAST)
			return;

		bssid = sqdb_lookup_bssid_by_access_point(squirrel->sqdb, access_point_mac);
		if (bssid)
			regmac_station_ctrl(squirrel->sqdb, bssid, receiver, DIR_BASE_TO_STA);
		else
			FRAMERR(frame, "unknown bssid\n");
		break;
	case STATION_TYPE_STA:
		substation_mac = transmitter;
		access_point_mac = receiver;
		bssid = sqdb_lookup_bssid_by_access_point(squirrel->sqdb, access_point_mac);
		if (bssid)
			regmac_station_ctrl(squirrel->sqdb, bssid, transmitter, DIR_STA_TO_BASE);
		else
			FRAMERR(frame, "unknown bssid\n");
		break;
	}
}

/**
 * Parses a "Beacon" packet from an WiFi Access Point (AP).
 * These are the packets that NetStumbler picks up on to find access-points.
 * On a quiet network, the majority of packets will be these beacons
 * from access points announcing themselves.
 *
 * The most important information we are interested in is the SSID.
 */
void squirrel_wifi_beacon(struct Squirrel *squirrel, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned offset;
	struct	WIFI_MGMT wifimgmt;
	/*unsigned supports_wep=0;*/
	unsigned capability;
	unsigned direction;
	const unsigned char *bssid;
	const unsigned char *mac_address;
    unsigned is_adhoc = 0;

	memset(&wifimgmt, 0, sizeof(wifimgmt));

	/* Beacon Frame:
	 * 
	 * +--------+--------+
	 * |  0x80  |  0x00  | Frame Control
	 * +--------+--------+
	 * |    duration     | 
	 * +--------+--------+--------+--------+--------+--------+
	 * |                   FF:FF:FF:FF:FF:FF                 |
	 * +--------+--------+--------+--------+--------+--------+
	 * |                  source MAC address                 |
	 * +--------+--------+--------+--------+--------+--------+
	 * |                        BSSID                        |
	 * +--------+--------+--------+--------+--------+--------+
	 * |       seq#      | 
	 * +--------+--------+--------+--------+
	 * |                                   |
	 * |             timestamp             |
	 * +--------+--------+--------+--------+
	 * |     interval    | 
	 * +--------+--------+
	 * |    capability   | 
	 * +--------+--------+--------...
	 * |   tag  | length |  value
	 * +--------+--------+--------...
	 * |   tag  | length |  value
	 * +--------+--------+--------...
	 * |   tag  | length |  value
	 * +--------+--------+--------...
	 * .        .        .
	 * .        .        .
	 * .        .        .
	 *
	 *  [INTERVAL]
	 *	Usually around 1/10th of a second, this tells the amount of time 
	 *  between beacons. Stations can tell the access-point that they are
	 *  going to sleep for a while. If any packets arrive for the station,
	 *  the access-point will queue them up and add a flag to the beacon
	 *  saying that packets are waiting. The station knows to wake up
	 *  every interval to see if any packets have arrived, and go to sleep
	 *  for the rest of the time.
	 *
	 *  
	 */

	if (length < 24) {
		FRAMERR(frame, "wifi: truncated\n");
		return;
	}
	
	/* Grab the source Ethernet address (i.e. the address of the access point) */
	direction = px[1]&3;
	if (direction != 0)
		FRAMERR(frame, "MGMT-BEACON: bad direction bit\n");
	memcpy(wifimgmt.source, px+10, 6);
	memcpy(wifimgmt.bss_id,  px+16, 6);
	mac_address = px+10;
	bssid = px+16;


	/* Copy the beacon into the BSSI entry */
	{
		struct SquirrelPacket pkt[1];
		pkt->length = length;
		pkt->secs = frame->time_secs;
		pkt->usecs = frame->time_usecs;
		pkt->px = px;
        pkt->linktype = frame->layer2_protocol;
		sqdb_set_bssid_packet(squirrel->sqdb, wifimgmt.bss_id, SQPKT_BEACON, pkt);
	}

	/* Record how much transmit power we have */
	regmac_transmit_power(squirrel->sqdb, mac_address, frame->dbm, frame->time_secs);

	/* 
	 * Process the FIXED information
	 */
	offset = 24; /* packet header */
	offset += 8; /* timestamp */
	offset += 2; /* beacon interval */
	capability = px[offset] | (px[offset+1] << 8);
    if (capability & 0x02)
        is_adhoc = 1;
	offset += 2; /* capability information */
    
	/*
	 * Process the variable information
	 */
	{
		unsigned channel;
		struct SQDB_RateList rates1;
		struct SQDB_RateList rates2;
		struct SQDB_String ssid;
        struct SQDB_String cisco_name;

		ssid = ie_to_string(get_information_element(px, offset, length, 0x00));
		rates1 = ie_to_rate_list(get_information_element(px, offset, length, 0x01));
		rates2 = ie_to_rate_list(get_information_element(px, offset, length, 0x32));
		channel = ie_to_unsigned(get_information_element(px, offset, length, 0x03));
        cisco_name = ie_decode_cisco_name(get_information_element(px, offset, length, 0x85));

		sqdb_add_beacon(
			squirrel->sqdb, 
			mac_address,
			bssid,
			ssid,
			channel,
			rates1,
			rates2,
            is_adhoc,
            cisco_name
			);

		ie_wpa1wme_to_crypto_flags(squirrel->sqdb, frame, bssid, 
			get_information_element(px, offset, length, 221, 0x0050F2, 1));
		ie_wpa2rsn_to_crypto_flags(squirrel->sqdb, frame, bssid, 
			get_information_element(px, offset, length, 48));
		if (capability & 0x010)
			regmac_base_crypto(squirrel->sqdb, bssid, ENC_TYPE_WEP);

	}




}

#define XX(type,subtype) ((type)<<2)|((subtype)<<4)
/**
 * Tries to decrypt a WEP packet by cycling through keys
 */
unsigned test_wep_decrypt(
						const unsigned char *px, unsigned length, 
						unsigned char *new_px, unsigned *r_new_length)
{
	unsigned i;
	struct XKey {
		unsigned len;
		const char *key;
	} xkey[] = {
        { 40, "\x12\x34\x56\x19\x72"}, /* Chef Rob's */
		{ 40, "\x77\x03\x90\x08\x59"}, /* Royal Oak 1 */
		{ 40, "\x69\x93\x71\x62\x53"}, /* Royal Oak 1 */
		{ 40, "\x11\x28\x52\x46\x14"}, /* Royal Oak 1 */
		{104, "\xa3\x42\xee\x54\xc1\x2e\x5d\x23\x1f\xfe\xe0\x02\x00"},
		{ 40, "\x11\x11\x11\x11\x11"},
		{ 40, "\x4b\x78\x52\xd7\x80"},
		{ 40, "\x00\x00\x00\x00\x00"},
		{ 40, "\x12\x34\x56\x78\x90"},
		{104, "\x10\x01\x11\x11\x00\x00\x11\x11\x00\x00\x11\x11\x01"},
		{104, "\x12\x34\x56\x78\x90\xab\xcd\xef\x12\x34\x56\x78\x90"},
	};

	int foo;


	if (length > 4)
		*r_new_length = length-4;
	else
		return 0; /* error, too short */

	/*
	 * Attempt to decrypt using all the keys, and return the
	 * first one that is found. WEP has a built-in CRC that we use
	 * to check that the encryption was successful.
	 */
	for (i=0; i<sizeof(xkey)/sizeof(xkey[0]); i++) {
		memcpy(new_px, px, length);
		foo = wep_decrypt_packet(new_px+24, length-24, xkey[i].len/8, (const unsigned char*)xkey[i].key);
		if (foo == 0)
			return 1; /* Successfully decrypted */
	}

	return 0;
}


void squirrel_wifi_data(struct Squirrel *squirrel, struct NetFrame *frame, const unsigned char *px, unsigned length)
{
	unsigned offset=0;
	unsigned ethertype;
	unsigned oui;
	unsigned version, type, subtype;
	unsigned is_null=0;

	version = px[0]&3;
	type = (px[0]>>2)&3;
	subtype = (px[0]>>4)&0xf;

	if (length < 24) {
		FRAMERR(frame, "wifi.data: too short\n");
		return;
	}

	/* Skip fixed header */
	offset += 24;
	if ((px[1]&0x03) == 3)
		offset += 6;

	switch (XX(type,subtype)) {
	case XX(2,0x0): /* Data */
		is_null = 0;
		break;
	case XX(2,0x4): /* Data (NULL function) */
		is_null = 1;
		break;
	case XX(2,0x8): /* Data (QoS) */
		offset += 2; /* QoS data */
		is_null = 0;
		break;
	case XX(2,0xc): /* Data (QoS, NULL function) */
		is_null = 1;
		offset += 2; /* QoS data */
		break;
	}

	/* Mark this packet */
	switch (px[1]&0x03) {
	case 0:
		frame->dst_mac = px+4;
		frame->src_mac = px+10;
		frame->bss_mac = px+16;
		if (memcmp(frame->bss_mac, frame->dst_mac, 6) == 0 && is_null) {
			regmac_station_ctrl(squirrel->sqdb, frame->bss_mac, frame->dst_mac, DIR_STA_TO_BASE);
        } else if (memcmp("\xFF\xFF\xFF\xFF\xFF\xFF", frame->dst_mac, 6) == 0 && !is_null) {
            /* Regress: adhoc00166f946afd.pcap(35) */
			regmac_station_data(squirrel->sqdb, frame->bss_mac, frame->src_mac, DIR_STA_TO_BASE);
        } else
			FRAMERR(frame, "unknown\n");
		regmac_transmit_power(squirrel->sqdb, frame->src_mac, frame->dbm, frame->time_secs);
		break;
	case 2:
		/* This packet is sent by a station on the WIRED network through
		 * the access-point bridge to a station on the WIRELESS side */
		frame->dst_mac = px+4;
		frame->bss_mac = px+10;
		frame->src_mac = px+16;

		if (!is_null && offset < length) {
			regmac_station_data(squirrel->sqdb, frame->bss_mac, frame->dst_mac, DIR_RECEIVED);
			if (memcmp(frame->src_mac, frame->bss_mac, 6) != 0)
				regmac_station_wired(squirrel->sqdb, frame->bss_mac, frame->src_mac, DIR_SENT);
		} else
			regmac_station_ctrl(squirrel->sqdb, frame->bss_mac, frame->dst_mac, DIR_BASE_TO_STA);

		regmac_transmit_power(squirrel->sqdb, frame->src_mac, frame->dbm, frame->time_secs);
		break;
	case 1:
		frame->bss_mac = px+4;
		frame->src_mac = px+10;
		frame->dst_mac = px+16;

		if (!is_null && offset < length) {
			regmac_station_data(squirrel->sqdb, frame->bss_mac, frame->src_mac, DIR_SENT);
			if (memcmp(frame->dst_mac, frame->bss_mac, 6) != 0)
				regmac_station_wired(squirrel->sqdb, frame->bss_mac, frame->dst_mac, DIR_RECEIVED);
		} else
			regmac_station_ctrl(squirrel->sqdb, frame->bss_mac, frame->src_mac, DIR_STA_TO_BASE);

		regmac_transmit_power(squirrel->sqdb, frame->src_mac, frame->dbm, frame->time_secs);
		break;
	case 3:
		frame->bss_mac = (const unsigned char*)"\0\0\0\0\0\0";
		frame->dst_mac = px+16;
		frame->src_mac = px+24;
		offset += 6;
		break;
	}


	/* If this is a "NULL" frame, then stop processing here 
	 * before getting to data */
	if (px[0] == 0x48 || px[0] == 0xc8)
		return;

	/* Handle encrypted stuff */
	if (px[1] & 0x40) {
		unsigned char tmp_packet[2048];
		unsigned tmp_length=0;
        if (test_wep_decrypt(px, length, tmp_packet, &tmp_length)) {
            px = tmp_packet;
            length = tmp_length;
        } else
            return;
	}
	





	/* Look for SAP header */
	if (offset + 6 >= length) {
		//FRAMERR(frame, "wifi.sap: too short\n");
		return;
	}

	if (length-offset > 5 && memcmp(px+offset, "\xe0\xe0\x03\xFF\xFF", 5) == 0) {
		offset += 3;
		//parse_novell_ipx(squirrel, frame, px+offset, length-offset);
		return;
	}

	if (memcmp(px+offset, "\x00\x00\xaa\xaa\x03", 5) == 0) {
		offset += 2;
	} else if (memcmp(px+offset, "\xaa\xaa\x03", 3) != 0) {
		return;
	}
	offset +=3 ;

	oui = ex24be(px+offset);

	/* Look for OUI code */
	switch (oui){
	case 0x000000:
		/* fall through below */
		break;
	case 0x004096: /* Cisco Wireless */
		return;
		break;
	case 0x00000c:
		offset +=3;
        if (offset < length) {
			; //squirrel_cisco00000c(squirrel, frame, px+offset, length-offset);
		}
        return;
	case 0x080007:
		break; /*apple*/
	case 0x000b85:
		/* Some sort of Cisco packet sent between access-points */
		return;
	case 0x0037f: /* Atheros */
		/* Looking at the packet, it seems to contains MULTPLE TCP/IP packets
		 * that have similar IP/port info to other packets on the wire. I'm thinking
		 * that maybe it's briding packet across multiple access points? Or, it
		 * maybe just including "slack" data, which of course happen to be
		 * packets */
		return;
	case 0x00601d: /* Lucent */
		return;
	default:
		FRAMERR(frame, "Unknown SAP OUI: 0x%06x\n", oui);
		return;
	}
	offset +=3;

	/* EtherType */
	if (offset+2 >= length) {
		FRAMERR(frame, "ethertype: packet too short\n");
		return;
	}

	ethertype = ex16be(px+offset);
	offset += 2;

	/* Check for 802.1q VLAN */
	switch (ethertype) {
	case 0x9100: /* Cisco version of 802.1q */
	case 0x9200: /* Cisco version of 802.1q */
	case 0x8100: /* 802.1q encapsulation */
		if (offset+4 >= length) {
			FRAMERR(frame, "ethertype: packet too short\n");
			return;
		}
		offset += 2;
		ethertype = ex16be(px+offset);
		offset += 2;
		break;
	}

	switch (ethertype) {
	case 0x0006: /* ??? */
		/* I saw this packet at Toorcon. I have no idea what it's doing, but I'm
		 * filtering it out from printing an error message */
		break;
	case 0x0800: /* IP */
		squirrel_ip(squirrel, frame, px+offset, length-offset);
		break;
	case 0x0806: /* ARP */
		squirrel_arp(squirrel, frame, px+offset, length-offset);
		break;
	case 0x8035: /* Reverse ARP */
		FRAMERR_BADVAL(frame, "ethertype", ethertype);
		break;
	case 0x809b: /* Apple-talk I*/
		//parse_atalk_ddp(squirrel, frame, px+offset, length-offset);
		break;
	case 0x80f3: /* AppleTalk ARP */
		/* This will have the same format as ARP, except that AppleTalk
		 * addresses will be used instead of IP addresses */
		break;
	case 0x8137: /* Novell IPX */
	case 0x8138: /* Novell */
		FRAMERR_BADVAL(frame, "ethertype", ethertype);
		break;
	case 0x86dd: /* IPv6*/
		//squirrel_ipv6(squirrel, frame, px+offset, length-offset);
		break;
	case 0x872d: /* Cisco OWL */
		break;
	case 0x8863: /* PPPoE Discover */
		//parse_ppoe_discovery(squirrel, frame, px+offset, length-offset);
		break;
	case 0x888e: /*802.11x authentication*/
		//squirrel_802_1x_auth(squirrel, frame, px+offset, length-offset);
		break;
	default:
		if (length-offset > 8 && ethertype <= length-offset && ethertype+10 >length-offset && memcmp(px+offset, "\xAA\xAA\x03\x08\x00\x07\x80\x9b", 8) == 0) {
			offset += 8;
			//parse_atalk_ddp(squirrel, frame, px+offset, length-offset);
		} else if (ethertype == length-offset && ex16be(px+offset) == 0xAAAA) {
		}
		else
			FRAMERR_BADVAL(frame, "ethertype", ethertype);
	}
}

unsigned filtered_out(struct NetFrame *frame, const char *mac_address)
{
	if (frame->src_mac && memcmp(frame->src_mac, mac_address, 6) == 0)
		return 1;
	if (frame->dst_mac && memcmp(frame->dst_mac, mac_address, 6) == 0)
		return 1;
	if (frame->bss_mac && memcmp(frame->bss_mac, mac_address, 6) == 0)
		return 1;
	return 0;
}

/**
 * Parses raw 802.11 WiFi frames. This requires specialized wifi adapters and
 * drivers, otherwise you'll just get Ethernet frames from the driver (and
 * would instead hit the 'parse_ethernet()' function instead of this one).
 *
 * Both wifi management packets (like Beacons and Probes) are parsed here,
 * as well as Data packets.
 *
 * TODO: at some point, we'll add the ability to import WEP and WAP keys to
 * automatically decrypt packets.
 */
void
squirrel_wifi_frame(struct Squirrel *squirrel,
                    struct NetFrame *frame,
                    const unsigned char *px, unsigned length)
{
	unsigned version, type, subtype;


	version = px[0]&3;
	type = (px[0]>>2)&3;
	subtype = (px[0]>>4)&0xf;

	/* Only version=0 is used in the real world, any other value indicates
	 * that the packet has been corrupted */
	if (version != 0) {
		FRAMERR(frame, "wifi packet corrupted, version=%d\n", version);
		return;
	}


	/* Copy the MAC addresses found in the packet to the NetFrame structure */
	squirrel_get_mac_address(frame, px, length);


#define XX(type,subtype) ((type)<<2)|((subtype)<<4)

	/*
	 * Dispatch to the correct function to handle the packet
	 */
	switch (XX(type,subtype)) {
	case XX(0,0x0): /* MGMT - Association Request */
		squirrel_wifi_associate_request(squirrel, frame, px, length);
		break;
	case XX(0,0x1): /* MGMT - Assocation Response */
		squirrel_wifi_associate_response(squirrel, frame, px, length);
		break;
	case XX(0,0x2): /* MGMT - Reassociation Request */
		squirrel_wifi_associate_request(squirrel, frame, px, length);
		break;
	case XX(0,0x3): /* MGMT - Reassociation Response*/
		squirrel_wifi_associate_response(squirrel, frame, px, length);
		break;
	case XX(0,0x4): /* MGMT - Probe Request */
		squirrel_wifi_proberequest(squirrel, frame, px, length);
		break;
	case XX(0,0x5): /* MGMT - Probe Response */
		squirrel_wifi_beacon(squirrel, frame, px, length);
		break;
	case XX(0,0x8): /* MGMT - Beacon */
		squirrel_wifi_beacon(squirrel, frame, px, length);
		break;
	case XX(0,0xD): /* MGMT - Action */
		squirrel_wifi_mgmt_action(squirrel, frame, px, length);
		break;
	case XX(0,0x9): /* MGMT - Announcement traffic indication message (ATIM) */
		FRAMERR(frame, "unknown wifi packet [0x%02x]\n", px[0]);
		break;
	case XX(0,0xa): /* MGMT - Disassociate Request */
		squirrel_wifi_disassociate(squirrel, frame, px, length);
		break;
	case XX(0,0xb): /* MGMT - Authentication */
		squirrel_wifi_authentication(squirrel, frame, px, length);
		break;
	case XX(0,0xc): /* MGMT - Deauthentication Request */
		squirrel_wifi_deauthentication(squirrel, frame, px, length);
		break;

	case XX(2,0x0): /* Data */
	case XX(2,0x4): /* Data (NULL function) */
	case XX(2,0x8): /* Data (QoS) */
	case XX(2,0xc): /* Data (QoS, NULL function) */
		squirrel_wifi_data(squirrel, frame, px, length);
		break;
	case XX(1,0xa): /* CTRL - Power Save Poll */
		/* REF: sniff-2009-02-09-127.pcap(231303) */
		squirrel_wifi_ctrl_power_save_poll(squirrel, frame, px, length);
		break;
	case XX(1,0xb): /* CTRL - Request-to-Send (RTS) */
		squirrel_wifi_ctrl_frame(squirrel, frame, px, length);
		break;
	case XX(1,0xE): /* CTRL - CF-END */
		squirrel_wifi_ctrl_frame(squirrel, frame, px, length);
		break;
	case XX(1,0x8): /* CTRL - Block Ack Request */
	case XX(1,0x9): /* CTRL - Block Ack Response */
		squirrel_wifi_ctrl_frame(squirrel, frame, px, length);
		break;
	case XX(1,0xC): /*clear to send */
	case XX(1,0xD): /*acknowledgement*/
		/* This only has the "receiver address" of whom the ack is going to,
		 * which doesn't tell us anything about the sender, although we might
		 * be able to reverse engineer the sender according to the sending power*/
		break;
	default:
		FRAMERR(frame, "unknown wifi packet [0x%02x]\n", px[0]);

	}
}

/*
00  Management  0000  		Association request
00 	Management 	0001 		Association response
00 	Management 	0010 		Reassociation request
00 	Management 	0011 		Reassociation response
00 	Management 	0100 		Probe request
00 	Management 	0101 		Probe response
00 	Management 	0110-0111 	Reserved
00 	Management 	1000 		Beacon
00 	Management 	1001 		Announcement traffic indication message (ATIM)
00 	Management 	1010 		Disassociation
00 	Management 	1011 		Authentication
00 	Management 	1100 		Deauthentication
00 	Management 	1101-1111 	Reserved
01 	Control 	0000-1001 	Reserved
01 	Control 	1010 		Power Save (PS)-Poll
01 	Control 	1011 		Request To Send (RTS)
01 	Control 	1100 		Clear To Send (CTS)
01 	Control 	1101 		ACK
01 	Control 	1110 		Contention Free (CF)-end
01 	Control 	1111 		CF-end + CF-ACK
10 	Data 		0000 	Data
10 	Data 		0001 	Data + CF-ACK
10 	Data 		0010 	Data + CF-Poll
10 	Data 		0011 	Data + CF-ACK+CF-Poll
10 	Data 		0100 	Null function
10 	Data 		0101 	CF-ACK
10 	Data 		0110 	CF-Poll
10 	Data 		0111 	CF-ACK + CF-Poll
10 	Data 		1000-1111 	Reserved
11 	Data 		0000-1111 	Reserved 
*/
