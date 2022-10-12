#ifndef __SQDB_H
#define __SQDB_H
#include <time.h>

struct SQDB;
struct SquirrelPacket;

/**
 * Holds a list of rates. There are two lists, one originally
 * defined for 802.11b that used PSK/CCK encoding, another
 * for 802.11g that used OFDM encoding. Even when both lists
 * contain the same speed, such as 11-MHz, they will use a 
 * different encoding. Thus, we need to store both these
 * lists separately
 */
struct SQDB_RateList {
	unsigned count;
	unsigned char rates[16];
};

/** 
 * Holds an SSID field.
 *
 * The standard says that SSIDs can only be up to 32 bytes
 * long, but the field can hold up to 255 bytes. I compromise
 * at 48 bytes to conserve space. If the SSID is longer than 
 * that, I remove bytes from the MIDDLE of the proffered field
 * so that we can see a few bytes from both the beginning
 * and end.
 */
struct SQDB_String {
	unsigned length;
	unsigned char value[48];
};

struct SQDB *sqdb_create(void);


/**
 * Called when we see a beacon or probe-response packet
 */
unsigned sqdb_add_beacon(
	 struct SQDB *sqdb, 
	 const unsigned char *src_mac,
	 const unsigned char *bssid,
	 struct SQDB_String ssid,
	 unsigned channel,
	 struct SQDB_RateList rates1,
	 struct SQDB_RateList rates2,
     unsigned is_adhoc,
     struct SQDB_String cisco_name
	 );

enum WiFiStandard {
    WIFI_80211a,     // 5 GHz
    WIFI_80211b,    // original 2.4 GHz (11 mbps)
    WIFI_80211g,    // faster 2.4 GHz (54 mbps)
    WIFI_80211n,    // faster 2.4/5 GHz, 150/300/450 mbps
    WIFI_80211ac,   // faster 5 GHz (~gigabit/s)
};
/**
 * Called when we see a probe packet from a station
 */
unsigned sqdb_add_probe_request(
	struct SQDB *sqdb, 
	const unsigned char *mac_address,
	struct SQDB_String ssid,
	struct SQDB_RateList rates1,
	struct SQDB_RateList rates2,
    const struct SquirrelPacket *pkt,
    unsigned ie_hash,
    enum WiFiStandard standard,
    unsigned channel_width
	);





void
sqdb_add_info(struct SQDB *sqdb, const unsigned char *mac_address, const unsigned char *bssid,
			  const char *name, const char *value, int in_length);



/**
 * Given a MAC address, return the type of wireless station
 */
enum {
	STATION_TYPE_UNKNOWN = 1,
	STATION_TYPE_BASE = 2,
	STATION_TYPE_STA = 3,
	STATION_TYPE_STA_ALONE,
	STATION_TYPE_WIRED,
	STATION_TYPE_MULTICAST
};
unsigned 
sqdb_station_type(struct SQDB *sqdb, const unsigned char *mac_address);

const unsigned char *
sqdb_lookup_bssid_by_access_point(struct SQDB *sqdb, const unsigned char *mac_address);

enum {
	ENC_TYPE_WEP	= 1,
	ENC_TYPE_WEP40	= 2,
	ENC_TYPE_WEP128	= 4,
	ENC_TYPE_WPA	=0x0008,
	ENC_TYPE_WPA2	=0x0010,
	ENC_TYPE_WPAu	=0x0020,
	CIPHER_TYPE_WEP	=0x0040,
	CIPHER_TYPE_TKIP=0x0080,
	CIPHER_TYPE_AES =0x0100,
	AUTH_TYPE_OPEN	=0x0400,
	AUTH_TYPE_SKA	=0x0800,
	AUTH_TYPE_EAP	=0x1000,
	AUTH_TYPE_PSK	=0x2000,
	AUTH_TYPE_MGMT	=0x4000,
};
/*enum {
	SQDB_CRYPTO_WEP			= 0x01,
	SQDB_CRYPTO_CRYPT_TKIP	= 0x04,
	SQDB_CRYPTO_CRYPT_AES	= 0x08,
	SQDB_CRYPTO_AUTH_PSK	= 0x10,
	SQDB_CRYPTO_AUTH_EAP	= 0x20,
	SQDB_CRYPTO_AUTH_PRE	= 0x40,
	SQDB_CRYPTO_AUTH_WPA	= 0x80,
} SQDB_Crypto;*/


void 
sqdb_set_bssid_auth_type(struct SQDB *sqdb, const unsigned char *bssid, unsigned auth_type);

struct SquirrelPacket {
    struct SquirrelPacket *next;
    unsigned type;
	const unsigned char *px;
	unsigned length;
	time_t secs;
	unsigned usecs;
    unsigned linktype;
};
enum {
	SQPKT_UNKNOWN=0,
	SQPKT_BEACON,
    SQPKT_PROBERESPONSE,
};

/**
 * Saves packets with the BSSID, such as the beacon packet.
 */
unsigned
sqdb_set_bssid_packet(struct SQDB *sqdb, const unsigned char *bssid, unsigned type, const struct SquirrelPacket *pkt);

unsigned
sqdb_get_bssid_packet(struct SQDB *sqdb, const unsigned char *bssid, unsigned type, struct SquirrelPacket *pkt);
unsigned
sqdb_get_prober_packets(struct SQDB *sqdb, const unsigned char *mac, struct SquirrelPacket *packets);

unsigned
sqdb_set_prober_packet(struct SQDB *sqdb, const unsigned char *bssid, unsigned type, const struct SquirrelPacket *pkt);

unsigned
sqdb_get_prober_packet(struct SQDB *sqdb, const unsigned char *bssid, unsigned type, struct SquirrelPacket *pkt);

/**
 * Register the fact that we have seen a base-station/access-point with the given
 * BSSID and mac-address. Note that in 90% of the cases, the bssid and mac-address
 * will be the same, and in 10% of the time, they might be different (because 
 * there are more than one bases within a BSSID)
 */
void regmac_base(struct SQDB *sqdb, const unsigned char *bssid, const unsigned char *base_mac_address);

/**
 * Register the fact that we've seen an SSID associated with a bssid
 */
void regmac_base_ssid(struct SQDB *sqdb, const unsigned char *bssid, struct SQDB_String *ssid);

void regmac_base_rates(struct SQDB *sqdb, const unsigned char *bssid, struct SQDB_RateList *rates1, struct SQDB_RateList *rates2);

/**
 * Mark a crypto feature
 */
void regmac_base_crypto(struct SQDB *sqdb, const unsigned char *bssid, unsigned crypto);

/**
 * Register the fact that we have seen a client/station interacting with a bssid through some
 * means other than DATA packets.
 */
void regmac_station_ctrl(struct SQDB *sqdb, const unsigned char *bssid, const unsigned char *mac_address, unsigned dir);
#define regmac_station regmac_station_ctrl

void regmac_station_data(struct SQDB *sqdb, const unsigned char *bssid, const unsigned char *mac_address, unsigned dir);
void regmac_station_wired(struct SQDB *sqdb, const unsigned char *bssid, const unsigned char *mac_address, unsigned dir);

enum {
    EVENT_UNKNOWN,
    EVENT_DEAUTH,
    EVENT_ASSOC,
    EVENT_DEAUTH_FROM_AP,
    EVENT_DEAUTH_FROM_STA,
    
    EVENT_PROBE_REQ,
    EVENT_PROBE_RSP,
    EVENT_AUTH_REQ,
    EVENT_AUTH_RSP,
    EVENT_ASSOC_REQ,
    EVENT_ASSOC_RSP,
    EVENT_EAPOL_REQ1,
    EVENT_EAPOL_RSP1,
    EVENT_EAPOL_REQ2,
    EVENT_EAPOL_RSP2,

};
struct StackFrame;
void regmac_event(struct SQDB *sqdb, 
                         unsigned event_type,
                         const unsigned char *bssid, const unsigned char *mac_address, 
                         unsigned frame_type,
                         struct StackFrame *frame);

/** Resolve which direction this packet went, either to a STA or to a BASE */
unsigned regmac_base_resolve_direction(struct SQDB *sqdb, const unsigned char *bssid, const unsigned char *src, const unsigned char *dst);
enum {
	DIR_UNKNOWN,
	DIR_BASE_TO_STA,
	DIR_STA_TO_BASE,
	DIR_RECEIVED,
	DIR_SENT
};

/**
 * Mark the transmit power and timestamp
 */
void regmac_transmit_power(struct SQDB *sqdb, const unsigned char *mac_address, int dbm, time_t timestamp);


#endif /*__SQDB_H*/
