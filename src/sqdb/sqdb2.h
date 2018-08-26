#ifndef	SQDB2_H
#define SQDB2_H
#ifdef __cplusplus
extern "C" {
#endif

#include "../squirrel.h"

#ifndef true
#define true (1)
#endif
#ifndef false
#define false (0)
#endif
#ifndef bool
#define bool unsigned
#endif

#define PRINTMAC(mac) mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
#define PRINTSTR(str) (str)->length, (str)->value
extern void SQUIRREL_EVENT(const char *msg, ...);


struct EntryMacAddr
{
	unsigned char addr[6];
	struct EntryMacAddr *next;
};
struct EntrySSID
{
	struct SQDB_String ssid;
	struct EntrySSID *next;
};

struct NVPair {
	char *name;
	char *value;
	struct NVPair *next;
};


struct SQDB_Event {
    /** The type of event, such as "associate", "deauth", etc. */
    unsigned type;

    /** A unique numeric ID for each new event, starting at 1 and increasing
     * as new events are created */
    unsigned event_id;


    time_t time_first;

    /** The timestamp, mod 3600, serves as the index into event table.
     * All events older than 3600 seconds are timed out */
    time_t time_last;

    struct SQDB_AccessPoint *ap;   
    struct SQDB_SubStation *sta;

    struct EventPackets {
        char *buffer;
        unsigned captured_length;
        unsigned original_length;
        unsigned linktype;
        time_t secs;
        unsigned usecs;
        unsigned dup_count;
    } packets[16];

    struct SQDB_Event *next;
};
/**
 * A station attached to an access-point.
 */
struct SQDB_SubStation
{
	unsigned char			mac_address[6];
	unsigned				ip_address;
	char *					name;
	struct NVPair *			data;

	unsigned data_sent;
	unsigned data_received;
	unsigned ctrl_sent;
	unsigned ctrl_received;
	signed char dbm;
	time_t dbm_last_update;

    time_t first;
    time_t last;

    struct SQDB_Event *current_event;

	struct SQDB_SubStation *next;
};


struct SQDB_AccessPoint
{
	unsigned char			bssid[6];
	struct EntryMacAddr		mac_address;
	struct SQDB_String		ssid;
    struct SQDB_String      cisco_name;
	unsigned char			channels[16];
	unsigned				channel_count;
	//unsigned				cipher_suites;
	struct SQDB_RateList	rates1;
	struct SQDB_RateList	rates2;
	
	unsigned	encryption_type;
	unsigned	cipher_type;
	unsigned	auth_type;
    unsigned flag_is_ibss:1;

	struct SQDB_SubStation *substations;
	struct SQDB_AccessPoint *next;

	unsigned	beacon_count;

	signed char dbm;
	time_t dbm_last_update;

	unsigned data_sent;
	unsigned data_received;
	unsigned ctrl_sent;
	unsigned ctrl_received;
	unsigned mgmt_sent;
	unsigned mgmt_received;
	struct SquirrelPacket packets[2];
    time_t first;
    time_t last;
};


struct SQDB_Station
{
	unsigned char			mac_address[6];
	struct EntrySSID		ssid;
	struct SQDB_RateList	rates1;
	struct SQDB_RateList	rates2;
	signed char dbm;
	time_t dbm_last_update;
    unsigned probe_count;
    unsigned response_count;
    enum WiFiStandard standard;
    unsigned channel_width;
    unsigned ie_hash;
    time_t first;
    time_t last;

    struct SquirrelPacket *packet;
    //struct SquirrelPacket probe_response;


	struct SQDB_Station *next;
};

struct XMAC {
	unsigned char mac_address[6];
	unsigned type;
	struct SQDB_AccessPoint *base;
	struct SQDB_Station *sta_alone;
	struct SQDB_SubStation *sta;

	struct XMAC *left;
	struct XMAC *right;
};


struct SQDB
{
	struct SQDB_AccessPoint *access_points[1024];
	struct SQDB_Station *stations[1024];
	struct XMAC *macs;
	void *cs;

    /**
     * A list of the current events being tracked
     */
    struct SQDB_Event *events;
    unsigned latest_event_id;


    /** FIXME
     * I don't pass in information like channel, signal strength,
     * and signal quality to underlying functions. Therefore, if
     * we discover a virtual access point (for example, we see a 
     * transmitting station but no replies due to split-horizon),
     * then we don't remember the channel. However, I'm going to
     * pass that information in here via a "global" variable.
     * This is stupid, and I need to fix this eventually.
     */
    struct Kludgy {
        unsigned channel;
        int dbm;
        time_t time_stamp;
    } kludge;
};

struct TMP_STATIONS {
    time_t last_update;
    struct {
        struct SQDB_Station *unassociated;
        struct SQDB_SubStation *associated;
        struct SQDB_AccessPoint *accesspoint;
    } sta;
    unsigned type;
};


struct TMP_STATIONS *sqdb_enum_probers(struct SQDB *sqdb, size_t *count);

/**
 * Lookup the MAC address and find what types of records we may have for it.
 * There may be multiple records, because the station may have associated
 * and unassociated with multiple access-points.
 */
struct TMP_STATIONS *sqdb_find_station(struct SQDB *sqdb, const unsigned char *mac, unsigned *count);

unsigned sqdb_bssid_station_count(struct SQDB *sqdb, const unsigned char *bssid);
unsigned accesspoint_maxrate(struct SQDB_AccessPoint *entry);
const char *format_enum(unsigned crypto);
struct SQDB_AccessPoint * sqdb_find_bssid(struct SQDB *sqdb, const unsigned char *bssid);
extern void parse_mac_address(unsigned char *dst, size_t sizeof_dst, const char *src);

struct mg_request_info;
struct mg_connection;
void display_topmenu(struct mg_connection *c, const struct mg_request_info *ri, void *user_data, unsigned depth);


#ifdef __cplusplus
}
#endif
#endif
