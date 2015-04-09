#include "sqdb.h"
#include "mongoose.h"
#include "pixie.h"
#include "sqdb2.h"
#include "netframe.h"
#include "sprintf_s.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>


static void
sqdb_ap_add_mac_address(struct SQDB_AccessPoint *ap, const unsigned char *mac_address)
{
    struct EntryMacAddr *e;
    static const unsigned char nulladdr[6] = "\0\0\0\0\0\0";

    /* Ignore null addresses (those containing all zeroes) */
    if (memcmp(mac_address, nulladdr, 6) == 0)
        return;
    
    /* If it already exists, then don't add a new copy of it 
     * in the list */
    for (e = &ap->mac_address; e; e = e->next) {
        if (memcmp(e->addr, mac_address, 6) == 0)
            return;
    }

    /* Boundary case: do this for the first mac address */
    if (memcmp(ap->mac_address.addr, nulladdr, 6) == 0) {
        memcpy(ap->mac_address.addr, mac_address, 6);
        return;
    }

    /* Create a new record */
    e = (struct EntryMacAddr*)malloc(sizeof(*e));
    memset(e, 0, sizeof(*e));
    memcpy(e->addr, mac_address, 6);
    e->next = ap->mac_address.next;
    ap->mac_address.next = e;
}


static struct XMAC *
xmac_create(struct XMAC **root, const unsigned char *mac_address)
{
	struct XMAC *entry;

	while (*root) {
		int c = memcmp((*root)->mac_address, mac_address, 6);
		if (c == 0)
			return *root;
		else if (c < 0)
			root = &(*root)->left;
		else
			root = &(*root)->right;
	}

	entry = (struct XMAC*)malloc(sizeof(*entry));
	memset(entry, 0, sizeof(*entry));
	memcpy(entry->mac_address, mac_address, 6);
	*root = entry;
	return *root;
}


const char *format_enum(unsigned crypto)
{
	switch (crypto) {
	case ENC_TYPE_WEP:		return "WEP";
	case ENC_TYPE_WEP40:	return "WEP40";
	case ENC_TYPE_WEP128:	return "WEP128";
	case ENC_TYPE_WPA:		return "WPA";
	case ENC_TYPE_WPA2:		return "WPA2";
	case ENC_TYPE_WPAu:		return "WPA?";
	case CIPHER_TYPE_WEP:	return "WEP";
	case CIPHER_TYPE_TKIP:	return "TKIP";
	case CIPHER_TYPE_AES:	return "CCMP";
	case AUTH_TYPE_OPEN:	return "OPN";
	case AUTH_TYPE_SKA:		return "SKA";
	case AUTH_TYPE_EAP:		return "EAP";
	case AUTH_TYPE_PSK:		return "PSK";
	case AUTH_TYPE_MGMT:	return "MGMT";
	default:
		return "";
	}
}


unsigned
accesspoint_maxrate(struct SQDB_AccessPoint *entry)
{
	unsigned maxrate=0;
	unsigned i;

	for (i=0; i<entry->rates1.count; i++) {
		unsigned rate=0;

		rate = (entry->rates1.rates[i]&0x7F) * 5;
		if (maxrate < rate)
			maxrate = rate;
	}
	for (i=0; i<entry->rates2.count; i++) {
		unsigned rate=0;

		rate = (entry->rates2.rates[i]&0x7F) * 5;
		if (maxrate < rate)
			maxrate = rate;
	}
	return maxrate;
}

/**
 * Has the BSSID of a packet in order to find the corresponding
 * entry in our table. Each BSSID define a separate network.
 */
unsigned bssid_hash(const unsigned char *px)
{
	unsigned result = 0;

    if (px == 0)
        return 0;
	result ^= (px[0]<<8) | px[1];
	result ^= (px[2]<<8) | px[3];
	result ^= (px[4]<<8) | px[5];

	result &= 0x3FF;

	return result;
}

struct SQDB_AccessPoint *
sqdb_find_bssid(struct SQDB *sqdb, const unsigned char *bssid)
{
	struct SQDB_AccessPoint **r_entry;
	unsigned index;

	index = bssid_hash(bssid);

	r_entry = &sqdb->access_points[index];
	while ((*r_entry) && memcmp((*r_entry)->bssid, bssid, 6) != 0)
		r_entry = &((*r_entry)->next);
	return *r_entry;
}

unsigned
sqdb_bssid_station_count(struct SQDB *sqdb, const unsigned char *bssid)
{
	struct SQDB_AccessPoint *entry;

	entry = sqdb_find_bssid(sqdb, bssid);
	if (entry == NULL)
		return 0;
	else {
		struct SQDB_SubStation *sta;
		unsigned result = 0;

		for (sta=entry->substations; sta; sta=sta->next) {
			result++;
		}
		return result;
	}
}




struct SQDB *sqdb_create()
{
	struct SQDB *result;

	result = (struct SQDB *)malloc(sizeof(*result));
	memset(result, 0, sizeof(*result));

	result->cs = pixie_initialize_critical_section();

	return result;
}

void sqdb_destroy(struct SQDB *sqdb)
{
	free(sqdb);
}


/**
 * Compare two internal strings to see if they are equal,
 * including case sensitivity.
 */
static bool
sqdb_string_is_equal(struct SQDB_String *lhs, struct SQDB_String *rhs)
{
	if (lhs->length != rhs->length)
		return false;
	if (memcmp(lhs->value, rhs->value, rhs->length) == 0)
		return true;
	else
		return false;
}


/**
 * Copy from one internal string to another
 */
static void
sqdb_string_copy(struct SQDB_String *dst, const struct SQDB_String *src)
{
	unsigned length_to_copy = src->length;
	if (length_to_copy > sizeof(dst->value))
		length_to_copy = sizeof(dst->value);
	memcpy(dst->value, src->value, length_to_copy);
	dst->length = length_to_copy;
}

/**
 * Copy a 'rates' field from one point to another.
 */
static void
sqdb_ratesfield_copy(struct SQDB_RateList *dst, const struct SQDB_RateList *src)
{
	unsigned count_to_copy = src->count;
	if (count_to_copy > sizeof(dst->rates))
		count_to_copy = sizeof(dst->rates);
	memcpy(dst->rates, src->rates, count_to_copy);
	dst->count = count_to_copy;
}

/**
 * See if two 'rates' fields are equal.
 */
static bool
sqdb_ratesfield_equal(struct SQDB_RateList *lhs, const struct SQDB_RateList *rhs)
{
	if (lhs->count != rhs->count)
		return false;
	if (memcmp(lhs->rates, rhs->rates, lhs->count) == 0)
		return true;
	else
		return false;
}

/**
 * The rate values in the first that are missing in the secon
 */
struct SQDB_RateList
sqdb_ratesfield_missing(struct SQDB_RateList *lhs, const struct SQDB_RateList *rhs)
{
	struct SQDB_RateList result;
	unsigned i;

	memset(&result, 0, sizeof(result));

	for (i=0; i<lhs->count; i++) {
		unsigned rate;
		unsigned j;
		bool was_found = false;

		rate = lhs->rates[i];

		for (j=0; j<rhs->count; j++) {
			if (rhs->rates[j] == rate)
				was_found = true;
		}

		if (!was_found) {
			result.rates[result.count++] = rate;
		}
	}

	return result;
}


/**
 * See if the current BSSID contains the specified access-point. The first
 * time we see a second access-point within a single network, this will return
 * false.
 */
static bool
sqdb_contains_mac_address(struct SQDB_AccessPoint *entry, const unsigned char *mac)
{
	struct EntryMacAddr *p;

	if (memcmp(entry->mac_address.addr, mac, 6) == 0)
		return true;
	
	for (p = entry->mac_address.next; p; p = p->next) {
		if (memcmp(p->addr, mac, 6) == 0)
			return true;
	}
	
	return false;
}



/**
 * Lookup access point by BSSID
 */
static struct SQDB_AccessPoint *
sqdb_create_bssid(struct SQDB *sqdb, const unsigned char *bssid)
{
	struct SQDB_AccessPoint **r_entry;
	unsigned index = bssid_hash(bssid);

	pixie_enter_critical_section(sqdb->cs);

	r_entry = &sqdb->access_points[index];
	while ((*r_entry) && memcmp((*r_entry)->bssid, bssid, 6) != 0)
		r_entry = &((*r_entry)->next);
	if (*r_entry == NULL) {
		struct XMAC *xmac;

		*r_entry = (struct SQDB_AccessPoint*)malloc(sizeof(**r_entry));
		memset(*r_entry, 0, sizeof(**r_entry));
		memcpy((*r_entry)->bssid, bssid, 6);
        if (sqdb->kludge.channel) {
            (*r_entry)->channels[0] = sqdb->kludge.channel;
            (*r_entry)->channel_count = 1;
        }

		/* Create a link to this from the master MAC address registery */
		xmac = xmac_create(&sqdb->macs, bssid);
		xmac->type = STATION_TYPE_BASE;
		xmac->base = *r_entry;
        (*r_entry)->first = sqdb->kludge.time_stamp;
	}

    (*r_entry)->last = sqdb->kludge.time_stamp;
	pixie_leave_critical_section(sqdb->cs);
	return *r_entry;
}

void
regmac_base(struct SQDB *sqdb, const unsigned char *bssid, const unsigned char *mac_address)
{
	struct SQDB_AccessPoint *base;
	struct XMAC *xmac;

	pixie_enter_critical_section(sqdb->cs);

	base = sqdb_create_bssid(sqdb, bssid);

    if (!sqdb_contains_mac_address(base, mac_address)) {
        sqdb_ap_add_mac_address(base, mac_address);

		/* Create a link to this from the master MAC address registery */
		xmac = xmac_create(&sqdb->macs, bssid);
		xmac->type = STATION_TYPE_BASE;
		xmac->base = base;
	}
	pixie_leave_critical_section(sqdb->cs);
}

void
regmac_transmit_power(struct SQDB *sqdb, const unsigned char *src, int dbm, time_t timestamp)
{
	struct XMAC *xmac;
	if (dbm == 0)
		return;

	pixie_enter_critical_section(sqdb->cs);

	xmac = xmac_create(&sqdb->macs, src);

	switch (xmac->type) {
	case STATION_TYPE_BASE:
		{
			struct SQDB_AccessPoint *entry = xmac->base;
			entry->dbm = dbm;
			entry->dbm_last_update = timestamp;
		}
		break;
	case STATION_TYPE_STA:
		{
			struct SQDB_SubStation *entry = xmac->sta;
			entry->dbm = dbm;
			entry->dbm_last_update = timestamp;
		}
		break;
	case STATION_TYPE_STA_ALONE:
		{
			struct SQDB_Station *entry = xmac->sta_alone;
			entry->dbm = dbm;
			entry->dbm_last_update = timestamp;
		}
		break;
	}

	pixie_leave_critical_section(sqdb->cs);
}


unsigned regmac_base_resolve_direction(struct SQDB *sqdb, const unsigned char *bssid, const unsigned char *src, const unsigned char *dst)
{
	struct SQDB_AccessPoint *entry;
	struct EntryMacAddr *mac;
	unsigned dir = DIR_UNKNOWN;

	pixie_enter_critical_section(sqdb->cs);

	if (memcmp(bssid, src, 6) == 0) {
		regmac_base(sqdb, bssid, bssid);
		regmac_station(sqdb, bssid, dst, -1);
		dir = DIR_BASE_TO_STA;
	} else if (memcmp(bssid, dst, 6) == 0) {
		regmac_base(sqdb, bssid, bssid);
		regmac_station(sqdb, bssid, src, -1);
		dir = DIR_STA_TO_BASE;
	} else {
		/* Neither matches, so let's see if this is a different
		 * access-point in the BSS */
		entry = sqdb_create_bssid(sqdb, bssid);
		for (mac = &entry->mac_address; mac; mac = mac->next) {
			if (memcmp(mac->addr, src, 6) == 0) {
				regmac_station(sqdb, bssid, dst, -1);
				dir = DIR_BASE_TO_STA;
				break;
			} else if (memcmp(mac->addr, dst, 6) == 0) {
				regmac_station(sqdb, bssid, src, -1);
				dir = DIR_STA_TO_BASE;
			}
		}
	}

	pixie_leave_critical_section(sqdb->cs);
	return dir;
}



void
regmac_base_ssid(struct SQDB *sqdb, const unsigned char *bssid, struct SQDB_String *ssid)
{
	struct SQDB_AccessPoint *entry;

    /* Ignore empty SSIDs */
    if (ssid->length == 0)
        return;
    if (ssid->length == 1 && ssid->value[0] == '\0')
        return;

	pixie_enter_critical_section(sqdb->cs);

	entry = sqdb_create_bssid(sqdb, bssid);

	if (!sqdb_string_is_equal(&entry->ssid, ssid)) {
		if (entry->ssid.length > 0) {
			SQUIRREL_EVENT("[%02X:%02X:%02X:%02X:%02X:%02X]  SSID=\"%.*s\" (was \"%.*s\")\n", 
				PRINTMAC(bssid),
				PRINTSTR(ssid),
				PRINTSTR(&entry->ssid));
		}
		sqdb_string_copy(&entry->ssid, ssid);
		/*FIXME: we should support seeing multiple SSIDs on a BSSID */
	}
	pixie_leave_critical_section(sqdb->cs);
}

void regmac_base_crypto(struct SQDB *sqdb, const unsigned char *bssid, unsigned crypto)
{
	struct SQDB_AccessPoint *entry;

	pixie_enter_critical_section(sqdb->cs);

	entry = sqdb_create_bssid(sqdb, bssid);

	switch (crypto) {
	case ENC_TYPE_WEP	:
	case ENC_TYPE_WEP40	:
	case ENC_TYPE_WEP128	:
	case ENC_TYPE_WPA	:
	case ENC_TYPE_WPA2	:
		if (entry->encryption_type < crypto)
			entry->encryption_type = crypto;
		break;
	case CIPHER_TYPE_WEP	:
	case CIPHER_TYPE_TKIP:
	case CIPHER_TYPE_AES:
		if (entry->cipher_type < crypto)
			entry->cipher_type = crypto;
		break;
	case AUTH_TYPE_OPEN	:
	case AUTH_TYPE_SKA	:
	case AUTH_TYPE_EAP	:
	case AUTH_TYPE_PSK	:
	case AUTH_TYPE_MGMT:
		entry->auth_type = crypto;
		break;
	default:
		;
	}
	pixie_leave_critical_section(sqdb->cs);
}

void
regmac_base_rates(struct SQDB *sqdb, const unsigned char *bssid, struct SQDB_RateList *rates1, struct SQDB_RateList *rates2)
{
	struct SQDB_AccessPoint *entry;

	pixie_enter_critical_section(sqdb->cs);

	entry = sqdb_create_bssid(sqdb, bssid);

	if (rates1) {
		if (!sqdb_ratesfield_equal(&entry->rates1, rates1)) {
			sqdb_ratesfield_copy(&entry->rates1, rates1);
		}
	}
	if (rates2) {
		if (!sqdb_ratesfield_equal(&entry->rates2, rates2)) {
			sqdb_ratesfield_copy(&entry->rates2, rates2);
		}
	}
	pixie_leave_critical_section(sqdb->cs);

}

/**
 *  Format an SSID string, changing bad characters to hexadecimal
 */
static unsigned
format_ssid(char *dst, unsigned sizeof_dst, const char *v_src, unsigned sizeof_src)
{
	const unsigned char *src = (const unsigned char *)v_src;
	unsigned s = 0;
	unsigned d = 0;

	while (s < sizeof_src && d + 1 < sizeof_dst) {
		unsigned char c = src[s++];
		if (isprint(c)) {
			dst[d++] = c;
		} else {
			if (d+1 < sizeof_dst)
				dst[d++] = '\\';
			if (d+1 < sizeof_dst)
				dst[d++] = 'x';
			if (d+1 < sizeof_dst)
				dst[d++] = "01234567890ABCDEF"[(c>>4)&0x0F];
			if (d+1 < sizeof_dst)
				dst[d++] = "01234567890ABCDEF"[(c>>0)&0x0F];
		}
	}

	dst[d] = '\0';
	return d;
}

/**
 * Lookup a station attached to an access point
 */
static struct SQDB_SubStation *
sqdb_lookup_substation(
	 struct SQDB *sqdb, 
	 const unsigned char *mac_address,
	 const unsigned char *bssid)
{
	struct SQDB_AccessPoint *access_point;
	struct SQDB_SubStation *substation;

	/* Find the access point first */
	access_point = sqdb_create_bssid(sqdb, bssid);

	/* Lookup the mac address within this access point */
	for (substation = access_point->substations; substation; substation = substation->next) {
		if (memcmp(mac_address, substation->mac_address, 6) == 0)
			break;
	}

	/* If not found, create a new one */
	if (substation == NULL) {
		struct XMAC *xmac;
		char myssid[256];
		unsigned myssid_length;

		substation = (struct SQDB_SubStation*)malloc(sizeof(*substation));
		memset(substation, 0, sizeof(*substation));
		memcpy(substation->mac_address, mac_address, 6);
		substation->next = access_point->substations;
		access_point->substations = substation;
		
		/* Create a link to this from the master MAC address registery */
		xmac = xmac_create(&sqdb->macs, mac_address);
		xmac->type = STATION_TYPE_STA;
		xmac->sta = substation;


		myssid_length = format_ssid(myssid, sizeof(myssid), (char*)access_point->ssid.value,  access_point->ssid.length);

		SQUIRREL_EVENT("[%02X:%02X:%02X:%02X:%02X:%02X] "
			"SSID=\"%.*s\" "
			"%.*s"
			"station=%02X:%02X:%02X:%02X:%02X:%02X"
			"\n",
			PRINTMAC(bssid),
			myssid_length, myssid, 
			(access_point->ssid.length>16)?0:(16-access_point->ssid.length), "                 ",
			PRINTMAC(mac_address)
			);
	}
	
	return substation;
}

/**
 * Create a new event record (for things like authentiation, attacks,
 * and so on).
 */
static void
event_new(struct SQDB *sqdb, struct SQDB_SubStation *sta, struct SQDB_AccessPoint *ap, time_t timestamp, unsigned type)
{
    struct SQDB_Event *event;

    /* Allocate a new event structure */
    event = (struct SQDB_Event*)malloc(sizeof(*event));
    memset(event, 0, sizeof(*event));
    event->type = type;
    event->time_first = timestamp;
    event->event_id = ++sqdb->latest_event_id;

    /* Link it into the system */
    event->ap = ap;
    if (sta) {
        event->sta = sta;
        sta->current_event = event;
    }

    event->next = sqdb->events;
    sqdb->events = event;
}



/**
 * Events can span multiple packets, and so can remain "open" for a while.
 * This function is called when we know for sure that the event is done, either
 * because it has been timed-out, or because we've received packets confirming
 * that the event is done (for example, if we see data packets, we know that
 * the association phase is over).
 */
static void
event_close(struct SQDB *sqdb, struct SQDB_Event *event)
{
    if (event->sta && event->sta->current_event == event)
        event->sta->current_event = NULL;
}

static void
event_update_packet(struct SQDB_Event *event, unsigned frame_type, struct NetFrame *frame)
{
    unsigned char *buf;
    unsigned buf_length;

    /* Check for duplicates */
    if (event->packets[frame_type].buffer != NULL) {
        event->packets[frame_type].dup_count++;
        return;
    }

    /* Copy over the data */
    buf_length = frame->captured_length;
    buf = (unsigned char*)malloc(buf_length+1);
    memcpy(buf, frame->px, buf_length);
    buf[buf_length] = '\0';
    event->packets[frame_type].buffer = (char*)buf;
    event->packets[frame_type].captured_length = frame->captured_length;
    event->packets[frame_type].original_length = frame->original_length;
    event->packets[frame_type].secs = frame->time_secs;
    event->packets[frame_type].usecs = frame->time_usecs;
    event->packets[frame_type].linktype = frame->layer2_protocol;
    event->packets[frame_type].dup_count = 1;
}

void regmac_event(struct SQDB *sqdb, 
                         unsigned event_type,
                         const unsigned char *bssid, const unsigned char *mac_address, 
                         unsigned frame_type,
                         struct NetFrame *frame)
{
	struct SQDB_SubStation *sta;
	struct SQDB_AccessPoint *ap;
    struct SQDB_Event *event;
    time_t timestamp = sqdb->kludge.time_stamp;

	pixie_enter_critical_section(sqdb->cs);

	ap = sqdb_create_bssid(sqdb, bssid);
	sta = sqdb_lookup_substation(sqdb, mac_address, bssid);

    /* If the existing event doesn't match this, then we need to close it */
    if (sta->current_event && sta->current_event->type != event_type) {
        event_close(sqdb, sta->current_event);
    }

    /* If there is no current event, create one */
    if (sta->current_event == NULL)
        event_new(sqdb, sta, ap, sqdb->kludge.time_stamp, event_type);
    event = sta->current_event;

    /* update latest time */
    if (event->time_last < timestamp)
        event->time_last = timestamp;

    /* Do different logic, depending on the event type */
    event_update_packet(event, frame_type, frame);

	pixie_leave_critical_section(sqdb->cs);
}

void regmac_station_ctrl(struct SQDB *sqdb, const unsigned char *bssid, const unsigned char *mac_address, unsigned dir)
{
	struct SQDB_SubStation *sta;
	struct SQDB_AccessPoint *base;

	pixie_enter_critical_section(sqdb->cs);

	base = sqdb_create_bssid(sqdb, bssid);
	sta = sqdb_lookup_substation(sqdb, mac_address, bssid);
	switch (dir) {
	case DIR_RECEIVED:
	case DIR_BASE_TO_STA:
		base->ctrl_sent++;
		sta->ctrl_received++;
		break;
	case DIR_SENT:
	case DIR_STA_TO_BASE:
		base->ctrl_received++;
		sta->ctrl_sent++;
		break;
	}
	pixie_leave_critical_section(sqdb->cs);
}
void regmac_station_data(struct SQDB *sqdb, const unsigned char *bssid, const unsigned char *mac_address, unsigned dir)
{
	struct SQDB_SubStation *sta;
	struct SQDB_AccessPoint *base;
	struct SQDB_SubStation multicast;


	pixie_enter_critical_section(sqdb->cs);

	/* First, register the fact we have an access-point*/
	base = sqdb_create_bssid(sqdb, bssid);

	/* Second, regisger the fact we have an access-point attached
	 * to that access-point */
    if (mac_address[0]&1)
        sta = &multicast;
    else
    	sta = sqdb_lookup_substation(sqdb, mac_address, bssid);

	/* Finally, update the packet counts */
	switch (dir) {
	case DIR_RECEIVED:
	case DIR_BASE_TO_STA:
		base->data_sent++;
		sta->data_received++;
		break;
	case DIR_SENT:
	case DIR_STA_TO_BASE:
		base->data_received++;
		sta->data_sent++;
		break;
	}
	pixie_leave_critical_section(sqdb->cs);
}
void regmac_station_wired(struct SQDB *sqdb, const unsigned char *bssid, const unsigned char *mac_address, unsigned dir)
{
	struct SQDB_SubStation *sta;
	struct SQDB_AccessPoint *base;
	struct SQDB_SubStation multicast;


	pixie_enter_critical_section(sqdb->cs);

	/* First, register the fact we have an access-point*/
	base = sqdb_create_bssid(sqdb, bssid);

	/* Second, regisger the fact we have an access-point attached
	 * to that access-point */
    if (mac_address[0]&1)
        sta = &multicast;
    else
    	sta = sqdb_lookup_substation(sqdb, mac_address, bssid);

	/* Finally, update the packet counts */
	switch (dir) {
	case DIR_RECEIVED:
	case DIR_BASE_TO_STA:
		//base->data_sent++;
		sta->data_received++;
		break;
	case DIR_SENT:
	case DIR_STA_TO_BASE:
		//base->data_received++;
		sta->data_sent++;
		break;
	}
	pixie_leave_critical_section(sqdb->cs);
}


/*void 
sqdb_set_bssid_auth_type(struct SQDB *sqdb, const unsigned char *bssid, unsigned auth_type)
{
	struct SQDB_AccessPoint *x;
	const char *auth_string[] = {"UNKNOWN", "OPEN", "SKA", "EAP", };

	pixie_enter_critical_section(sqdb->cs);
	pixie_leave_critical_section(sqdb->cs);

	x = sqdb_create_bssid(sqdb, bssid);

	if (x->auth_type != auth_type) {
		SQUIRREL_EVENT(" %02X:%02X:%02X:%02X:%02X:%02X  "
			"AUTH=%s"
			"\n",
			PRINTMAC(bssid),
			auth_string[auth_type]
			);
		x->auth_type = auth_type;
	}
}*/

unsigned
sqdb_set_bssid_packet(struct SQDB *sqdb, const unsigned char *bssid, unsigned type, const struct SquirrelPacket *pkt)
{
	struct SQDB_AccessPoint *ap;
	unsigned i;

	pixie_enter_critical_section(sqdb->cs);

	ap = sqdb_create_bssid(sqdb, bssid);

    if (pkt->px[0] == 0x80)
        i = 0; /* Beacon */
    else if (pkt->px[0] == 0x50)
        i = 1; /* Probe Response */
    else
        return 0;

	if (ap) {
		unsigned char *px;

		if (ap->packets[i].px == NULL) {
            /* If no existing packets, then allocate a buffer */
			px = (unsigned char*)malloc(pkt->length);
		} else if (ap->packets[i].length < pkt->length) {
            /* If there was already a buffer, but it's too short,
             * then allocate a replacement buffer that's long enough */
			free((unsigned char*)ap->packets[i].px);
			px = (unsigned char*)malloc(pkt->length);
        } else {
            /* The existing buffer is big enough, so just reusee it */
			px = (unsigned char*)ap->packets[i].px;
        }
		memcpy(&ap->packets[i], pkt, sizeof(*pkt));
		ap->packets[i].px = px;
		memcpy(px, pkt->px, pkt->length);
        
	}

	pixie_leave_critical_section(sqdb->cs);
	return 0;
}

unsigned
sqdb_get_bssid_packet(struct SQDB *sqdb, const unsigned char *bssid, unsigned type, struct SquirrelPacket *pkt)
{
	struct SQDB_AccessPoint *ap;
	unsigned i;

	pkt->px = (const unsigned char*)"";
	pkt->length = 1;
	pkt->secs = time(0);
	pkt->usecs = 0;
    pkt->linktype = 0;

	pixie_enter_critical_section(sqdb->cs);

    /* Grab the AP record */
	ap = sqdb_find_bssid(sqdb, bssid);
    if (ap == NULL)
        goto _end;

    /* Figure out which type of packet we need */
    if (type == SQPKT_BEACON)
        i = 0;
    else if (type == SQPKT_PROBERESPONSE)
        i = 1;
    else
        goto _end;

    /* Copy the packet over */
	memcpy(pkt, &ap->packets[i], sizeof(*pkt));

_end:
	pixie_leave_critical_section(sqdb->cs);
	return 1;
}


const unsigned char *
sqdb_lookup_bssid_by_access_point(struct SQDB *sqdb, const unsigned char *mac_address)
{
	unsigned i;
	const unsigned char *result = NULL;

	pixie_enter_critical_section(sqdb->cs);

	for (i=0; i<sizeof(sqdb->access_points)/sizeof(sqdb->access_points[0]); i++) {
		struct SQDB_AccessPoint *x;


		for (x = sqdb->access_points[i]; x; x = x->next) {
			struct EntryMacAddr *y;
			
			if (memcmp(mac_address, x->bssid, 6) == 0) {
				result = x->bssid;
				goto _return;
			}

			for (y = &x->mac_address; y; y = y->next) {
				if (memcmp(mac_address, y->addr, 6) == 0) {
					result = x->bssid;
					goto _return;
				}
			}
		}
	}
_return:
	pixie_leave_critical_section(sqdb->cs);
	return result;
}




/**
 * Lookup a MAC address in the system and see whether it refers
 * to an access-point or a normal station
 */
unsigned sqdb_station_type(struct SQDB *sqdb, const unsigned char *mac_address)
{
	unsigned result = STATION_TYPE_UNKNOWN;
	pixie_enter_critical_section(sqdb->cs);
	if ((mac_address[0]&1) == 1)
		result = STATION_TYPE_MULTICAST;
	else {
		struct XMAC *xmac;
		xmac = xmac_create(&sqdb->macs, mac_address);
		result = xmac->type;
	}
	pixie_leave_critical_section(sqdb->cs);
	return result;
}



unsigned MATCHESZ(const char *lhs, const char *rhs)
{
	return strcasecmp_s(lhs, rhs) == 0;
}

void
sqdb_add_info(struct SQDB *sqdb, const unsigned char *mac_address, const unsigned char *bssid,
			  const char *name, const char *value)
{
	struct SQDB_SubStation *sta;
	struct NVPair **r_data;
	struct NVPair *d;
	unsigned name_length = strlen(name);
	unsigned value_length = strlen(value);

    if (bssid == 0)
        bssid = (const unsigned char*)"\0\0\0\0\0\0";
    
    /* Filter out some common names that I see */
    if (MATCHESZ(name, "domain")) {
        if (MATCHESZ(value, "savvis.net"))
            return;
    }


	pixie_enter_critical_section(sqdb->cs);


	sta = sqdb_lookup_substation(sqdb, mac_address, bssid);
	if (sta == NULL)
		goto _return;

	for (r_data =  &sta->data; *r_data; r_data = &(*r_data)->next) {
		d = *r_data;

		if (MATCHESZ(d->name, name) && MATCHESZ(d->value, value))
			goto _return;
	}

	d = (struct NVPair*)malloc(sizeof(*d));
	d->name = (char*)malloc(name_length+1);
	memcpy(d->name, name, name_length+1);
	d->value = (char*)malloc(value_length+1);
	memcpy(d->value, value, value_length+1);
	d->next = 0;

	*r_data = d;

_return:
	pixie_leave_critical_section(sqdb->cs);
}


static unsigned
sqdb_base_channel(struct SQDB_AccessPoint *entry, unsigned channel)
{
	unsigned j;

	for (j=0; j<entry->channel_count; j++) {
		if (entry->channels[j] == channel)
			return 0; /* existing channel found */
	}
	entry->channels[entry->channel_count++] = channel;
	return 1; /* new channel created */
}

/**
 * Add access-point information for a beacon or probe-response packet
 * Returns '1' if a new entry was created, or '0' otherwise
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
)
{
	struct SQDB_AccessPoint *entry;
	/*unsigned is_new = false;*/

	pixie_enter_critical_section(sqdb->cs);

	/*  
	 * Look up the entry in the hash table 
	 */
	entry = sqdb_create_bssid(sqdb, bssid);
    entry->flag_is_ibss = is_adhoc;
    if (memcmp(entry->mac_address.addr, "\0\0\0\0\0\0", 6) == 0)
        memcpy(entry->mac_address.addr, src_mac, 6);
	regmac_base(sqdb, bssid, src_mac);
	regmac_base_ssid(sqdb, bssid, &ssid);
	sqdb_base_channel(entry, channel);
	sqdb_string_copy(&entry->cisco_name, &cisco_name);

	entry->beacon_count++;


	/*
	 * See if the Rates fields are the same
	 */
	if (!sqdb_ratesfield_equal(&entry->rates1, &rates1)) {
		sqdb_ratesfield_copy(&entry->rates1, &rates1);
	}
	if (!sqdb_ratesfield_equal(&entry->rates2, &rates2)) {
		sqdb_ratesfield_copy(&entry->rates2, &rates2);
	}

	pixie_leave_critical_section(sqdb->cs);
	return 0;
}


unsigned sqdb_add_probe_request(
	struct SQDB *sqdb, 
	const unsigned char *src_mac,
	struct SQDB_String ssid,
	struct SQDB_RateList rates1,
	struct SQDB_RateList rates2
)
{
	struct SQDB_Station *entry;
	unsigned is_new = false;

	pixie_enter_critical_section(sqdb->cs);

	/*  
	 * Look up the entry in the hash table 
	 */
	{
		struct SQDB_Station **r_entry;
		unsigned index = bssid_hash(src_mac);

		r_entry = &sqdb->stations[index];
		while ((*r_entry) && memcmp((*r_entry)->mac_address, src_mac, 6) != 0)
			r_entry = &((*r_entry)->next);
		if (*r_entry == NULL) {
			struct XMAC *xmac;
			char myssid[256];
			unsigned myssid_length;

			*r_entry = (struct SQDB_Station*)malloc(sizeof(**r_entry));
			memset(*r_entry, 0, sizeof(**r_entry));
			memcpy((*r_entry)->mac_address, src_mac, 6);
			sqdb_string_copy(&(*r_entry)->ssid.ssid, &ssid);
			is_new = true;

			/* Create a link to this from the master MAC address registery */
			xmac = xmac_create(&sqdb->macs, src_mac);
			xmac->type = STATION_TYPE_STA_ALONE;
			xmac->sta_alone = *r_entry;

			myssid_length = format_ssid(myssid, sizeof(myssid), (const char*)ssid.value,  ssid.length);

			SQUIRREL_EVENT(" %02X:%02X:%02X:%02X:%02X:%02X  "
				"probe=\"%.*s\" "
				"%.*s"
				"\n",
				PRINTMAC(src_mac),
				myssid_length, myssid, 
				(ssid.length>16)?0:(16-ssid.length), "                 "
				);
		}
		entry = *r_entry;
	}
    
    entry->probe_count++;

	/*
	 * See if the SSID of the network has changed. This should
	 * never really happen.
	 */
	if (!sqdb_string_is_equal(&entry->ssid.ssid, &ssid)) {
		struct EntrySSID **r;
		unsigned found = 0;

		for (r=&entry->ssid.next; *r; r = &((*r)->next)) {
			if (sqdb_string_is_equal(&(*r)->ssid, &ssid)) {
				found = 1;
				break;
			}
		}
		if (!found) {
			char myssid[256];
			unsigned myssid_length;

			myssid_length = format_ssid(myssid, sizeof(myssid), (const char*)ssid.value,  ssid.length);

			*r = (struct EntrySSID*)malloc(sizeof(**r));
			memset(*r, 0, sizeof(**r));
			sqdb_string_copy(&(*r)->ssid, &ssid);
			SQUIRREL_EVENT(" %02X:%02X:%02X:%02X:%02X:%02X  probe=\"%.*s\"\n", 
				PRINTMAC(src_mac), myssid_length, myssid);
		}
	}

	/*
	 * See if the Rates fields are the same
	 */
	if (!sqdb_ratesfield_equal(&entry->rates1, &rates1)) {
		sqdb_ratesfield_copy(&entry->rates1, &rates1);
	}
	if (!sqdb_ratesfield_equal(&entry->rates2, &rates2)) {
		sqdb_ratesfield_copy(&entry->rates2, &rates2);
	}


	pixie_leave_critical_section(sqdb->cs);
	return 0;
}

struct TMP_STATIONS *
alloc_tmp_stations(struct TMP_STATIONS *tmp, unsigned *count, unsigned *maxcount)
{
    if (*count + 1 >= *maxcount) {
        unsigned newmax = *maxcount*2 + 1;
        struct TMP_STATIONS *newtmp;

        newtmp = (struct TMP_STATIONS*)malloc(sizeof(*newtmp) * newmax);
        memset(newtmp, 0, sizeof(*newtmp) * newmax);

        if (*count) {
            memcpy(newtmp, tmp, sizeof(*newtmp) * (*count));
        }
        if (tmp)
            free(tmp);
        *maxcount = newmax;
        return newtmp;
    }
    return tmp;
}

struct TMP_STATIONS *
sqdb_find_station(struct SQDB *sqdb, const unsigned char *mac, unsigned *count)
{
    struct TMP_STATIONS *result = 0;
    unsigned i;
    unsigned maxcount = 0;
    *count = 0;

   	pixie_enter_critical_section(sqdb->cs);

    memset(&result, 0, sizeof(result));

    /*
     * Look for a "prober" record
     */
    {
    	struct SQDB_Station *entry;
		unsigned index = bssid_hash(mac);

		entry = sqdb->stations[index];
		while (entry && memcmp(entry->mac_address, mac, 6) != 0)
			entry = entry->next;
        if (entry != NULL) {
            result = alloc_tmp_stations(result, count, &maxcount);
            result[*count].type = 1;
            result[*count].sta.unassociated = entry;
            result[*count].last_update = entry->dbm_last_update;
            (*count)++;
        }
    }

    /* Look for Associated station */
    for (i=0; i<sizeof(sqdb->access_points)/sizeof(sqdb->access_points[0]); i++) {
        struct SQDB_AccessPoint *ap;
        
        ap = sqdb->access_points[i];
        while (ap) {
            struct SQDB_SubStation *sta;

            sta = ap->substations;
            while (sta) {
                if (memcmp(sta->mac_address, mac, 6) == 0) {
                    result = alloc_tmp_stations(result, count, &maxcount);
                    result[*count].type = 2;
                    result[*count].sta.associated = sta;
                    result[*count].last_update = sta->dbm_last_update;
                    result[*count].sta.accesspoint = ap;
                    (*count)++;
                    break;
                }
                sta = sta->next;
            }
            ap = ap->next;
        }
    }

	pixie_leave_critical_section(sqdb->cs);

    return result;
}

/**
 * Create a list pointing to discovered stations
 */
struct TMP_STATIONS *
sqdb_enum_probers(struct SQDB *sqdb, size_t *count)
{  
    unsigned i;
    unsigned total_stations = 0;
    unsigned n;
    struct TMP_STATIONS *result;
    bool still_swapping;

	pixie_enter_critical_section(sqdb->cs);

    /* First, count all the station records */
    for (i=0; i<sizeof(sqdb->stations)/sizeof(sqdb->stations[0]); i++) {
        struct SQDB_Station *entry = sqdb->stations[i];
        while (entry) {
            total_stations++;
            entry = entry->next;
        }
    }

    /* Allocate a list of the stations */
    result = (struct TMP_STATIONS*)malloc(sizeof(result[0]) * (total_stations + 1));
    n = 0;
    for (i=0; i<sizeof(sqdb->stations)/sizeof(sqdb->stations[0]); i++) {
        struct SQDB_Station *entry = sqdb->stations[i];
        while (entry) {
            result[n].sta.unassociated = entry;
            result[n].last_update = entry->dbm_last_update;
            result[n].type = 1;
            n++;
            entry = entry->next;
        }
    }
    result[n].type = 0;
    *count = total_stations;

    /* Sort the list so that most recent are on top */
    still_swapping = true;
    if (total_stations)
    while (still_swapping) {
        still_swapping = false;
        for (i=0; i<total_stations-1; i++) {
            if (result[i].last_update < result[i+1].last_update) {
                struct TMP_STATIONS x;
                memcpy(&x, &result[i], sizeof(x));
                memcpy(&result[i], &result[i+1], sizeof(x));
                memcpy(&result[i+1], &x, sizeof(x));
                still_swapping = true;
            }
        }
    }
	pixie_leave_critical_section(sqdb->cs);
	return result;
}


