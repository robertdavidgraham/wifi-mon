#include "../sqdb/sqdb2.h"
#include "pixie.h"
#include "mongoose.h"
#include "ctype.h"
#include <stdlib.h>
#include "manuf.h"
#include "display.h"
#include "../sqdb/sqdb.h"

/**
 * Test this SSID to see if it looks like one that a station
 * would reasonable probe for, or random garbage that represents a bug
 */
bool sanity_check(struct SQDB_String *str)
{
    if (str->length == 0)
        return false;
    if (str->length == 16 || str->length == 30 || str->length == 32) {
        unsigned non_printable = 0;
        unsigned i;
        for (i=0; i<str->length; i++) {
            if (!isprint(str->value[i]))
                non_printable++;
        }
        if (non_printable > 6)
            return false;
    }
    return true;
}

void defang_ssid(char *defanged, size_t defanged_length, const char *ssid, unsigned ssid_length)
{
    unsigned d=0, s=0;

    for (s=0; s<ssid_length && d+1<defanged_length; s++) {
        unsigned char c = (unsigned char)ssid[s];

        if (!isprint(c) || c == ']' || c == '[') {
            if (d+5 >= defanged_length)
                break;
            defanged[d++] = '\\';
            defanged[d++] = 'x';
            defanged[d++] = "0123456789abcdef"[(c>>4)&0xF];
            defanged[d++] = "0123456789abcdef"[(c>>0)&0xF];
        } else if (c == '&') {
            if (d+6 >= defanged_length)
                break;
            defanged[d++] = '&';
            defanged[d++] = 'a';
            defanged[d++] = 'm';
            defanged[d++] = 'p';
            defanged[d++] = ';';
        } else if (c == '\"') {
            if (d+7 >= defanged_length)
                break;
            defanged[d++] = '&';
            defanged[d++] = 'q';
            defanged[d++] = 'u';
            defanged[d++] = 'o';
            defanged[d++] = 't';
            defanged[d++] = ';';
        } else if (c == '<') {
            if (d+5 >= defanged_length)
                break;
            defanged[d++] = '&';
            defanged[d++] = 'l';
            defanged[d++] = 't';
            defanged[d++] = ';';
        } else if (c == '>') {
            if (d+5 >= defanged_length)
                break;
            defanged[d++] = '&';
            defanged[d++] = 'g';
            defanged[d++] = 't';
            defanged[d++] = ';';
        } else
            defanged[d++] = c;
    }

    defanged[d] = '\0';
}

/*===========================================================================
 *===========================================================================*/
const char *
standard_name(enum WiFiStandard standard)
{
    switch (standard) {
        case WIFI_80211a: return "802.11a";
        case WIFI_80211b: return "802.11b";
        case WIFI_80211g: return "802.11g";
        case WIFI_80211n: return "802.11n";
        case WIFI_80211ac: return "802.11ac";
        default: return "unknown";
    }
}

/*===========================================================================
 *===========================================================================*/
void
display_probers_list(struct mg_connection *c, const struct mg_request_info *ri, void *user_data)
{
	struct SQDB *sqdb = (struct SQDB*)user_data;
	unsigned i;
    struct TMP_STATIONS *list;
    size_t list_count = 0;
    char defanged[1024];

	pixie_enter_critical_section(sqdb->cs);

    list = sqdb_enum_probers(sqdb, &list_count);

	mg_headers_ok(c, "text/html; charset=utf-8");
	X(c, "Connection: close\r\n");
	X(c, "\r\n");

	//X(c, "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\" \"http://www.w3.org/TR/html4/strict.dtd\">\r\n");
	X(c,"<html>\n");
	X(c,"<head>\n");
	X(c," <title>%u probers</title>\n", list_count);
	X(c," <link rel=\"stylesheet\" type=\"text/css\" href=\"squirrel.css\" />\n");
	X(c," <link rel=\"Shortcut Icon\" href=\"/favicon.ico\" type=\"image/x-icon\">\n");
	X(c," <script type=\"text/javascript\" src=\"squirrel.js\"></script>\n");
    X(c," <script src=\"sorttable.js\"></script>\n");
	X(c,"</head>\n");
	X(c,"<body onLoad=\"setInterval(refresh_probers,1000)\">\n");

	/*X(c, "<button onclick=\"loadXMLDoc('bssids.xml')\">Get CD info</button>\n");
	X(c, "<button onclick='nukeRow()'>Nuke Row</button>\n");
	X(c, "<button onclick='self.setInterval(refresh,1000)'>Auto</button>\n");*/
	display_topmenu(c, ri, user_data, 0);

	X(c, "<table class=\"sortable\" id=\"probers\">\n");
	X(c,	"<tr>\n <th>MAC</th>\n"
			" <th id=\"menu_manuf\" class=\"menu\">MANUF</th>\n"
            " <th>Hash</th>\n"
            " <th>Type</th>\n"
            " <th>Width</th>\n"
			" <th>PWR</th>\n"
			" <th>Count</th>\n"
			" <th>----- Last Activity -----</th>\n"
			" <th>ESSID</th>\n"
			"</tr>\n");
    for (i=0; i<list_count; i++) {
		struct SQDB_Station *sta = list[i].sta.unassociated;
	    const unsigned char *mac_address = sta->mac_address;	
    
		X(c, "  <tr id=\"%02x%02x%02x%02x%02x%02x\" timestamp=\"%u\">\n",
				mac_address[0],mac_address[1],mac_address[2],
				mac_address[3],mac_address[4],mac_address[5],
                sta->dbm_last_update
				);

		/*
		 * MAC ADDRESSS
		 */
		X(c, "  <td id=\"mac\" class=\"mac\"><a href=\"/station/%02x%02x%02x%02x%02x%02x.html\">[%02x:%02x:%02x:%02x:%02x:%02x]</a></td>\n",
				mac_address[0],mac_address[1],mac_address[2],
				mac_address[3],mac_address[4],mac_address[5],
				mac_address[0],mac_address[1],mac_address[2],
				mac_address[3],mac_address[4],mac_address[5]
				);
        X(c, "  <td id=\"manuf\" class=\"manuf\">%s</td>\n", manuf_from_mac(mac_address));
        
        X(c, "  <td id=\"iehash\" class=\"iehash\">0x%08x</td>\n", sta->ie_hash);
        X(c, "  <td id=\"standard\" class=\"standard\">%s</td>\n", standard_name(sta->standard));
        X(c, "  <td id=\"channelwidth\" class=\"channelwidth\">%dMHz</td>\n", sta->channel_width);

		
		/*
		 * Power
		 */
		if (sta->dbm) {
			X(c, "  <td id=\"power\" class=\"power\">%d</td>\n", sta->dbm);
		} else
			X(c, "  <td id=\"power\" class=\"power\"></td>\n");

        /*
         * Count
         */
		X(c, "  <td id=\"probes\" class=\"probes\">%u</td>\n", sta->probe_count);

        /*
         * Last Timestamp
         */
        {
            struct tm *mytm;
            char timestr[64];
            mytm = localtime(&sta->dbm_last_update);
            strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", mytm);
    		X(c, "  <td id=\"seenlast\" class=\"seenlast\">%s</td>\n", timestr);
        }

        /*
         * ESSIDs probed
         */
		X(c, "  <td id=\"essids\" class=\"essids\">");
        {
            struct EntrySSID *s;
            bool needs_comma = false;
            for (s=&sta->ssid; s; s = s->next) {
                if (sanity_check(&s->ssid)) {
                    if (needs_comma)
                        X(c, ", ");
                    defang_ssid(defanged, sizeof(defanged), (const char*)s->ssid.value, s->ssid.length);
                    X(c, "\"%s\"", defanged);
                    needs_comma = true;
                }
            }
        }
		X(c, "</td>\n");
		X(c, " </tr>\n");
	}
	X(c, "</table>\n");

	X(c,	"</body>\n"
			"</html>\n"
			);

    if (list)
        free(list);
	pixie_leave_critical_section(sqdb->cs);
}

/*===========================================================================
 *===========================================================================*/
void
xml_probers_list(struct mg_connection *c, const struct mg_request_info *ri, void *user_data)
{
	struct SQDB *sqdb = (struct SQDB*)user_data;
	unsigned i;
    struct TMP_STATIONS *list;
    size_t list_count = 0;
    char defanged[1024];
    char *last_update_string;
    time_t last_update = 0;
    
	pixie_enter_critical_section(sqdb->cs);

	mg_headers_ok(c, "text/xml");
	X(c, "Connection: close\r\n");
	X(c, "\r\n");

	X(c, "<?xml version=\"1.0\" ?>\n");

    last_update_string = mg_get_var(c, "last_update");
    if (last_update_string) {
        last_update = atoi(last_update_string);
        free(last_update_string);
    }

    /*
     * Extract a sorted list
     */
    list = sqdb_enum_probers(sqdb, &list_count);

	X(c, "<update timestamp=\"%u\" count=\"%u\">\n", time(0), list_count);

    /*
     * Print the list
     */
    for (i=0; i<list_count; i++) {
		struct SQDB_Station *sta = list[i].sta.unassociated;
	    const unsigned char *mac_address = sta->mac_address;	
		
        if (sta->dbm_last_update+1 < last_update)
            continue;

		X(c, " <prober id=\"%02x%02x%02x%02x%02x%02x\" timestamp=\"%u\">\n",
				mac_address[0],mac_address[1],mac_address[2],
				mac_address[3],mac_address[4],mac_address[5],
                sta->dbm_last_update
				);

		/*
		 * BSSID
		 */
		X(c, "  <mac>[%02x:%02x:%02x:%02x:%02x:%02x]</mac>\n",
				mac_address[0],mac_address[1],mac_address[2],
				mac_address[3],mac_address[4],mac_address[5],
				mac_address[0],mac_address[1],mac_address[2],
				mac_address[3],mac_address[4],mac_address[5]
				);
		X(c, "  <manuf>%s</manuf>\n", manuf_from_mac(mac_address));

        X(c, "  <iehash>0x%08x</iehash>\n", sta->ie_hash);
        X(c, "  <standard>%s</standard>\n", standard_name(sta->standard));
        X(c, "  <channelwidth>%dMHz</channelwidth>\n", sta->channel_width);


		/*
		 * Power
		 */
		if (sta->dbm) {
			X(c, "  <power>%d</power>\n", sta->dbm);
		}

		/*
		 * Probe Count
		 */
		X(c, "  <probes>%u</probes>\n", sta->probe_count);


        /*
         * Timestamp last seen
         */
		X(c, "  <seenlast>%u</seenlast>\n", sta->dbm_last_update);


		/*
		 * ESSID
		 */
		X(c, "  <essids>");
        {
            struct EntrySSID *s;
            bool needs_comma = false;
            for (s=&sta->ssid; s; s = s->next) {
                if (sanity_check(&s->ssid)) {
                    if (needs_comma)
                        X(c, ", ");
                    defang_ssid(defanged, sizeof(defanged), (const char*)s->ssid.value, s->ssid.length);
                    X(c, "\"%s\"", defanged);
                    needs_comma = true;
                }
            }
        }
		X(c, "</essids>\n");
		X(c, " </prober>\n");
	}
	X(c, "</update>\n");

    if (list)
        free(list);
	pixie_leave_critical_section(sqdb->cs);
}
