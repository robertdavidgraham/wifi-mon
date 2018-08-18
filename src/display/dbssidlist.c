#include "../sqdb/sqdb2.h"
#include "pixie.h"
#include "mongoose.h"
#include "manuf.h"
#include "display.h"
#include <stdlib.h>
#include <string.h>

/**
 * Insert an access-point into an ordered list of access-points,
 * where order is determined by time of activity, with most recently
 * active access-points at the front of the list
 *
 * Thus, we we search forward in the list until we find an "older"
 * access-point (or an empty entry), and insirt it into that point.
 */
static void
ap_insert_into_list(struct SQDB_AccessPoint **list, struct SQDB_AccessPoint *ap)
{
    unsigned i;

    for (i=0; list[i]; i++) {
        if (ap->last > list[i]->last) {
            struct SQDB_AccessPoint *x = list[i];
            list[i] = ap;
            ap = x;
        }
    }
    list[i] = ap;
}


/**
 * This goes through the table of access-points and returns an ordered
 * list, with the most recently active first.
 *
 * The caller is responsible for calling "free()" on the returned pointer
 */
static struct SQDB_AccessPoint **
ap_get_sorted_list(struct SQDB *sqdb)
{
    unsigned i;
    unsigned count = 0;
    struct SQDB_AccessPoint **list;

    /* First, count the total access points */
	for (i=0; i<sizeof(sqdb->access_points)/sizeof(sqdb->access_points[0]); i++) {
		struct SQDB_AccessPoint *ap;	
		for (ap = sqdb->access_points[i]; ap; ap = ap->next) {
            count++;
        }
    }

    /* Second, allocate memory to hold pointers to all the APs */
    list = (struct SQDB_AccessPoint **)malloc((count+1) * sizeof(list[0]));
    memset(list, 0, (count+1) * sizeof(list[0]));

    /* Insert everything into the list, with most recently active stations
     * at the front of the list, and oldest at the end */
   	for (i=0; i<sizeof(sqdb->access_points)/sizeof(sqdb->access_points[0]); i++) {
		struct SQDB_AccessPoint *ap;
		
		for (ap = sqdb->access_points[i]; ap; ap = ap->next) {
            ap_insert_into_list(list, ap);
        }
    }
    return list;
}


/*===========================================================================
 *===========================================================================*/
void
display_bssid_list(struct mg_connection *c, const struct mg_request_info *ri, void *user_data)
{
	struct SQDB *sqdb = (struct SQDB*)user_data;
	unsigned i;
    char buf[1024];
    struct SQDB_AccessPoint **list;

	pixie_enter_critical_section(sqdb->cs);

	mg_headers_ok(c, "text/html");
	X(c, "Connection: close\r\n");
	X(c, "\r\n");

    /*
     * Display the top part of the page
     */
    display_report_title(c, "Base Stations", "refresh", 0);

	/*
     * Create the table header 
     */
	X(c, "<table class=\"sortable\" id=\"bssidlist\">\n");
	X(c,	"<thead><tr>\n <th>BSSID</th>\n"
			" <th>MANUF</th>\n"
			" <th>#STA</th>\n"
			" <th>PWR</th>\n"
			" <th>Beacons</th>\n"
			" <th>Data</th>\n"
			" <th>CH</th>\n"
			" <th>MB</th>\n"
			" <th>ENC</th>\n"
			" <th>CIPHER</th>\n"
			" <th>AUTH</th>\n"
			" <th>AdHoc</th>\n"
			" <th>ESSID</th>\n"
			"</tr></thead>\n<tbody>\n");

    /*
     * Get a ordered list with most recent APs first
     */
    list = ap_get_sorted_list(sqdb);

    /*
     * print all the entries
     */
    for (i=0; list[i]; i++) {
    struct SQDB_AccessPoint *ap = list[i];
	

		X(c, " <tr id=\"%02x%02x%02x%02x%02x%02x\" timestamp=\"%u\" class=\"inactive\">\n",
				ap->bssid[0],ap->bssid[1],ap->bssid[2],
				ap->bssid[3],ap->bssid[4],ap->bssid[5],
                ap->last
				);

		/*
		 * BSSID
		 */
		X(c, "  <td id=\"bssid\" class=\"bssid\"><a href=\"/bssid/%02x%02x%02x%02x%02x%02x.html\">[%02x:%02x:%02x:%02x:%02x:%02x]</a></td>\n",
				ap->bssid[0],ap->bssid[1],ap->bssid[2],
				ap->bssid[3],ap->bssid[4],ap->bssid[5],
				ap->bssid[0],ap->bssid[1],ap->bssid[2],
				ap->bssid[3],ap->bssid[4],ap->bssid[5]
				);
		X(c, "  <td id=\"manuf\" class=\"manuf\">%s</td>\n", manuf_from_mac(ap->bssid));

		/*
		 * # of stations
		 */
		X(c, "  <td id=\"stacount\" class=\"stacount\">%s</td>\n", 
            format_unsigned(sqdb_bssid_station_count(sqdb, ap->bssid),buf,sizeof(buf)));

		/*
		 * Power
		 */
		if (ap->dbm) {
			X(c, "  <td id=\"power\" class=\"power\">%d</td>\n", ap->dbm);
		} else
			X(c, "  <td id=\"power\" class=\"power\"></td>\n");

		/*
		 * Beacons
		 */
		if (ap->beacon_count) {
			X(c, "  <td id=\"beacons\" class=\"beacons\">%u</td>\n", ap->beacon_count);
		} else
			X(c, "  <td id=\"beacons\" class=\"beacons\"></td>\n");

		/*
		 * Data
		 */
		X(c, "  <td id=\"datapackets\" class=\"datapackets\">%s</td>\n", 
            format_unsigned(ap->data_sent + ap->data_received,buf,sizeof(buf)));

		/*
		 * Channels
		 */
		X(c, "  <td id=\"channels\" class=\"channels\">");
		{
			unsigned j;
			for (j=0; j<ap->channel_count; j++) {
				X(c, "%u%c", ap->channels[j], (j+1<ap->channel_count?',':' '));
			}
		}
		X(c, "</td>\n");


		/*
		 * Mbps speed
		 */
        if (accesspoint_maxrate(ap) > 0)
    		X(c, "  <td id=\"speed\" class=\"speed\">%u%s</td>\n", accesspoint_maxrate(ap)/10, (accesspoint_maxrate(ap)%10)?".5":"");
        else
    		X(c, "  <td id=\"speed\" class=\"speed\"></td>\n");
		
		/*
		 * CIPHERS
		 */
		X(c, "  <td id=\"encryption\" class=\"encryption\">%s</td>\n", format_enum(ap->encryption_type));
		X(c, "  <td id=\"cipher\" class=\"cipher\">%s</td>\n", format_enum(ap->cipher_type));
		X(c, "  <td id=\"auth\" class=\"auth\">%s</td>\n", format_enum(ap->auth_type));
        X(c, "  <td id=\"adhoc\" class=\"adhoc\">%s</td>\n", ap->flag_is_ibss?"***":"");
		
		/*
		 * ESSID
		 */
        {
            if (ap->cisco_name.length) {
    		    X(c, "  <td id=\"essid\" class=\"essid\">%.*s &nbsp; name=%.*s</td>\n", ap->ssid.length, ap->ssid.value, ap->cisco_name.length, ap->cisco_name.value);
            } else
    		    X(c, "  <td id=\"essid\" class=\"essid\">%.*s</td>\n", ap->ssid.length, ap->ssid.value);
        }

		X(c, " </tr>\n");
		/*X(c, " <tr>\n");

		X(c, "  <td class=\"substations\" colspan=\"4\">\n");
		if (ap->substations) {
			struct SQDB_SubStation *sta;

			X(c, "   <table>\n");
			for (sta=ap->substations; sta; sta = sta->next) {
				X(c, "     <tr>\n");
				X(c, "      <td>[%02x:%02x:%02x:%02x:%02x]</td>\n",
					sta->mac_address[0], sta->mac_address[1], sta->mac_address[2], 
					sta->mac_address[3], sta->mac_address[4], sta->mac_address[5]);
				X(c, "     </tr>\n");
			}
			X(c, "   </table>\n");

		}
		X(c, "  </td>\n");
		X(c, " </tr>\n");*/
	}
    free(list);
	X(c, "</tbody>\n</table>\n");

	X(c,	"</body>\n"
			"</html>\n"
			);

	pixie_leave_critical_section(sqdb->cs);
}

/*===========================================================================
 *===========================================================================*/
void
xml_bssid_list(struct mg_connection *c, const struct mg_request_info *ri, void *user_data)
{
	struct SQDB *sqdb = (struct SQDB*)user_data;
	unsigned i;
    char buf[1024];
    struct SQDB_AccessPoint **list;
    time_t last_update = 0;
    char *last_update_string;

	pixie_enter_critical_section(sqdb->cs);

	mg_headers_ok(c, "text/xml");
	X(c, "Connection: close\r\n");
	X(c, "\r\n");

	X(c, "<?xml version=\"1.0\" ?>\n");
	X(c, "<update timestamp=\"%u\">\n", time(0));

    last_update_string = mg_get_var(c, "last_update");
    if (last_update_string) {
        last_update = atoi(last_update_string);
        free(last_update_string);
    }

    /*
     * Extract a sorted list
     */
    list = ap_get_sorted_list(sqdb);

    /*
     * Print the list
     */
    for (i=0; list[i]; i++) {
		struct SQDB_AccessPoint *ap = list[i];

        if (ap->last+1 < last_update)
            continue;

		X(c, " <base id=\"%02x%02x%02x%02x%02x%02x\" timestamp=\"%u\">\n",
				ap->bssid[0],ap->bssid[1],ap->bssid[2],
				ap->bssid[3],ap->bssid[4],ap->bssid[5],
                ap->last
				);

		/*
		 * BSSID
		 */
		X(c, "  <bssid>[%02x:%02x:%02x:%02x:%02x:%02x]</bssid>\n",
				ap->bssid[0],ap->bssid[1],ap->bssid[2],
				ap->bssid[3],ap->bssid[4],ap->bssid[5],
				ap->bssid[0],ap->bssid[1],ap->bssid[2],
				ap->bssid[3],ap->bssid[4],ap->bssid[5]
				);
		X(c, "  <manuf>%s</manuf>\n", manuf_from_mac(ap->bssid));

		/*
		 * # of stations
		 */
		X(c, "  <stacount>%s</stacount>\n", format_unsigned(sqdb_bssid_station_count(sqdb, ap->bssid),buf,sizeof(buf)));

		/*
		 * Power
		 */
		if (ap->dbm) {
			X(c, "  <power>%d</power>\n", ap->dbm);
		}

		/*
		 * Beacons
		 */
		if (ap->beacon_count) {
			X(c, "  <beacons>%u</beacons>\n", ap->beacon_count);
		}

		/*
		 * Data
		 */
		if (ap->data_sent + ap->data_received)
			X(c, "  <datapackets>%u</datapackets>\n", ap->data_sent + ap->data_received);

		/*
		 * Channels
		 */
		X(c, "  <channels>");
		{
			unsigned j;
			for (j=0; j<ap->channel_count; j++) {
				X(c, "%u%c", ap->channels[j], (j+1<ap->channel_count?',':' '));
			}
		}
		X(c, "</channels>\n");


		/*
		 * Mbps speed
		 */
        if (accesspoint_maxrate(ap) > 0)
		X(c, "  <speed>%u%s</speed>\n", accesspoint_maxrate(ap)/10, (accesspoint_maxrate(ap)%10)?".5":"");
		
		/*
		 * CIPHERS
		 */
		X(c, "  <encryption>%s</encryption>\n", format_enum(ap->encryption_type));
		X(c, "  <cipher>%s</cipher>\n", format_enum(ap->cipher_type));
		X(c, "  <auth>%s</auth>\n", format_enum(ap->auth_type));
        X(c, "  <adhoc>%s</adhoc>\n", ap->flag_is_ibss?"***":"");
		
		/*
		 * ESSID
		 */
        X(c, "  <essid><![CDATA[");
        {
            char defanged[1024];
            defang_ssid(defanged, sizeof(defanged), (const char*)ap->ssid.value, ap->ssid.length);
            X(c, "%s", defanged);
            if (ap->cisco_name.length) {
                defang_ssid(defanged, sizeof(defanged), (const char*)ap->cisco_name.value, ap->cisco_name.length);
    		    X(c, " &nbsp; name=%s", defanged);
            }
        }
        X(c, "]]></essid>\n");
		X(c, " </base>\n");
	}
	X(c, "</update>\n");

    if (list)
        free(list);
	pixie_leave_critical_section(sqdb->cs);
}
