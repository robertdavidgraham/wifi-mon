#include "sqdb/sqdb2.h"
#include "pixie.h"
#include "mongoose.h"
#include "manuf.h"
#include "display.h"
#include <string.h>

/*===========================================================================
 *===========================================================================*/
void
display_events_list(struct mg_connection *c, const struct mg_request_info *ri, void *user_data)
{
	struct SQDB *sqdb = (struct SQDB*)user_data;
	unsigned i;
    struct SQDB_Event *event;
    unsigned event_count = 0;

	pixie_enter_critical_section(sqdb->cs);

	mg_headers_ok(c, "text/html");
	X(c, "Connection: close\r\n");
	X(c, "\r\n");

	//X(c, "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\" \"http://www.w3.org/TR/html4/strict.dtd\">\r\n");
	X(c,"<html>\n");
	X(c,"<head>\n");
	X(c," <title>Squirrel WiFi monitor</title>\n");
	X(c," <link rel=\"stylesheet\" type=\"text/css\" href=\"squirrel.css\" />\n");
	X(c," <link rel=\"Shortcut Icon\" href=\"/favicon.ico\" type=\"image/x-icon\">\n");
	X(c," <script type=\"text/javascript\" src=\"squirrel.js\"></script>\n");
	X(c,"</head>\n");
	X(c,"<body onLoad=\"setInterval(refresh_event_list,1000)\">\n");

	/*X(c, "<button onclick=\"loadXMLDoc('bssids.xml')\">Get CD info</button>\n");
	X(c, "<button onclick='nukeRow()'>Nuke Row</button>\n");
	X(c, "<button onclick='self.setInterval(refresh,1000)'>Auto</button>\n");*/
	display_topmenu(c, ri, user_data, 0);

	X(c, "<table class=\"bssids\" id=\"bssidlist\">\n");
	X(c,	"<tr>\n <th>Event#</th>\n"
            " <th>Time</th>\n"
			" <th>TYPE</th>\n"
			" <th>BASE</th>\n"
			" <th>STATION</th>\n"
			" <th>Packets</th>\n"
			"</tr>\n");

    /*
     * Go through the linked list of events and display them
     */
    for (event=sqdb->events, event_count=0; event && event_count < 100; event = event->next, event_count++) {
        char timestr[64];
        struct tm *mytm = gmtime(&event->time_last);
        struct SQDB_AccessPoint *ap = event->ap;
        struct SQDB_SubStation *sta = event->sta;
        unsigned packet_count = 0;

        strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", mytm);

	    X(c, " <tr id=\"%u\">\n", event->event_id);

	    X(c, "  <td id=\"eventid\">%u</td>\n", event->event_id);
		X(c, "  <td id=\"time\">%s</td>\n", timestr);

        switch (event->type) {
        case EVENT_ASSOC: X(c, "  <td id=\"eventtype\">Connect</td>\n"); break;
        case EVENT_DEAUTH: X(c, "  <td id=\"eventtype\">Disconnect</td>\n"); break;
        default: X(c, "  <td id=\"eventtype\">%u</td>\n", event->type); break;
        }

		/*
		 * ACCESS POINT
		 */
        if (ap->ssid.length) {
		    X(c, "  <td id=\"bssid\"><a href=\"/bssid/%02x%02x%02x%02x%02x%02x.html\">\"%.*s\"</a></td>\n",
				    ap->bssid[0],ap->bssid[1],ap->bssid[2],
				    ap->bssid[3],ap->bssid[4],ap->bssid[5],
                    ap->ssid.length, ap->ssid.value
				    );
        } else {
		    X(c, "  <td id=\"bssid\"><a href=\"/bssid/%02x%02x%02x%02x%02x%02x.html\">[%02x:%02x:%02x:%02x:%02x:%02x]</a></td>\n",
				    ap->bssid[0],ap->bssid[1],ap->bssid[2],
				    ap->bssid[3],ap->bssid[4],ap->bssid[5],
				    ap->bssid[0],ap->bssid[1],ap->bssid[2],
				    ap->bssid[3],ap->bssid[4],ap->bssid[5]
				    );
        }

        /*
         * STATION
         */
        {
            const char *name = get_station_name(sta);
            if (name && name[0]) {
                char defanged[128];
                defang_ssid(defanged, sizeof(defanged), name, strlen(name));
		        X(c, "  <td id=\"station\"><a href=\"/station/%02x%02x%02x%02x%02x%02x.html\">\"%s\"</a></td>\n",
				        sta->mac_address[0],sta->mac_address[1],sta->mac_address[2],
				        sta->mac_address[3],sta->mac_address[4],sta->mac_address[5],
				        name
				        );
            } else {
		        X(c, "  <td id=\"station\"><a href=\"/station/%02x%02x%02x%02x%02x%02x.html\">[%02x:%02x:%02x:%02x:%02x:%02x]</a></td>\n",
				        sta->mac_address[0],sta->mac_address[1],sta->mac_address[2],
				        sta->mac_address[3],sta->mac_address[4],sta->mac_address[5],
				        sta->mac_address[0],sta->mac_address[1],sta->mac_address[2],
				        sta->mac_address[3],sta->mac_address[4],sta->mac_address[5]
				        );
            }
        }
        packet_count = 0;
        for (i=0; i<sizeof(event->packets)/sizeof(event->packets[0]); i++)
            packet_count += event->packets[i].dup_count;

	    X(c, "  <td id=\"packets\"><a href=\"/eventpkt/%u.html\">%u</a></td>\n", event->event_id, packet_count);
		X(c, " </tr>\n");
	}
	X(c, "</table>\n");

	X(c,	"</body>\n"
			"</html>\n"
			);

	pixie_leave_critical_section(sqdb->cs);
}

/*===========================================================================
 *===========================================================================*/
void
xml_event_list(struct mg_connection *c, const struct mg_request_info *ri, void *user_data)
{
	struct SQDB *sqdb = (struct SQDB*)user_data;
	unsigned i;
    char buf[1024];

	pixie_enter_critical_section(sqdb->cs);

	mg_headers_ok(c, "text/xml");
	X(c, "Connection: close\r\n");
	X(c, "\r\n");

	X(c, "<?xml version=\"1.0\" ?>\n");
	X(c, "<update timestamp=\"%u\">\n", time(0));

	for (i=0; i<sizeof(sqdb->access_points)/sizeof(sqdb->access_points[0]); i++) {
		struct SQDB_AccessPoint *ap;
		
		for (ap = sqdb->access_points[i]; ap; ap = ap->next) {

			X(c, " <base id=\"%02x%02x%02x%02x%02x%02x\" timestamp=\"%u\">\n",
					ap->bssid[0],ap->bssid[1],ap->bssid[2],
					ap->bssid[3],ap->bssid[4],ap->bssid[5],
                    ap->dbm_last_update
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
            if (ap->cisco_name.length) {
    			X(c, "  <essid>%.*s name=%.*s</essid>\n", ap->ssid.length, ap->ssid.value, ap->cisco_name.length, ap->cisco_name.value);
            } else
	    		X(c, "  <essid>%.*s</essid>\n", ap->ssid.length, ap->ssid.value);

			X(c, " </base>\n");
		}
	}
	X(c, "</update>\n");

	pixie_leave_critical_section(sqdb->cs);
}
