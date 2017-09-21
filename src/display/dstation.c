#include "../sqdb/sqdb2.h"
#include "pixie.h"
#include "mongoose.h"
#include "display.h"
#include <string.h>
#include <stdlib.h>
#include "manuf.h"
#include "sprintf_s.h"

/*===========================================================================
 *===========================================================================*/
void
xml_station_item(struct mg_connection *c, const struct mg_request_info *ri, void *user_data)
{
	struct SQDB *sqdb = (struct SQDB*)user_data;
	unsigned char mac_address[6];
    char mac_address_str[16] = "";
    struct TMP_STATIONS *stations=NULL;
    unsigned station_count = 0;

	pixie_enter_critical_section(sqdb->cs);

	if (memcmp(ri->uri, "/station/", 9) != 0) {
		mg_printf(c, "404 Not Found\r\nConnection: closed\r\n\r\n");
		goto _return;
	}

	/*
	 * Lookup this BSSID entry
	 */
	parse_mac_address(mac_address, sizeof(mac_address), ri->uri+strlen("/station/"));
	stations = sqdb_find_station(sqdb, mac_address, &station_count);
	if (stations == NULL || station_count == 0) {
		mg_printf(c, "404 Not Found\r\nConnection: closed\r\n\r\n");
		goto _return;
	}

	sprintf_s(mac_address_str, sizeof(mac_address_str), "%02x%02x%02x%02x%02x%02x", 
					mac_address[0],mac_address[1],mac_address[2],
					mac_address[3],mac_address[4],mac_address[5]
					);

	mg_headers_ok(c, "text/xml");
	X(c, "Connection: close\r\n");
	X(c, "\r\n");

	X(c, "<?xml version=\"1.0\" ?>\n");
	X(c, "<update timestamp=\"%u\">\n", time(0));
	X(c, " <station id=\"%02x%02x%02x%02x%02x%02x\">\n",
					mac_address[0],mac_address[1],mac_address[2],
					mac_address[3],mac_address[4],mac_address[5]
					);
	X(c, "  <mac>[%02x:%02x:%02x:%02x:%02x:%02x]</mac>\n",
					mac_address[0],mac_address[1],mac_address[2],
					mac_address[3],mac_address[4],mac_address[5]
					);
	X(c, " </station>\n");

	X(c, "</update>\n");
_return:
	pixie_leave_critical_section(sqdb->cs);
    if (stations)
        free(stations);
}




/*===========================================================================
 *===========================================================================*/
void
display_station_item(struct mg_connection *c, const struct mg_request_info *ri, void *user_data)
{
	struct SQDB *sqdb = (struct SQDB*)user_data;
	unsigned char mac_address[6];
	char mac_address_str[16];
	char buf[64];
    struct TMP_STATIONS *stations = NULL;
    unsigned station_count = 0;
    unsigned i;

	if (strstr(ri->uri, ".xml")) {
		xml_station_item(c, ri, user_data);
		return;
	}
	pixie_enter_critical_section(sqdb->cs);

	if (memcmp(ri->uri, "/station/", 9) != 0) {
		mg_printf(c, "404 Not Found\r\nConnection: closed\r\n\r\n");
		goto _return;
	}

	/*
	 * Lookup this BSSID entry
	 */
	parse_mac_address(mac_address, sizeof(mac_address), ri->uri+strlen("/station/"));
	stations = sqdb_find_station(sqdb, mac_address, &station_count);
	if (stations == 0 || station_count == 0) {
		mg_printf(c, "404 Not Found\r\nConnection: closed\r\n\r\n");
		goto _return;
	}


	
	sprintf_s(mac_address_str, sizeof(mac_address_str), "%02x%02x%02x%02x%02x%02x", 
					mac_address[0],mac_address[1],mac_address[2],
					mac_address[3],mac_address[4],mac_address[5]
					);

	mg_headers_ok(c, "text/html");
	X(c, "Connection: close\r\n");
	X(c, "\r\n");

	//X(c, "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\" \"http://www.w3.org/TR/html4/strict.dtd\">\r\n");
	X(c,"<html>\n");
	X(c,"<head>\n");
	X(c," <title>Squirrel WiFi monitor</title>\n");
	X(c," <link rel=\"stylesheet\" type=\"text/css\" href=\"../squirrel.css\" />\n");
	X(c," <link rel=\"Shortcut Icon\" href=\"../favicon.ico\" type=\"image/x-icon\">\n");
	X(c," <script type=\"text/javascript\" src=\"../squirrel.js\"></script>\n");
	X(c, "<script type=\"text/javascript\">var bssid_item_address = '%s';</script>\n", mac_address_str);
	X(c,"</head>\n");
	X(c,"<body onLoad=\"setInterval(refresh_station_item,1000)\">\n");

	display_topmenu(c, ri, user_data, 1);

    for (i=0; i<station_count; i++) {
        struct TMP_STATIONS *tmp = &stations[i];

        /*
         * ASSOCIATED station
         */
        if (tmp->type == 2) {
            struct SQDB_SubStation *sta = tmp->sta.associated;
            struct SQDB_AccessPoint *ap = tmp->sta.accesspoint;

	        X(c, "<table id=\"station\" class=\"station\">\n");
            X(c, "  <tr id=\"0\"><th colspan=\"6\" class=\"title\">ASSOCIATED STATION</th></tr>\n");
	        X(c, "  <tr id=\"1\">\n");
	        X(c, "   <th>MAC:</th><td id=\"mac\" class=\"mac\">[%02x:%02x:%02x:%02x:%02x:%02x]</td>\n",
					        mac_address[0],mac_address[1],mac_address[2],
					        mac_address[3],mac_address[4],mac_address[5],
					        mac_address[0],mac_address[1],mac_address[2],
					        mac_address[3],mac_address[4],mac_address[5]
					        );
	        X(c, "   <th>Data Sent:</th><td id=\"dataout\" class=\"sent\">%s</td>\n", format_unsigned(sta->data_sent,buf,sizeof(buf)));
	        X(c, "   <th>Data Recv:</th><td id=\"datain\" class=\"sent\">%s</td>\n", format_unsigned(sta->data_received,buf,sizeof(buf)));
	        X(c, "  </tr>\n");
	        X(c, "  <tr id=\"2\">\n");
	        X(c, "   <th>SSID:</th><td id=\"essid\" class=\"essid\"><a href=\"/bssid/%02x%02x%02x%02x%02x%02x.html\">%.*s</a></td>\n", 
                ap->bssid[0], ap->bssid[1], ap->bssid[2], 
                ap->bssid[3], ap->bssid[4], ap->bssid[5], 
                ap->ssid.length, ap->ssid.value);
	        X(c, "   <th>Ctrl Sent:</th><td id=\"ctrlout\" class=\"sent\">%s</td>\n", format_unsigned(sta->ctrl_sent,buf,sizeof(buf)));
	        X(c, "   <th>Ctrl Recv:</th><td id=\"ctrlin\" class=\"sent\">%s</td>\n", format_unsigned(sta->ctrl_received,buf,sizeof(buf)));
	        X(c, "  </tr>\n");
	        X(c, "  <tr id=\"4\">\n");
	        X(c, "   <th>BSSID:</th><td id=\"bssid\" class=\"bssid\"><a href=\"/bssid/%02x%02x%02x%02x%02x%02x.html\">%02x:%02x:%02x:%02x:%02x:%02x</a></td>\n", 
                ap->bssid[0], ap->bssid[1], ap->bssid[2], 
                ap->bssid[3], ap->bssid[4], ap->bssid[5], 
                ap->bssid[0], ap->bssid[1], ap->bssid[2], 
                ap->bssid[3], ap->bssid[4], ap->bssid[5]
                );
	        X(c, "   <th>Power:</th><td id=\"power\" class=\"power\">%s</td>\n", format_signed(sta->dbm,buf,sizeof(buf)));
	        X(c, "   <th>Channels:</th><td id=\"channels\" class=\"channels\">");
	        {
		        unsigned j;
		        for (j=0; j<ap->channel_count; j++) {
			        X(c, "%u%c", ap->channels[j], (j+1<ap->channel_count?',':' '));
		        }
	        }
            X(c, "</td>\n");
	        X(c, "  </tr>\n");
	        X(c, "  <tr id=\"6\">\n");
	        X(c, "   <th>MANUF:</th><td id=\"manuf\" class=\"manuf\">%s</td>\n", manuf_from_mac(mac_address));
	        X(c, "   <th>Desc:</th><td id=\"manuf2\" class=\"manuf2\" colspan=\"3\">%s</td>\n", manuf2_from_mac(mac_address));
	        X(c, "  </tr>\n");
	        X(c, "  <tr id=\"7\">\n");
	        X(c, "   <th>Info:</th><td id=\"manuf\" class=\"manuf\" colspan=\"5\">\n");
            {
                struct NVPair *nv = sta->data;
                while (nv) {
                    X(c, "    %s = %s<br/>\n", nv->name, nv->value);
                    nv = nv->next;
                }
            }
            X(c, "   </th>\n");
	        X(c, "  </tr>\n");
	        X(c, "</table><br/>\n");
        }

        if (tmp->type == 1) {
            struct SQDB_Station *sta = tmp->sta.unassociated;

	        X(c, "<table id=\"station\" class=\"station\">\n");
            X(c, "  <tr id=\"0\"><th colspan=\"6\" class=\"title\">UNASSOCIATED PROBER</th></tr>\n");
	        X(c, "  <tr id=\"1\">\n");
	        X(c, "   <th>MAC:</th><td id=\"mac\" class=\"mac\">[%02x:%02x:%02x:%02x:%02x:%02x]</td>\n",
					        mac_address[0],mac_address[1],mac_address[2],
					        mac_address[3],mac_address[4],mac_address[5],
					        mac_address[0],mac_address[1],mac_address[2],
					        mac_address[3],mac_address[4],mac_address[5]
					        );
	        X(c, "   <th><a href=\"../probe/%02x%02x%02x%02x%02x%02x.html\"><img src=\"../decoder.ico\" />Probes</a>:</th><td id=\"dataout\" class=\"sent\">%s</td>\n",
              mac_address[0],mac_address[1],mac_address[2],
              mac_address[3],mac_address[4],mac_address[5],
              format_unsigned(sta->probe_count,buf,sizeof(buf)));
	        X(c, "   <th>Responses:</th><td id=\"datain\" class=\"sent\">%s</td>\n", format_unsigned(0,buf,sizeof(buf)));
	        X(c, "  </tr>\n");
	        X(c, "  <tr id=\"7\">\n");
	        X(c, "   <th>SSIDs:</th><td id=\"essid\" class=\"essid\" colspan=\"5\">\n");
            {
                struct EntrySSID *s;
                for (s=&sta->ssid; s; s = s->next) {
                    char defanged[1024];
                    defang_ssid(defanged, sizeof(defanged), (const char*)s->ssid.value, s->ssid.length);
                    X(c, "%s<br/>", defanged);
                }
            }
            X(c, "   </th>\n");
	        X(c, "  </tr>\n");
	        X(c, "</table><br/>\n");
        }
    }

	X(c,	"</body>\n"
			"</html>\n"
			);

_return:
	pixie_leave_critical_section(sqdb->cs);
    if (stations)
        free(stations);
}


