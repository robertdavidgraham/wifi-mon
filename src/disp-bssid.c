#include "sqdb2.h"
#include "util-pixie.h"
#include "mongoose.h"
#include "disp-squirrel.h"
#include <string.h>
#include "pcap-manuf.h"
#include "disp-main.h"
#include "util-annexk.h"
#include <stdlib.h>

#if 0
static bool has_name(struct NVPair *nv, const char *name)
{
	UNUSEDPARM(name);
    while (nv) {
        if (strcmp(nv->name, name) == 0)
            return true;
        nv = nv->next;
    }
    return false;
}
#endif

#if 0
static bool has_value(struct NVPair *nv, const char *name, const char *value)
{
    size_t value_length = strlen(value);

    while (nv) {
        if (strcmp(nv->name, name) == 0) {
            if (strlen(nv->value) >= value_length) {
                if (memcmp(nv->value, value, value_length) == 0)
                    return true;
            }
        }
        nv = nv->next;
    }
    return false;
}
#endif

/*===========================================================================
 *===========================================================================*/
#if 0
static void
system_logo(struct mg_connection *c, struct SQDB_SubStation *sta)
{
    if (has_name(sta->data, "system")) {
        if (has_value(sta->data, "system", "WinXP")) {
            X(c, "<img height=\"24\" width=\"24\" src=\"/img/windows-logo1.jpg\" />");
        }
    }
}
#endif


/*===========================================================================
 *===========================================================================*/
void
xml_bssid_item(struct mg_connection *c, const struct mg_request_info *ri, void *user_data)
{
	struct SQDB *sqdb = (struct SQDB*)user_data;
	unsigned char bssid[6];
	struct SQDB_AccessPoint *ap;
	struct SQDB_SubStation *sta;
	char buf[64];
    char *seenlast_str;
    time_t seenlast = 0;

	pixie_enter_critical_section(sqdb->cs);

	if (memcmp(ri->uri, "/bssid/", 7) != 0) {
		mg_printf(c, "404 Not Found\r\nConnection: closed\r\n\r\n");
		goto _return;
	}
    
    /*
     * Get the last time, to only grab the latest changes
     */
    seenlast_str = mg_get_var(c, "seenlast");
    if (seenlast_str) {
        //printf("seenlast = %s\n", seenlast_str);
        seenlast = atoi(seenlast_str);
    }

	/*
	 * Lookup this BSSID entry
	 */
	parse_mac_address(bssid, sizeof(bssid), ri->uri+strlen("/bssid/"));
	ap = sqdb_find_bssid(sqdb, bssid);
	if (ap == NULL) {
		mg_printf(c, "404 Not Found\r\nConnection: closed\r\n\r\n");
		goto _return;
	}

	mg_headers_ok(c, "text/xml");
	X(c, "Connection: close\r\n");
	X(c, "\r\n");

	X(c, "<?xml version=\"1.0\" ?>\n");
	X(c, "<bssidupdate timestamp=\"%u\">\n", time(0));
	X(c, " <base id=\"%02x%02x%02x%02x%02x%02x\">\n",
					ap->bssid[0],ap->bssid[1],ap->bssid[2],
					ap->bssid[3],ap->bssid[4],ap->bssid[5]
					);
	X(c, "  <bssid>[%02x:%02x:%02x:%02x:%02x:%02x]</bssid>\n",
					ap->bssid[0],ap->bssid[1],ap->bssid[2],
					ap->bssid[3],ap->bssid[4],ap->bssid[5]
					);
	X(c, "  <stacount>%s</stacount>\n", format_unsigned(sqdb_bssid_station_count(sqdb, ap->bssid),buf,sizeof(buf)));
	X(c, "  <power>%s</power>\n", format_signed(ap->dbm,buf,sizeof(buf)));
	X(c, "  <beacons>%s</beacons>\n", format_unsigned(ap->beacon_count,buf,sizeof(buf)));
    X(c, "  <essid>%.*s%s</essid>\n", ap->ssid.length, ap->ssid.value, ap->flag_is_ibss?" (adhoc)":"");
	X(c, "  <dataout>%s</dataout>\n", format_unsigned(ap->data_sent,buf,sizeof(buf)));
	X(c, "  <datain>%s</datain>\n", format_unsigned(ap->data_received,buf,sizeof(buf)));
	X(c, "  <ctrlout>%s</ctrlout>\n", format_unsigned(ap->ctrl_sent,buf,sizeof(buf)));
	X(c, "  <ctrlin>%s</ctrlin>\n", format_unsigned(ap->ctrl_received,buf,sizeof(buf)));
	X(c, "  <mgmtout>%s</mgmtout>\n", format_unsigned(ap->mgmt_sent,buf,sizeof(buf)));
	X(c, "  <mgmtin>%s</mgmtin>\n", format_unsigned(ap->mgmt_received,buf,sizeof(buf)));
	X(c, "  <seenfirst>%s</seenfirst>\n", format_time_t(ap->first,buf,sizeof(buf)));
	X(c, "  <seenlast>%s</seenlast>\n", format_time_t(ap->last,buf,sizeof(buf)));
	X(c, "  <mac><![CDATA[");
    {
        struct EntryMacAddr *mac = &ap->mac_address;
        for (mac=&ap->mac_address; mac; mac = mac->next) {
            X(c, "[%02x:%02x:%02x:%02x:%02x:%02x]%s", 
					mac->addr[0],mac->addr[1],mac->addr[2],
					mac->addr[3],mac->addr[4],mac->addr[5],
                    mac->next?"<br/>\n":"");
        }
    }
    X(c, "]]></mac>\n");
	X(c, "  <channels>");
	{
		unsigned j;
		for (j=0; j<ap->channel_count; j++) {
			X(c, "%u%c", ap->channels[j], (j+1<ap->channel_count?',':' '));
		}
	}
	X(c, "</channels>\n");
	X(c, "  <speed>%u%s</speed>\n", accesspoint_maxrate(ap)/10, (accesspoint_maxrate(ap)%10)?".5":"");
	X(c, "  <encryption>%s</encryption>\n", format_enum(ap->encryption_type));
	X(c, "  <cipher>%s</cipher>\n", format_enum(ap->cipher_type));
	X(c, "  <auth>%s</auth>\n", format_enum(ap->auth_type));
	X(c, "  <manuf>%s</manuf>\n", manuf_from_mac(ap->mac_address.addr));
	X(c, "  <manuf2>%s</manuf2>\n", manuf2_from_mac(ap->mac_address.addr));
	X(c, " </base>\n");

	/* Station list */
	X(c, " <stationlist>\n");
	for (sta = ap->substations; sta; sta = sta->next) {
        /* Skip entries that haven't changed */
        if (sta->last < seenlast)
            continue;
		X(c, " <station id=\"%02x%02x%02x%02x%02x%02x\">\n",
						sta->mac_address[0],sta->mac_address[1],sta->mac_address[2],
						sta->mac_address[3],sta->mac_address[4],sta->mac_address[5]
						);
		X(c, "  <macaddr>[%02x:%02x:%02x:%02x:%02x:%02x]</macaddr>\n",
						sta->mac_address[0],sta->mac_address[1],sta->mac_address[2],
						sta->mac_address[3],sta->mac_address[4],sta->mac_address[5]
						);
	    X(c, "  <stamanuf>%s</stamanuf>\n", manuf_from_mac(sta->mac_address));
		X(c, "  <dataout>%s</dataout>\n", format_unsigned(sta->data_sent,buf,sizeof(buf)));
		X(c, "  <datain>%s</datain>\n", format_unsigned(sta->data_received,buf,sizeof(buf)));
		X(c, "  <ctrlout>%s</ctrlout>\n", format_unsigned(sta->ctrl_sent,buf,sizeof(buf)));
		X(c, "  <ctrlin>%s</ctrlin>\n", format_unsigned(sta->ctrl_received,buf,sizeof(buf)));
		X(c, "  <power>%s</power>\n", format_signed(sta->dbm,buf,sizeof(buf)));
		X(c, "  <info>");
        //system_logo(c, sta);
		{
			struct NVPair *nv;

			for (nv = sta->data; nv; nv = nv->next) {
				X(c, "%s:%s ", nv->name, nv->value);
			}
		}
		X(c, "</info>\n");
		X(c, " </station>\n");
	}
	X(c, " </stationlist>\n");
	X(c, "</bssidupdate>\n");
_return:
	pixie_leave_critical_section(sqdb->cs);
}


/**
 * Display the value for a particular item
 */
static void
bssid_value(struct mg_connection *c, const char *name, struct SQDB_AccessPoint *ap, struct SQDB *sqdb)
{
    struct tm *mytm;
    char timestr[128];
    unsigned j;
    char buf[1024];
    char bssidstr[16];

#define VAL(n0,n1,n2,n3) (n0<<24|n1<<16|n2<<8|n3)
    X(c, "<td class=\"foo\"></td>");

    switch (VAL(name[0],name[1],name[2],name[3])) {
    case VAL('A','U','T','H'): /* Authentication */
    	X(c, "<th>Auth:</th><td id=\"auth\">%s</td>", format_enum(ap->auth_type));
        break;
    case VAL('B','S','S','I'): /* BSSID */
	    X(c, "<th>BSSID</th><td id=\"bssid\">[%02x:%02x:%02x:%02x:%02x:%02x]</td>",
					    ap->bssid[0],ap->bssid[1],ap->bssid[2],
					    ap->bssid[3],ap->bssid[4],ap->bssid[5],
					    ap->bssid[0],ap->bssid[1],ap->bssid[2],
					    ap->bssid[3],ap->bssid[4],ap->bssid[5]
					    );
        break;
    case VAL('C','H','A','N'): /* CHANNELS */
	    X(c, "<th>Channels:</th><td id=\"channels\">");
		for (j=0; j<ap->channel_count; j++) {
			X(c, "%u%c", ap->channels[j], (j+1<ap->channel_count?',':' '));
		}
        X(c, "</td>");
        break;
    case VAL('C','I','P','H'): /* Cipher */
	    X(c, "<th>Cipher:</th><td id=\"cipher\">%s</td>", format_enum(ap->cipher_type));
        break;
    case VAL('B','E','A','C'): /* Beacons Sent */
        sprintf_s(bssidstr, sizeof(bssidstr), "%02x%02x%02x%02x%02x%02x", 
			ap->bssid[0],ap->bssid[1],ap->bssid[2],
			ap->bssid[3],ap->bssid[4],ap->bssid[5]
			);
	    X(c, "<th>Beacons<a href=\"../beacon/%s.html\"><img src=\"../decoder.ico\" align=\"right\" border=\"0\"/></a><div id=\"dolphin\" /></th><td id=\"beacons\">%s", bssidstr, format_unsigned(ap->beacon_count,buf,sizeof(buf)));
        X(c, "</td>");
        break;
    case VAL('C','R','E','C'): /* Control Received */
	    X(c, "<th>Ctrl Recv:</th><td id=\"ctrlin\">%s</td>", format_unsigned(ap->ctrl_received,buf,sizeof(buf)));
        break;
    case VAL('C','S','E','N'): /* Control Sent */
	    X(c, "<th>Ctrl Sent:</th><td id=\"ctrlout\">%s</td>", format_unsigned(ap->ctrl_sent,buf,sizeof(buf)));
        break;
    case VAL('D','S','E','N'): /* Data Sent */
	    X(c, "<th>Data Sent:</th><td id=\"dataout\">%s</td>", format_unsigned(ap->data_sent,buf,sizeof(buf)));
        break;
    case VAL('D','R','E','C'): /* Data Received */
	    X(c, "<th>Data Recv:</th><td id=\"datain\">%s</td>", format_unsigned(ap->data_received,buf,sizeof(buf)));
        break;
    case VAL('M','S','E','N'): /* Mgmnt Sent */
	    X(c, "<th>Mgmnt Sent:</th><td id=\"mgmtout\">%s</td>", format_unsigned(ap->mgmt_sent,buf,sizeof(buf)));
        break;
    case VAL('M','R','E','C'): /* Mgmnt Received */
	    X(c, "<th>Mgmnt Recv:</th><td id=\"mgmtin\">%s</td>", format_unsigned(ap->mgmt_received,buf,sizeof(buf)));
        break;
    case VAL('F','I','R','S'): /* FIRST timestamp */
        mytm = localtime(&ap->first);
        strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S %z", mytm);
	    X(c, "<th>First Seen</th><td id=\"seenfirst\">%s</td>", timestr);
        break;
    case VAL('L','A','S','T'): /* LAST timestamp */
        mytm = localtime(&ap->last);
        strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S %z", mytm);
	    X(c, "<th>Last Seen</th><td id=\"seenlast\" value=\"%u\">%s</td>", ap->last, timestr);
        break;
    case VAL('M','A','C','\0'): /* MAC address */
	    X(c, "<th>MAC:</th><td id=\"mac\">");
        {
            struct EntryMacAddr *mac = &ap->mac_address;
            for (mac=&ap->mac_address; mac; mac = mac->next) {
                X(c, "[%02x:%02x:%02x:%02x:%02x:%02x]%s", 
					    mac->addr[0],mac->addr[1],mac->addr[2],
					    mac->addr[3],mac->addr[4],mac->addr[5],
                        mac->next?"<br/>\n":"");
            }
        }
        X(c, "</td>");
        break;
    case VAL('E','N','C','R'): /* Encryption */
	    X(c, "<th>Encryption:</th><td id=\"encryption\">%s</td>", format_enum(ap->encryption_type));
        break;
    case VAL('M','A','N','U'): /* Manufacturer */
       	X(c, "<th>Manuf</th><td id=\"manuf\">%s</td>", manuf_from_mac(ap->mac_address.addr));
        break;
    case VAL('M','A','N','D'): /* Manufacturer Description */
    	X(c, "<th>Desc</th><td id=\"manuf2\">%s</td>", manuf2_from_mac(ap->mac_address.addr));
        break;
    case VAL('P','O','W','E'): /* power */
	    X(c, "<th>Power:</th><td id=\"power\">%s</td>", format_signed(ap->dbm,buf,sizeof(buf)));
        break;
    case VAL('S','S','I','D'): /* SSID */
        X(c, "<th>SSID</th><td id=\"essid\">%.*s%s</td>", ap->ssid.length, ap->ssid.value, ap->flag_is_ibss?" (adhoc)":"");
        break;
    case VAL('S','P','E','E'): /* speed */
        if (accesspoint_maxrate(ap) == 0)
    	    X(c, "<th>Speed:</th><td id=\"speed\"></td>");
        else
    	    X(c, "<th>Speed:</th><td id=\"speed\">%u%s</td>", accesspoint_maxrate(ap)/10, (accesspoint_maxrate(ap)%10)?".5":"");
        break;
    case VAL('S','T','A','S'): /* station count */
	    X(c, "<th>Stations:</th><td id=\"stacount\">%s</td>", format_unsigned(sqdb_bssid_station_count(sqdb, ap->bssid),buf,sizeof(buf)));
        break;
    case VAL('N','O','N','E'):
        X(c, "<th>%s</th><td>%s</td>", "", "");
        break;
    default:
	    X(c, "<th>%s</th><td>%s</td>", name, "unknown");
        break;
    }
}

/*===========================================================================
 *===========================================================================*/
void
display_bssid_item(struct mg_connection *c, const struct mg_request_info *ri, void *user_data)
{
	struct SQDB *sqdb = (struct SQDB*)user_data;
	unsigned char bssid[6];
	char bssidstr[16];
	struct SQDB_AccessPoint *ap;
	struct SQDB_SubStation *sta;
	char buf[64];
	
	if (strstr(ri->uri, ".xml")) {
		xml_bssid_item(c, ri, user_data);
		return;
	}
	pixie_enter_critical_section(sqdb->cs);

	if (memcmp(ri->uri, "/bssid/", 7) != 0) {
		mg_printf(c, "404 Not Found\r\nConnection: closed\r\n\r\n");
		goto _return;
	}

	/*
	 * Lookup this BSSID entry
	 */
	parse_mac_address(bssid, sizeof(bssid), ri->uri+strlen("/bssid/"));
	ap = sqdb_find_bssid(sqdb, bssid);
	if (ap == NULL) {
		mg_printf(c, "404 Not Found\r\nConnection: closed\r\n\r\n");
		goto _return;
	}


	
	sprintf_s(bssidstr, sizeof(bssidstr), "%02x%02x%02x%02x%02x%02x", 
					ap->bssid[0],ap->bssid[1],ap->bssid[2],
					ap->bssid[3],ap->bssid[4],ap->bssid[5]
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
	X(c, "<script type=\"text/javascript\">var bssid_item_address = '%s';</script>\n", bssidstr);
    X(c, "<script src=\"../sorttable.js\"></script>\n");
	X(c,"</head>\n");
	X(c,"<body onLoad=\"setInterval(refresh_bssid_item,1000)\">\n");

	display_topmenu(c, ri, user_data, 1);


	X(c, "<table id=\"bssids2\" class=\"bssids2\">\n");
    X(c, "<tr><th></th><th>Property</th><th>Setting</th><th>&nbsp; &nbsp;</th><th>Property</th><th>Setting</th></tr>\n");
	X(c, "<tr>");
        bssid_value(c,"SSID",ap,sqdb);      bssid_value(c,"POWER",ap,sqdb);
    X(c, "</tr>\n<tr>");
        bssid_value(c,"BSSID",ap,sqdb);     bssid_value(c,"DSENT",ap,sqdb);
    X(c, "</tr>\n<tr>");
        bssid_value(c,"MAC",ap,sqdb);       bssid_value(c,"DRECV",ap,sqdb);
    X(c, "</tr>\n<tr>");
        bssid_value(c,"MANUF",ap,sqdb);     bssid_value(c,"CSENT",ap,sqdb);
    X(c, "</tr>\n<tr>");
        bssid_value(c,"MAND",ap,sqdb);      bssid_value(c,"CRECV",ap,sqdb);
    X(c, "</tr>\n<tr>");
        bssid_value(c,"CHANNEL",ap,sqdb);   bssid_value(c,"MSENT",ap,sqdb);
    X(c, "</tr>\n<tr>");
        bssid_value(c,"SPEED",ap,sqdb);     bssid_value(c,"MRECV",ap,sqdb);
    X(c, "</tr>\n<tr>");
        bssid_value(c,"ENCRYPT",ap,sqdb);   bssid_value(c,"BEACON",ap,sqdb);
    X(c, "</tr>\n<tr>");
        bssid_value(c,"CIPHER",ap,sqdb);   bssid_value(c,"FIRST",ap,sqdb);
    X(c, "</tr>\n<tr>");
        bssid_value(c,"AUTH",ap,sqdb);   bssid_value(c,"LAST",ap,sqdb);
	X(c, "</tr>\n");
	X(c, "</table>\n");


	X(c, "<p />\n");

		X(c, "<table id=\"stationlist\" class=\"sortable\">\n");
		X(c,	"<tr>\n"
				" <th>MAC</th>\n"
				" <th>MANUF</th>\n"
				" <th>PWR</th>\n"
				" <th>Data Out</th>\n"
				" <th>Data In</th>\n"
				" <th>Ctrl Out</th>\n"
				" <th>Ctrl In</th>\n"
				" <th>Info</th>\n"
				"</tr>\n");

		for (sta = ap->substations; sta; sta = sta->next) {
			X(c, " <tr id=\"%02x%02x%02x%02x%02x%02x\">\n",
					sta->mac_address[0],sta->mac_address[1],sta->mac_address[2],
					sta->mac_address[3],sta->mac_address[4],sta->mac_address[5]
				);

			/*
			 * station
			 */
			X(c, "  <td id=\"station\" class=\"station\"><a href=\"/station/%02x%02x%02x%02x%02x%02x.html\">[%02x:%02x:%02x:%02x:%02x:%02x]</a></td>\n",
					sta->mac_address[0],sta->mac_address[1],sta->mac_address[2],
					sta->mac_address[3],sta->mac_address[4],sta->mac_address[5],
					sta->mac_address[0],sta->mac_address[1],sta->mac_address[2],
					sta->mac_address[3],sta->mac_address[4],sta->mac_address[5]
					);
	        X(c, "  <td id=\"stamanuf\" class=\"stamanuf\">%s</td>\n", manuf_from_mac(sta->mac_address));

			/*
			 * Power
			 */
			if (sta->dbm)
				X(c, "  <td id=\"power\" class=\"power\">%s</td>\n", format_signed(sta->dbm,buf,sizeof(buf)));
			else
				X(c, "  <td id=\"power\" class=\"power\"></td>\n");

			/*
			 * Data
			 */
			X(c, "  <td id=\"dataout\" class=\"dataout\">%s</td>\n", format_unsigned(sta->data_sent,buf,sizeof(buf)));
			X(c, "  <td id=\"datain\"  class=\"datain\" >%s</td>\n", format_unsigned(sta->data_received,buf,sizeof(buf)));
			X(c, "  <td id=\"ctrlout\" class=\"ctrlout\">%s</td>\n", format_unsigned(sta->ctrl_sent,buf,sizeof(buf)));
			X(c, "  <td id=\"ctrlin\"  class=\"ctrlin\" >%s</td>\n", format_unsigned(sta->ctrl_received,buf,sizeof(buf)));

			/*
			 * Info
			 */
			X(c, "  <td id=\"info\" class=\"info\">");
            //system_logo(c, sta);
			{
				struct NVPair *nv;

				for (nv = sta->data; nv; nv = nv->next) {
					X(c, "%s:%s ", nv->name, nv->value);
				}
			}
			X(c, "</td>\n");


			

			X(c, " </tr>\n");
		}
	X(c, "</table>\n");

	X(c,	"</body>\n"
			"</html>\n"
			);

_return:
	pixie_leave_critical_section(sqdb->cs);
}


