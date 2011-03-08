#include "sqdb/sqdb2.h"
#include "pixie.h"
#include "mongoose.h"
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include "display.h"

/*===========================================================================
 *===========================================================================*/
void
xml_decode_eventpkt(struct mg_connection *c, const struct mg_request_info *ri, void *user_data)
{
	struct SQDB *sqdb = (struct SQDB*)user_data;
	unsigned char bssid[6];
	struct SquirrelPacket pkt[1];
	unsigned i;

	pixie_enter_critical_section(sqdb->cs);

	if (memcmp(ri->uri, "/eventpkt/", 8) != 0) {
		mg_printf(c, "404 Not Found\r\nConnection: closed\r\n\r\n");
		goto _return;
	}

	/*
	 * Lookup this BSSID entry
	 */
	{
		unsigned is_found;
		
		parse_mac_address(bssid, sizeof(bssid), ri->uri+strlen("/beacon/"));
		is_found = sqdb_get_bssid_packet(sqdb, bssid, SQPKT_BEACON, pkt);
		if (!is_found) {
			mg_printf(c, "404 Not Found\r\nConnection: closed\r\n\r\n");
			goto _return;
		}
	}

	mg_headers_ok(c, "text/xml");
	X(c, "Connection: close\r\n");
	X(c, "\r\n");

	X(c, "<?xml version=\"1.0\" ?>\n");
	X(c, "<packet"); 
	X(c, " id=\"%02x%02x%02x%02x%02x%02x\"",
					bssid[0],bssid[1],bssid[2],
					bssid[3],bssid[4],bssid[5]
					);
	X(c, " timestamp=\"%u\" ", pkt->secs);
	X(c, " microseconds=\"%u\" ", pkt->usecs);
	X(c, " length=\"%u\" ", pkt->length);
	X(c, ">\n");
	for (i=0; i<pkt->length; i++) {
		X(c, " %02x", pkt->px[i]);
		if ((i%8) == 7)
			X(c, " ");
		if ((i%16) == 15)
			X(c, "\n");
	}
	if ((i%16) != 15)
		X(c, "\n");
	X(c, "</packet>\n");
_return:
	pixie_leave_critical_section(sqdb->cs);
}


const char *
get_station_name(struct SQDB_SubStation *sta)
{
    struct NVPair *nv;

    for (nv = sta->data; nv; nv = nv->next) {
        if (strcmp(nv->name, "name")==0)
            return nv->value;
    }
    return NULL;
}


/*===========================================================================
 *===========================================================================*/
void
display_decode_eventpkt(struct mg_connection *c, const struct mg_request_info *ri, void *user_data)
{
	struct SQDB *sqdb = (struct SQDB*)user_data;
    unsigned char bssid[6] = {0,0,0,0,0,0};
	struct SquirrelPacket pkt[1];
	unsigned i;
    unsigned event_id;
    struct SQDB_Event *event;
    unsigned max_packets;

	pixie_enter_critical_section(sqdb->cs);

	if (memcmp(ri->uri, "/eventpkt/", 10) != 0) {
		mg_printf(c, "404 Not Found\r\nConnection: closed\r\n\r\n");
		goto _return;
	}

	/*
	 * Lookup this EVENT entry
	 */
    event_id = atoi(ri->uri+strlen("/eventpkt/"));
    for (event=sqdb->events; event; event = event->next) {
        if (event->event_id == event_id)
            break;
    }
	if (!event) {
		mg_printf(c, "404 Not Found\r\nConnection: closed\r\n\r\n");
		goto _return;
	}


    /*
     * Find the first packet
     */
    memset(pkt, 0, sizeof(*pkt));
    for (i=0; i<sizeof(event->packets)/sizeof(event->packets[0]); i++) {
        if (event->packets[i].buffer != 0) {
            pkt->length = event->packets[i].captured_length;
            pkt->px = (unsigned char*)event->packets[i].buffer;
            pkt->secs = event->packets[i].secs;
            pkt->usecs = event->packets[i].usecs;
            pkt->linktype = event->packets[i].linktype;
            break;
        }
    }

	if (!pkt->length) {
		mg_printf(c, "404 Not Found\r\nConnection: closed\r\n\r\n");
		goto _return;
	}

	mg_headers_ok(c, "text/html");
	X(c, "Connection: close\r\n");
	X(c, "\r\n");

	X(c,"<html>\n");
	X(c,"<head>\n");
	X(c," <title>WireDolphin</title>\n");
	X(c," <link rel=\"stylesheet\" type=\"text/css\" href=\"../decoder.css\" />\n");
	X(c," <link rel=\"Shortcut Icon\" href=\"../decoder.ico\" type=\"image/x-icon\">\n");
	X(c," <script type=\"text/javascript\" src=\"../decoder.js\"></script>\n");
	X(c, "<script type=\"text/javascript\">\nvar bssid_item_address = '%02x%02x%02x%02x%02x%02x';\n",
					bssid[0],bssid[1],bssid[2],
					bssid[3],bssid[4],bssid[5]
		);
    X(c, "var macnames = {\n \"ff:ff:ff:ff:ff:ff\": \"Broadcast\"");
    if (event->ap) {
        if (event->ap->ssid.length) {
            const unsigned char *mac = event->ap->bssid;
            X(c, ",\n \"%02x:%02x:%02x:%02x:%02x:%02x\": \"%.*s\"",
					mac[0],mac[1],mac[2],
					mac[3],mac[4],mac[5],
                    event->ap->ssid.length,
                    event->ap->ssid.value);
        }
    }
    if (event->sta) {
        const char *name = get_station_name(event->sta);
        if (name && name[0]) {
            const unsigned char *mac = event->sta->mac_address;
            char defanged[64];
            defang_ssid(defanged, sizeof(defanged), name, strlen(name));
            
            X(c, ",\n \"%02x:%02x:%02x:%02x:%02x:%02x\": \"%s\"",
					mac[0],mac[1],mac[2],
					mac[3],mac[4],mac[5],
                    defanged);
        }
    }
    X(c, "\n}\n");
	X(c, "</script>\n");
	X(c,"</head>\n");
	X(c,"<body>\n");

    
    
    
    
    
    /* 
     * Dump the packet contents
     */
    X(c, "<div id=\"packetlist\">\n");
    max_packets = sizeof(event->packets)/sizeof(event->packets[0]);
    for (i=0; i<max_packets; i++) {
	    struct SquirrelPacket pkt[1];
        unsigned j;
        char sz_time[64];
        struct tm *mytm;

        if (event->packets[i].buffer == 0)
            continue;

        /*
         * JavaScrpt date format that it will parse is;
         * month day, year hours:minutes:seconds
         */
        mytm = gmtime(&event->packets[i].secs);
   		strftime(sz_time, sizeof(sz_time), "%B %d, %Y %H:%M:%S GMT", mytm);

        memset(pkt, 0, sizeof(*pkt));
        pkt->length = event->packets[i].captured_length;
        pkt->px = (unsigned char*)event->packets[i].buffer;
        pkt->secs = event->packets[i].secs;
        pkt->usecs = event->packets[i].usecs;
        pkt->linktype = event->packets[i].linktype;


        if (pkt->linktype == 127) {
            /* Strip radiotap headers */
            if (pkt->length > 4) {
                unsigned header_length = pkt->px[2] + pkt->px[3]*256;
                if (header_length < pkt->length) {
                    pkt->px += header_length;
                    pkt->length -= header_length;
                    pkt->linktype = 0;
                }
            }
        }

	    X(c, "<div id=\"packetbytes\" timestamp=\"%s\" linktype=\"%u\">\n", sz_time, pkt->linktype);
	    for (j=0; j<pkt->length; j++) {
		    X(c, " %02x", pkt->px[j]);
		    if ((j%16) == 7)
			    X(c, " &nbsp;");
		    if ((j%16) == 15)
			    X(c, "<br/>\n");
	    }
	    if ((j%16) != 15)
		    X(c, "\n");
	    X(c, "</div>\n");
    }
	X(c, "</div>\n");

    
    
    
    
    
    
    
    /*
     * Three pane display
     */
    X(c, "<table id=\"threepane\" class=\"threepane\">\n"
		 " <tr><td><div id=\"summary\"></div></td></tr>\n");
	X(c, " <tr><td><div id=\"details\"></div></td></tr>\n");
	X(c, " <tr>\n"
		 " <td>\n"
		 " <table class=\"hexpane\"><tr><td><div id=\"hexindex\">\n");
	X(c, " </div></td>\n");
	X(c, "  <td>\n"
		 "  <div id=\"hexbytes\">\n");
	X(c, "  </div>\n"
		 "  </td>\n");
	X(c, "  <td>\n   <div id=\"hexdatachars\" onmousedown=\"show_coords(event)\">");
	X(c, "  </div></td></tr></table>\n </td>\n");
	X(c, " </tr>\n"
		 "</table>\n");
	X(c, "<script type=\"text/javascript\">run_decode()</script>\n");
	X(c,	"</body>\n"
			"</html>\n"
			);
_return:
	pixie_leave_critical_section(sqdb->cs);
}



