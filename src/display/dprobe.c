#include "../sqdb/sqdb2.h"
#include "pixie.h"
#include "mongoose.h"
#include <ctype.h>
#include <string.h>

/*===========================================================================
 *===========================================================================*/
void
xml_decode_probe(struct mg_connection *c, const struct mg_request_info *ri, void *user_data)
{
	struct SQDB *sqdb = (struct SQDB*)user_data;
	unsigned char bssid[6];
	struct SquirrelPacket pkt[10];
	unsigned i;
    unsigned count_found;

	pixie_enter_critical_section(sqdb->cs);

	if (memcmp(ri->uri, "/probe/", 7) != 0) {
		mg_printf(c, "404 Not Found\r\nConnection: closed\r\n\r\n");
		goto _return;
	}

	/*
	 * Lookup this MAC address entry
	 */
    parse_mac_address(bssid, sizeof(bssid), ri->uri+strlen("/probe/"));
    count_found = sqdb_get_prober_packets(sqdb, bssid, &pkt[0]);
    if (count_found == 0) {
        mg_printf(c, "404 Not Found\r\nConnection: closed\r\n\r\n");
        goto _return;
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




/*===========================================================================
 *===========================================================================*/
void
display_decode_probe(struct mg_connection *c, const struct mg_request_info *ri, void *user_data)
{
	struct SQDB *sqdb = (struct SQDB*)user_data;
	unsigned char bssid[6];
	struct SquirrelPacket pkt[11];
	unsigned i;
    unsigned count_found;
    
    
	if (strstr(ri->uri, ".xml")) {
		xml_decode_probe(c, ri, user_data);
		return;
	}


	pixie_enter_critical_section(sqdb->cs);

	if (memcmp(ri->uri, "/probe/", 7) != 0) {
		mg_printf(c, "404 Not Found\r\nConnection: closed\r\n\r\n");
		goto _return;
	}

	/*
	 * Lookup this BSSID entry
	 */
    parse_mac_address(bssid, sizeof(bssid), ri->uri+strlen("/probe/"));
    count_found = sqdb_get_prober_packets(sqdb, bssid, &pkt[0]);
    if (count_found == 0) {
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
    X(c, "\n}\n");
	X(c, "</script>\n");
	X(c,"</head>\n");
	X(c,"<body>\n");

    /* Dump the packet */
    X(c, "<div id=\"packetlist\">\n");
    for (i=0; i<count_found; i++) {
        char sz_time[64];
        struct tm *mytm;
        unsigned j;

        if (pkt[i].length == 0)
            continue;

        mytm = gmtime(&pkt[i].secs);
   		strftime(sz_time, sizeof(sz_time), "%B %d, %Y %H:%M:%S GMT", mytm);

	    X(c, "<div id=\"packetbytes\" timestamp=\"%s\">\n", sz_time, pkt[i].linktype);
	    for (j=0; j<pkt[i].length; j++) {
		    X(c, " %02x", pkt[i].px[j]);
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


	X(c, "<table id=\"threepane\" class=\"threepane\">\n"
		 " <tr><td><div id=\"summary\"></div></td></tr>\n");
	X(c, " <tr><td><div id=\"details\"></div></td></tr>\n");
	X(c, " <tr>\n"
		 " <td>\n"
		 " <table class=\"hexpane\"><tr><td><div id=\"hexindex\"\n");
	for (i=0; i<pkt->length; i += 16) {
		X(c, " %04x<br/>", i);
	}
	X(c, " </div></td>\n");
	X(c, "  <td>\n"
		 "  <div id=\"hexbytes\">\n");
	for (i=0; i<pkt->length; i++) {
		X(c, " %02x", pkt->px[i]);
		if ((i%16) == 7)
			X(c, "&nbsp;");
		if ((i%16) == 15)
			X(c, "<br/>\n");
	}
	if ((i%16) != 15)
		X(c, "\n");
	X(c, "  </div>\n"
		 "  </td>\n");
	X(c, "  <td>\n   <div id=\"hexdatachars\" onmousedown=\"show_coords(event)\">");
	for (i=0; i<pkt->length; i++) {
		if (isprint(pkt->px[i])) {
			if (pkt->px[i] == '<')
				X(c, "&lt;");
			else if (pkt->px[i] == '&')
				X(c, "&amp;");
			else
				X(c, "%c", pkt->px[i]);
		} else
			X(c, ".");
		if ((i%16) == 7)
			X(c, " ");
		if ((i%16) == 15)
			X(c, "<br/>\n");
	}
	if ((i%16) != 15)
		X(c, "\n");
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



