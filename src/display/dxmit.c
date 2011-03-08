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
xml_xmtpkt(struct mg_connection *c, const struct mg_request_info *ri, void *user_data)
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


/*===========================================================================
 *===========================================================================*/
void
display_decode_xmitpkt(struct mg_connection *c, const struct mg_request_info *ri, void *user_data)
{
	struct SQDB *sqdb = (struct SQDB*)user_data;
    /*unsigned char bssid[6] = {0,0,0,0,0,0};*/

	pixie_enter_critical_section(sqdb->cs);




	mg_headers_ok(c, "text/html");
	X(c, "Connection: close\r\n");
	X(c, "\r\n");

	X(c,"<html>\n");
	X(c,"<head>\n");
	X(c," <title>WireDolphin</title>\n");
	X(c," <link rel=\"stylesheet\" type=\"text/css\" href=\"../decoder.css\" />\n");
	X(c," <link rel=\"Shortcut Icon\" href=\"../decoder.ico\" type=\"image/x-icon\">\n");
	X(c," <script type=\"text/javascript\" src=\"../decoder.js\"></script>\n");
	X(c, "<script type=\"text/javascript\">\n");
    X(c, "var macnames = {\n \"ff:ff:ff:ff:ff:ff\": \"Broadcast\"");
    X(c, "\n}\n");
	X(c, "</script>\n");
	X(c,"</head>\n");
	X(c,"<body>\n");

    
    
    
    
    
    /* 
     * Dump the packet contents
     */
    X(c, "<div id=\"packetlist\">\n");
    {
        char sz_time[64];
        struct tm *mytm;
        time_t now = time(0);

        /*
         * JavaScrpt date format that it will parse is;
         * month day, year hours:minutes:seconds
         */
        mytm = gmtime(&now);
   		strftime(sz_time, sizeof(sz_time), "%B %d, %Y %H:%M:%S GMT", mytm);

	    X(c, "<div id=\"packetbytes\" timestamp=\"%s\">\n", sz_time);
X(c, "50 00 40 01 "
"00 1f 5b dc 15 1f 00 22 6b e2 54 c1 00 22 6b e2 "
"54 c1 e0 a4 f6 70 97 2e 16 00 00 00 64 00 21 04 "
"00 10 54 69 6c 74 65 64 20 4b 69 6c 74 20 57 69 "
"46 69 01 08 82 84 8b 96 0c 12 18 24 03 01 06 2a "
"01 00 32 04 30 48 60 6c"
);
	    X(c, "</div>\n");
    }
	X(c, "</div>\n");

    
    
    
    
    
    
    X(c, "<table><tr><td>\n");    
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
    
    X(c, "</td><td><form><div id=\"fieldname\">Field</div><input name=\"fieldvalue\" id=\"fieldvalue\" value=\"\" type=\"text\" /></td></tr>\n");
    X(c, "</table>\n");


	X(c, "<script type=\"text/javascript\">run_decode()</script>\n");
	X(c,	"</body>\n"
			"</html>\n"
			);

	pixie_leave_critical_section(sqdb->cs);
}



