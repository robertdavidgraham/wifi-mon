#include "sqdb2.h"
#include "util-pixie.h"
#include "mongoose.h"
#include "disp-squirrel.h"
#include <string.h>
#include "pcap-manuf.h"
#include "util-annexk.h"
#include "disp-main.h"
#include "util-unused.h"

void
display_report_title(struct mg_connection *c, const char *title, const char *refresh, unsigned depth)
{
	char root[64];
	sprintf_s(root, sizeof(root), "%s%s%s%s", 
		(depth>=1)?"../":"", 
		(depth>=2)?"../":"", 
		(depth>=3)?"../":"", 
		(depth>=4)?"../" :"");

	//X(c, "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\" \"http://www.w3.org/TR/html4/strict.dtd\">\r\n");
	X(c,"<html>\n");
	X(c,"<head>\n");
	X(c," <title>Squirrel: %s</title>\n", title);
	X(c," <link rel=\"stylesheet\" type=\"text/css\" href=\"squirrel.css\" />\n");
	X(c," <link rel=\"Shortcut Icon\" href=\"favicon.ico\" type=\"image/x-icon\">\n");
	X(c," <script type=\"text/javascript\" src=\"squirrel.js\"></script>\n");
    X(c, "<script src=\"sorttable.js\"></script>\n");
	X(c,"</head>\n");
	X(c,"<body onLoad=\"setInterval(%s,1000)\">\n", refresh);

	X(c, "<table class=\"topmenu\">\n"
			"<tr>\n"
			" <td class=\"logo\"><img src=\"/logo.gif\" border=\"0\" width=\"30\" height=\"30\" alt=\"squirrel\" /></td>\n"
			" <td class=\"title\">%s</td>\n"
			" <td class=\"menu\">\n"
			"   <a href=\"/accesspoints.html\">Access-Points</a> | \n"
			"   <a href=\"/probers.html\">Probers</a> | \n"
			"   <a href=\"/events.html\">Events</a> | \n"
			"   <a href=\"/xmit.html\">Xmit</a> | \n"
			"   <a href=\"/adapters.html\">Config</a> | \n"
			"   <a href=\"http://squirrel.erratasec.com/help/\">Help</a>\n"
			" </td>\n"
			"</tr>\n"
			"</table>\n",
            title);
}

void
display_topmenu(struct mg_connection *c, const struct mg_request_info *ri, void *user_data, unsigned depth)
{
	/*struct SQDB *sqdb = (struct SQDB*)user_data;*/
	char root[64];

    UNUSEDPARM(ri);
    UNUSEDPARM(user_data);

	sprintf_s(root, sizeof(root), "%s%s%s%s", 
		(depth>=1)?"../":"", 
		(depth>=2)?"../":"", 
		(depth>=3)?"../":"", 
		(depth>=4)?"../" :"");
	X(c, "<table class=\"topmenu\">\n"
			"<tr>\n"
			" <td class=\"logo\"><img src=\"/logo.gif\" border=\"0\" width=\"30\" height=\"30\" alt=\"squirrel\" /></td>\n"
			" <td class=\"title\">squirrel 1.0</td>\n"
			" <td class=\"menu\">\n"
			"   <a href=\"/accesspoints.html\">Access-Points</a> | \n"
			"   <a href=\"/probers.html\">Probers</a> | \n"
			"   <a href=\"/events.html\">Events</a> | \n"
			"   <a href=\"/xmit.html\">Xmit</a> | \n"
			"   <a href=\"/adapters.html\">Config</a> | \n"
			"   <a href=\"http://squirrel.erratasec.com/help/\">Help</a>\n"
			" </td>\n"
			"</tr>\n"
			"</table>\n");
}

const char *
format_unsigned(unsigned long long num, char *buf, unsigned buf_size)
{
    if (num == 0)
        return "";
    else {
        sprintf_s(buf, buf_size, "%llu", num);
        return buf;
    }
}

const char *
format_time_t(time_t num, char *buf, unsigned buf_size)
{
    if (num == 0)
        return "";
    else {
        sprintf_s(buf, buf_size, "%llu", (unsigned long long)num);
        return buf;
    }
}

const char *
format_signed(long long num, char *buf, unsigned buf_size)
{
	if (num == 0)
		return "";
	else {
		sprintf_s(buf, buf_size, "%lld", num);
		return buf;
	}
}
