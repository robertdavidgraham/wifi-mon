#include "../squirrel.h"
#include "mongoose.h"
#include "pcaplive.h"
#include "pixie.h"
#include "display.h"
#include "sprintf_s.h"
#include <ctype.h>
#include <stdlib.h>
#include <string.h>


extern struct PCAPLIVE pcap;
extern pcap_if_t *alldevs;

/*===========================================================================
 *===========================================================================*/
void
change_adapter_status(struct mg_connection *c, const struct mg_request_info *ri, void *user_data)
{
	struct Squirrel *squirrel = (struct Squirrel *)user_data;
	char *status = mg_get_var(c, "status");
	char *channel = mg_get_var(c, "channel");
	char *adapter_name = mg_get_var(c, "if");
	unsigned interface_channel = 0;

	if (status && channel && adapter_name) {
		unsigned is_running = squirrel_get_interface_status(squirrel, adapter_name, &interface_channel);
		unsigned new_channel;
		if (strcmp(channel, "scan") == 0)
			new_channel = (unsigned)-1;
		else if (isdigit(channel[0]))
			new_channel = atoi(channel);
		else
			new_channel = 0;

		if (is_running && strcmp(status, "monitor") != 0) {
			/* Turn off the adapter */
			squirrel_set_interface_status(squirrel, adapter_name, 0, 0);
			X(c, "<b>Turned off adapter</b>\n");
		} else if (!is_running && strcmp(status, "monitor") == 0) {
			launch_thread(squirrel, adapter_name);
			squirrel_set_interface_status(squirrel, adapter_name, 1, new_channel);
			X(c, "<b>Turned on adapter, channel %u</b>\n", new_channel);
		} else if (is_running && interface_channel != new_channel) {
			squirrel_set_interface_status(squirrel, adapter_name, 1, new_channel);
			X(c, "<b>Changed channel to %u</b>\n", new_channel);
		} else
			X(c, "<b>Nothing changed</b>\n");
	}
	if (status)
		free(status);
	if (channel)
		free(channel);
}

/*===========================================================================
 *===========================================================================*/
void
display_adapters(struct mg_connection *c, const struct mg_request_info *ri, void *user_data)
{
	struct Squirrel *squirrel = (struct Squirrel *)user_data;
	char errbuf[1024];
	unsigned interface_channel = 0;
	char *action = mg_get_var(c, "action");

	pixie_enter_critical_section(squirrel->cs);

	/* If a CGI request was sent to change an adapter status, then do that change */
	if (action) {
		; //change_adapter_status(
    }
    
	mg_headers_ok(c, "text/html");
	X(c, "Connection: close\r\n");
	X(c, "\r\n");

	//X(c, "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\" \"http://www.w3.org/TR/html4/strict.dtd\">\r\n");
	X(c,"<html>\n");
	X(c,"<head>\n");
	X(c," <title>Squirrel WiFi monitor / Adapters</title>\n");
	X(c," <link rel=\"stylesheet\" type=\"text/css\" href=\"squirrel.css\" />\n");
	X(c," <link rel=\"Shortcut Icon\" href=\"favicon.ico\" type=\"image/x-icon\">\n");
	X(c,"</head>\n");
	X(c,"<body>\n");


	display_topmenu(c, ri, user_data, 0);

	if (!pcap.is_available) {
		X(c, "<h1>ERROR: no libpcap</h1>\n");
		X(c, " On Unix, install libpcap from tcpdump site. On Windows, instal WinPcap from WinDump site.\n");
		goto _return;
	} else if (pcap.findalldevs(&alldevs, errbuf) == -1) {
		X(c, "<h1>ERROR: no adapters found</h1>\n");
		X(c, "<p>%s</p>\n", errbuf);
		X(c, "<p>Make sure you have root/administrator privileges</p>\n");
		goto _return;
	} else if (alldevs == NULL) {
		X(c, "<h1>ERROR: no adapters found</h1>\n");
		X(c, "<p>Make sure you have root/administrator privileges</p>\n");
		goto _return;
	} else {
		pcap_if_t *d;
		unsigned i=0;

		/* Print the list */
		X(c, "<table class=\"bssids\">\n");
		X(c, " <tr><th>Index</th><th>Name</th><th>Driver</th><th>Description</th><th>Monitor</th><th>Channel</th></tr>\n");
		for(d=alldevs; d; d=d->next)
		{
			const char *driver = "";
			if (strstr(d->name, "\\airpcap")) {
				driver = "airpcap";
			} else {
				driver = "airpcap";
			}
			++i;
			X(c, " <tr>\n");
			X(c, "  <td class=\"index\"><a href=\"monitor.php?index=%d\">%d</a></td>\n", i, i);
			X(c, "  <td><a href=\"adapter/%s.html\">%s</td>\n", d->name, d->name);
			if (strstr(d->name, "\\airpcap")) {
				X(c, "  <td>airpcap</td>\n\n");  
			} else {
				X(c, "  <td>ndis</td>\n");  
			}
			if (d->description)
				X(c, "  <td>%s</td>\n", d->description);
			else
				X(c, "  <td>%s</td>\n", "");
	
			if (squirrel_get_interface_status(squirrel, d->name, &interface_channel)) {
				X(c, "  <td id=\"status\">"
						"<form action=\"/adapters.html\">"
						"<input type=\"hidden\" name=\"adapter\" value=\"%s\">"
						"<input type=\"submit\" name=\"action\" value=\"Stop\">"
						"</form></td>\n", d->name);
				if (interface_channel == 0)
					X(c, "  <td id=\"channel\">%s</td>\n", "");
				else if (interface_channel == (unsigned)-1)
					X(c, "  <td id=\"channel\">%s</td>\n", "scan");
				else
					X(c, "  <td id=\"channel\">%u</td>\n", interface_channel);

			} else {
				X(c, "  <td id=\"status\">"
						"<form action=\"/adapters.html\">"
						"<input type=\"hidden\" name=\"adapter\" value=\"%s\">"
						"<input type=\"submit\" name=\"action\" value=\"Start\">"
						"</form></td>\n", d->name);
					X(c, "  <td id=\"channel\">%s</td>\n", "");
			}

		}
		X(c, "</table>\n");
	}
_return:
	pixie_leave_critical_section(squirrel->cs);
}


unsigned adapter_description(const char *adapter_name, char *description, unsigned description_name)
{
	char errbuf[1024];
	if (!pcap.is_available) {
		return 0;
	} else if (pcap.findalldevs(&alldevs, errbuf) == -1) {
		return 0;
	} else if (alldevs == NULL) {
		return 0;
	} else {
		pcap_if_t *d;

		for(d=alldevs; d; d=d->next)
		{
			if (strcmp(d->name, adapter_name) == 0) {
				sprintf_s(description, description_name, "%s", d->description);
				return 1;
			}
		}
	}
	return 0;
}

unsigned can_monitor_mode(const char *adapter_name)
{
	if (strstr(adapter_name, "\\airpcap"))
		return 1;
	else
		return 0;
}
unsigned can_transmit(const char *adapter_name)
{
	return pcap.can_transmit(adapter_name);
}


/*===========================================================================
 *===========================================================================*/
void
display_adapter(struct mg_connection *c, const struct mg_request_info *ri, void *user_data)
{
	struct Squirrel *squirrel = (struct Squirrel *)user_data;
	char adapter_name[256];
	char description[256];
	unsigned exists;
	const char *driver = "";
	unsigned interface_channel = 0;

	pixie_enter_critical_section(squirrel->cs);

	if (memcmp(ri->uri, "/adapter/", 9) != 0) {
		mg_printf(c, "404 Not Found\r\nConnection: closed\r\n\r\n");
		goto _return;
	} else
		sprintf_s(adapter_name, sizeof(adapter_name), "%s", ri->uri+9);

	if (strlen(adapter_name) > 5 && memcmp(adapter_name+strlen(adapter_name)-5, ".html", 5) == 0)
		adapter_name[strlen(adapter_name)-5] = '\0';
	if (strlen(adapter_name) > 7 && memcmp(adapter_name, "airpcap", 7) == 0 && strlen(adapter_name) < sizeof(adapter_name)-5) {
		memmove(adapter_name+4, adapter_name, strlen(adapter_name)+1);
		memcpy(adapter_name, "\\\\.\\", 4);
	}

	exists = adapter_description(adapter_name, description, sizeof(description));
	if (!exists) {
		mg_printf(c, "404 Not Found\r\nConnection: closed\r\n\r\n");
		goto _return;
	}
	if (strstr(adapter_name, "\\airpcap")) {
		driver = "airpcap";
	} else {
		driver = "ndis";
	}

	mg_headers_ok(c, "text/html");
	X(c, "Connection: close\r\n");
	X(c, "\r\n");

	//X(c, "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\" \"http://www.w3.org/TR/html4/strict.dtd\">\r\n");
	X(c,"<html>\n");
	X(c,"<head>\n");
	X(c," <title>Squirrel WiFi monitor / Adapter</title>\n");
	X(c," <link rel=\"stylesheet\" type=\"text/css\" href=\"../squirrel.css\" />\n");
	X(c," <link rel=\"Shortcut Icon\" href=\"../favicon.ico\" type=\"image/x-icon\">\n");
	X(c,"</head>\n");
	X(c,"<body>\n");

	display_topmenu(c, ri, user_data, 0);

	/*
	 * Do any necessary changes
	 */
	{
		char *status = mg_get_var(c, "status");
		char *channel = mg_get_var(c, "channel");

		if (status && channel) {
			unsigned is_running = squirrel_get_interface_status(squirrel, adapter_name, &interface_channel);
			unsigned new_channel;
			if (strcmp(channel, "scan") == 0)
				new_channel = (unsigned)-1;
			else if (isdigit(channel[0]))
				new_channel = atoi(channel);
			else
				new_channel = 0;

			if (is_running && strcmp(status, "monitor") != 0) {
				/* Turn off the adapter */
				squirrel_set_interface_status(squirrel, adapter_name, 0, 0);
				X(c, "<b>Turned off adapter</b>\n");
			} else if (!is_running && strcmp(status, "monitor") == 0) {
				launch_thread(squirrel, adapter_name);
				squirrel_set_interface_status(squirrel, adapter_name, 1, new_channel);
				X(c, "<b>Turned on adapter, channel %u</b>\n", new_channel);
			} else if (is_running && interface_channel != new_channel) {
				squirrel_set_interface_status(squirrel, adapter_name, 1, new_channel);
				X(c, "<b>Changed channel to %u</b>\n", new_channel);
			} else
				X(c, "<b>Nothing changed</b>\n");
		}
		if (status)
			free(status);
		if (channel)
			free(channel);
	}

	X(c, "<table class=\"adapter\">\n");
	X(c, "  <tr><th>Adapter:</th><td>%s</td></tr>\n", adapter_name);
	X(c, "  <tr><th>Description:</th><td>%s</td></tr>\n", description);
	X(c, "  <tr><th>Driver:</th><td>%s</td></tr>\n", driver);
	X(c, "  <tr><th>Monitor Mode:</th><td>%s</td></tr>\n", can_monitor_mode(adapter_name)?"yes":"no");
	X(c, "  <tr><th>Can Transmit:</th><td>%s</td></tr>\n", can_transmit(adapter_name)?"yes":"no");


	if (squirrel_get_interface_status(squirrel, adapter_name, &interface_channel)) {
		X(c, "  <tr><th>Status:</th><td>%s</td></tr>\n", "monitoring");
		if (interface_channel == 0)
			X(c, "  <tr><th>Channel:</th><td>%s</td></tr>\n", "");
		else if (interface_channel == (unsigned)-1)
			X(c, "  <tr><th>Channel:</th><td>%s</td></tr>\n", "scan");
		else
			X(c, "  <tr><th>Channel:</th><td>%u</td></tr>\n", interface_channel);

	} else {
		X(c, "  <tr><th>Status:</th><td>%s</td></tr>\n", "off");
		X(c, "  <tr><th>Channel:</th><td>%s</td></tr>\n", "");
	}
	X(c, "</table>\n");

	X(c, "<hr/>\n");
	X(c, "<form action=\"%s.html\">\n", adapter_name);
	X(c, " <input type=\"radio\" name=\"status\" value=\"monitor\" /> Monitor<br/>\n");
	X(c, " <input type=\"radio\" name=\"status\" value=\"off\" /> Off<br/>\n");
	X(c, " Channel: <input type=\"text\" name=\"channel\" value=\"scan\"/><br/>\n");
	X(c, " <input type=\"submit\" value=\"Submit\">\n");
	X(c, "</form>\n");

_return:
	pixie_leave_critical_section(squirrel->cs);
}
