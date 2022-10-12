#ifndef DISPLAY_H
#define DISPLAY_H

struct mg_connection;
struct mg_request_info;

void display_topmenu(struct mg_connection *c, const struct mg_request_info *ri, void *user_data, unsigned depth);

const char *format_unsigned(unsigned long long num, char *buf, unsigned buf_size);

const char *format_time_t(time_t num, char *buf, unsigned buf_size);

const char *format_signed(long long num, char *buf, unsigned buf_size);

void defang_ssid(char *defanged, size_t defanged_length, const char *ssid, unsigned ssid_length);

void display_report_title(struct mg_connection *c, const char *title, const char *refresh, unsigned depth);

struct SQDB_SubStation;
const char *get_station_name(struct SQDB_SubStation *sta);

#endif
