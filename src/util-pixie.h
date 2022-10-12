#ifndef PIXIE_H
#define PIXIE_H
#include <stddef.h>

typedef void (*PIXIE_FUNCTION)(void);

/* WIN32: LoadLibrary()
 * LINUX: dlopen() */
void *pixie_load_library(const char *library_name);

/* WIN32: GetProcAddress()
 * LINUX: dlsym() */
PIXIE_FUNCTION pixie_get_proc_symbol(void *library, const char *symbol);

void pixie_sleep(unsigned milliseconds);
void pixie_delete_critical_section(void *cs);
void pixie_close_thread(ptrdiff_t thread_handle);
void pixie_end_thread(void);
ptrdiff_t pixie_begin_thread(void (*worker_thread)(void*), unsigned flags, void *worker_data);
void *pixie_initialize_critical_section(void);
void pixie_leave_critical_section(void *cs);
void pixie_enter_critical_section(void *cs);
void pixie_lower_thread_priority(void);

/**
 * Retrieve the 6-byte MAC address of the local computer. This is
 * complicated by the fact that there is no robust API on systems to
 * get this address. The reason there is no simple method is that
 * computers may not have a network card at all, and thus no MAC address.
 * For example, a computer that connects via Bluetooth or dialup will
 * not have a MAC address. Another complication is that a computer may have
 * more than one network card, such as an Ethernet card and a WiFi card.
 */
unsigned pixie_get_mac_address(unsigned char macaddr[6]);

/**
 * WIN32: GetComputerName()
 * LINUX: get_host_name()
 */
unsigned pixie_get_host_name(char *name, unsigned name_size);


#endif
