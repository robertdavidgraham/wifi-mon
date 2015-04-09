/*
	Portable APIs modeled after Linux/Windows APIs
*/
#if defined linux || defined __linux || defined __linux__
#define _GNU_SOURCE
#endif

#include "pixie.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>


#if defined(WIN32)
#include <windows.h>
#include <process.h>
#include <rpc.h>
#include <rpcdce.h>
#pragma comment(lib,"rpcrt4.lib")
#elif defined(__GNUC__)
#include <unistd.h>
#include <pthread.h>
#include <dlfcn.h>
#ifdef __linux__
#include <sched.h>
#endif
#else
#error unknown environment
#endif

#ifndef UNUSEDPARM
#define UNUSEDPARM(x)
#endif

/*===========================================================================
 * IPHLPAPI.H (IP helper API)
 *	This include file is not included by default with Microsoft's compilers,
 *	but requires a seperate download of their SDK. In order to make
 *	compiling easier, we are going to copy the definitions from that file
 *	directly into this file, so that the header file isn't required.
 *===========================================================================*/
#if defined(WIN32) && !defined(__IPHLPAPI_H__)
/* __IPHLPAPI_H__ is the mutual-exclusion identifier used in the
 * original Microsoft file. We are going to use the same identifier here
 * so that if the programmer chooses, they can simply include the 
 * original file up above, and these definitions will automatically be
 * excluded. */
#define MAX_ADAPTER_DESCRIPTION_LENGTH  128
#define MAX_ADAPTER_NAME_LENGTH         256
#define MAX_ADAPTER_ADDRESS_LENGTH      8
#define DEFAULT_MINIMUM_ENTITIES        32
#define MAX_HOSTNAME_LEN                128
#define MAX_DOMAIN_NAME_LEN             128
#define MAX_SCOPE_ID_LEN                256
typedef struct {
    char String[4 * 4];
} IP_ADDRESS_STRING, *PIP_ADDRESS_STRING, IP_MASK_STRING, *PIP_MASK_STRING;
typedef struct _IP_ADDR_STRING {
    struct _IP_ADDR_STRING* Next;
    IP_ADDRESS_STRING IpAddress;
    IP_MASK_STRING IpMask;
    DWORD Context;
} IP_ADDR_STRING, *PIP_ADDR_STRING;
typedef struct _IP_ADAPTER_INFO {
    struct _IP_ADAPTER_INFO* Next;
    DWORD ComboIndex;
    char AdapterName[MAX_ADAPTER_NAME_LENGTH + 4];
    char Description[MAX_ADAPTER_DESCRIPTION_LENGTH + 4];
    UINT AddressLength;
    BYTE Address[MAX_ADAPTER_ADDRESS_LENGTH];
    DWORD Index;
    UINT Type;
    UINT DhcpEnabled;
    PIP_ADDR_STRING CurrentIpAddress;
    IP_ADDR_STRING IpAddressList;
    IP_ADDR_STRING GatewayList;
    IP_ADDR_STRING DhcpServer;
    BOOL HaveWins;
    IP_ADDR_STRING PrimaryWinsServer;
    IP_ADDR_STRING SecondaryWinsServer;
    time_t LeaseObtained;
    time_t LeaseExpires;
} IP_ADAPTER_INFO, *PIP_ADAPTER_INFO;


typedef DWORD (WINAPI *GETADAPTERSINFO)(PIP_ADAPTER_INFO pAdapterInfo, PULONG pOutBufLen);
typedef DWORD (WINAPI *GETBESTINTERFACE)(DWORD ip_address, DWORD *r_interface_index);

DWORD WINAPI
GetAdaptersInfo(PIP_ADAPTER_INFO pAdapterInfo, PULONG pOutBufLen)
{
	static GETADAPTERSINFO xGetAdaptersInfo;

	if (xGetAdaptersInfo == 0) {
		void *h = pixie_load_library("iphlpapi.dll");
		if (h == NULL) {
			fprintf(stderr, "PIXIE: LoadLibrary(iphlpapi.dll) failed %d\n", GetLastError());
			return GetLastError(); 
		}
		xGetAdaptersInfo = (GETADAPTERSINFO)GetProcAddress(h, "GetAdaptersInfo");
		if (xGetAdaptersInfo == NULL) {
			fprintf(stderr, "PIXIE: GetProcAddress(iphlpapi.dll/%s) failed %d\n", "GetAdaptersInfo", GetLastError());
			return GetLastError();
		}
	}

	return xGetAdaptersInfo(pAdapterInfo, pOutBufLen);
}

DWORD WINAPI
GetBestInterface(DWORD  dwDestAddr, DWORD  *pdwBestIfIndex) 
{
	static GETBESTINTERFACE xGetBestInterface;
	if (xGetBestInterface == 0) {
		void *h = pixie_load_library("iphlpapi.dll");
		if (h == NULL) {
			fprintf(stderr, "PIXIE: LoadLibrary(iphlpapi.dll) failed %d\n", GetLastError());
			return GetLastError(); 
		}
		xGetBestInterface = (GETBESTINTERFACE)GetProcAddress(h, "GetBestInterface");
		if (xGetBestInterface == NULL) {
			fprintf(stderr, "PIXIE: GetProcAddress(iphlpapi.dll/%s) failed %d\n", "GetBestInterface", GetLastError());
			return GetLastError();
		}
	}

	return xGetBestInterface(dwDestAddr, pdwBestIfIndex);
}


#endif

/**
 * Load a dynamic link library. By loading this manually with code,
 * we can catch errors when the library doesn't exist on the system.
 * We can also go hunting for the library, or backoff and run without
 * that functionality. Otherwise, in the normal method, when the
 * operating system can't find the library, it simply refuses to run
 * our program
 */
void *pixie_load_library(const char *library_name)
{
#ifdef WIN32
	return LoadLibraryA(library_name);
#else
	return dlopen(library_name,0);
#endif
}


/**
 * Retrieve a symbol from a library returned by "pixie_load_library()"
 */
PIXIE_FUNCTION pixie_get_proc_symbol(void *library, const char *symbol)
{
#ifdef WIN32
	return (PIXIE_FUNCTION)GetProcAddress(library, symbol);
#else
	/* ISO C doesn't allow us to cast a data pointer to a function
	 * pointer, therefore we have to cheat and use a union */
	union {
		void *data;
		PIXIE_FUNCTION func;
	} result;
	result.data = dlsym(library, symbol);
	return result.func;
#endif
}


/**
 * Retrieve the MAC address of the system
 */
unsigned pixie_get_mac_address(unsigned char macaddr[6])
{
	memset(macaddr, 0, 6);
#ifdef WIN32
	{
		DWORD dwStatus;
		IP_ADAPTER_INFO *p;
		IP_ADAPTER_INFO AdapterInfo[16];
		DWORD dwBufLen = sizeof(AdapterInfo);
		DWORD interface_index = -1;

		GetBestInterface(0x01010101, &interface_index);
		
		dwStatus = GetAdaptersInfo(AdapterInfo, &dwBufLen);
		if (dwStatus != ERROR_SUCCESS)
			  return 1;

		for (p=AdapterInfo; p; p = p->Next) {

			if (p->Index == interface_index || interface_index == -1) {
				memcpy(macaddr, p->Address, 6);
				return 0;
			}
			/*(
			printf("[%02x:%02x:%02x:%02x:%02x:%02x]\n",
			mac_address[0], mac_address[1], mac_address[2], 
			mac_address[3], mac_address[4], mac_address[5]
			);
			printf("    %s\n", p->AdapterName);
			printf("    %s\n", p->Description);
			printf("    IP: ");
			for (a = &p->IpAddressList; a; a = a->Next) {
				printf("%s ", a->IpAddress.String);
			}
			printf("\n");
			*/
		}
	}
#else
	return -1;
#endif
	return -1;
}


/**
 * Retrieve the name of the system. 'name_size' is size of the buffer pointed
 * to by 'name'.
 * Returns the length of the name.
 */
unsigned pixie_get_host_name(char *name, unsigned name_size)
{
#ifdef WIN32
	/*
	BOOL WINAPI GetComputerName(
	  __out    LPTSTR lpBuffer,
	__inout  LPDWORD lpnSize
	);
	Return Value: If the function succeeds, the return value is a nonzero value.
	The variable 'lpnsize' must be set to the length of the number of
	bytes in the string, and it be set to the resulting length */
	if (GetComputerNameA(name, &name_size))
		return name_size;
	else
		return 0;
#else
	/*
	int gethostname(char *name, size_t namelen)
	'namelen' is the size of the 'name' buffer.
	Returns 0 on success, -1 on failure
	*/
	if (gethostname(name, name_size) == 0) {
		/* If the buffer is too small, it might not nul terminate the
		 * string, so let's guarantee a nul-termination */
		name[name_size-1] = '\0';
		return name_size;
	} else
		return 0;
#endif
}



void pixie_lower_thread_priority()
{
#if defined(WIN32) && defined(_MT)
    SetThreadPriority(GetCurrentThread(),THREAD_PRIORITY_BELOW_NORMAL);
    SetThreadPriorityBoost(GetCurrentThread(), 1);
#elif defined(__GNUC__)
	/* Todo */
#else
#error pixie_lower_thread_priority undefimed
#endif
}


void pixie_raise_thread_priority()
{
#if defined(WIN32) && defined(_MT)
    SetThreadPriority(GetCurrentThread(),THREAD_PRIORITY_ABOVE_NORMAL);
    SetThreadPriorityBoost(GetCurrentThread(), 1);
#elif defined(__GNUC__)
	/* Todo */
#else
#error pixie_raise_thread_priority undefimed
#endif
}

void pixie_enter_critical_section(void *cs)
{
    /* check for null, allows users to compile without Multithreading 
     * support */
    if (cs == NULL)
        return;

#if defined(WIN32) && defined(_MT)
    if (TryEnterCriticalSection(cs))
        return;
    else {
        EnterCriticalSection(cs);
    }
#elif defined(__GNUC__)
    pthread_mutex_lock(cs);
#else
#error pixie_enter_critical_section undefimed
#endif
}

void pixie_leave_critical_section(void *cs)
{
    /* check for null, allows users to compile without Multithreading 
     * support */
    if (cs == NULL)
        return;

#if defined(WIN32) && defined(_MT)
    LeaveCriticalSection(cs);
#elif defined(__GNUC__)
    pthread_mutex_unlock(cs);
#else
#error pixie_leave_critical_section undefimed
#endif
}

void *pixie_initialize_critical_section()
{
#if defined(WIN32) && defined(_MT)
    CRITICAL_SECTION *cs = (CRITICAL_SECTION*)malloc(sizeof(*cs));
    memset(cs, 0, sizeof(*cs));
    InitializeCriticalSection(cs);
    return cs;
#elif defined(__GNUC__)
	pthread_mutexattr_t attr;
	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_t *mutex = (pthread_mutex_t*)malloc(sizeof(*mutex));
    memset(mutex, 0, sizeof(*mutex));
    pthread_mutex_init(mutex, &attr);
    return mutex;
#else
#error pixie_initialize_critical_section undefimed
#endif
}

ptrdiff_t pixie_begin_thread(void (*worker_thread)(void*), unsigned flags, void *worker_data)
{
#if defined(WIN32) && defined(_MT)
	return _beginthread(worker_thread, 0, worker_data);
#elif defined(__GNUC__)
	typedef void *(*PTHREADFUNC)(void*);
	pthread_t thread_id;
	return pthread_create(&thread_id, NULL, (PTHREADFUNC)worker_thread, worker_data);
#else
#error pixie_begin_thread undefined
#endif
}


void pixie_close_thread(ptrdiff_t thread_handle)
{
#if defined(WIN32) && defined(_MT)
	CloseHandle((HANDLE)thread_handle);
#elif defined(__GNUC__)
#else
#error pixie_close_thread undefined
#endif
}


void pixie_end_thread()
{
#ifdef _MT
#ifdef WIN32
	_endthread();
#endif
#endif
}

void pixie_delete_critical_section(void *cs)
{
#ifdef _MT
#ifdef WIN32
	if (cs) {
		DeleteCriticalSection(cs);
		free(cs);
	}
#endif
#endif
}

void pixie_sleep(unsigned milliseconds)
{
#ifdef WIN32
	Sleep(milliseconds);
#else
	usleep(milliseconds*1000);
#endif
}

