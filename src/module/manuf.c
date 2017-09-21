#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sprintf_s.h"

struct Manufs {
    unsigned oui;
    char str[12];
    char *desc;
};

struct Manufs xmanufs[] = {
    {0x00026f,  "Senao     ", "Senao Wireless, access-point"}, /* access-point */
    {0x000278,  "Samsung   ", "Samsung Electro-Mechanics Co."},
    {0x000423,  "Intel     ", "Intel Centrino PRO/Wireless"},
    {0x000625,  "Linksys   ", "Linksys, access-point"},
    {0x00095b,  "Netgear   ", "Netgear, access-point"},
    {0x000992,  "InterEpoch", "InterEpoch, access-point"},
    {0x000fcc,  "Netopia   ", "Netopia, access-point"}, /* [00:0f:cc:7d:87:d0] access-point Qiznos */
    {0x000c41,  "Linksys(C)", "Linksys by Cisco, access-point"},
    {0x000cf1,  "Intel     ", "Intel Centrino PRO/Wireless"},/* [00:0c:f1:23:be:46] station: Windows Notebook */
    {0x000ded,  "Cisco     ", "Cisco Systems, access-point"},
    {0x000d72,  "2wire     ", "2Wire, access-point"},
    {0x000e38,  "Cisco     ", "Cisco Systems, access-point"},
    {0x000e83,  "Cisco     ", "Cisco Systems, access-point"},
    {0x000ae4,  "Wistron   ", "Wistron, station, notebook"},
    {0x000f3d,  "D-Link    ", "D-Link, access-point"},
    {0x000f66,  "Linksys(C)", "Linksys by Cisco, access-point"},
    {0x001121,  "Cisco     ", "Cisco Systems, access-point"},
    {0x001150,  "Belkin    ", "Belkin, access-point"},
/**/{0x0011d9,  "TiVo      ", "TiVo, digital video recorder, access-point"},
    {0x0011f5,  "Askey     ", "Askey Computer Corp"},
    {0x001217,  "Linksys(C)", "Linksys by Cisco, access-point"},
    {0x00120e,  "AboCom    ", "AboCom, access-point"},
    {0x00125a,  "Microsoft ", "Microsoft Corporation"}, /* [00:12:5a:aa:0a:68] station */
/**/{0x001279,  "-hp-      ", "Hewlett-Packard, station"},
    {0x001302,  "Intel     ", "Intel Centrino PRO/Wireless"},
    {0x001310,  "Linksys(C)", "Linksys by Cisco"},
    {0x001346,  "D-Link    ", "D-Link, access-point"},
    {0x001372,  "Dell      ", "Dell Inc."},
    {0x0013ce,  "Intel     ", "Intel Centrino PRO/Wireless"},
    {0x0013e8,  "Intel     ", "Intel Centrino PRO/Wireless"},/* [00:13:e8:65:a0:0b] station: Windows Notebook */
    {0x001451,  "Apple     ", "Apple MacBook"}, /* [00:14:51:7d:02:48] station: MacBook (white plastic) */
    {0x0014a4,  "Foxconn   ", "Hon Hai Precision, Windows Notebook"},	
    {0x0014a5,  "GemTek    ", "GemTek Technology Company"},
    {0x0014bf,  "Linksys(C)", "Linksys by Cisco, access-point"},
    {0x0014D1,  "TRENDware ", "TRENDware International, Inc."}, /* [00:14:d1:37:4e:fc] access-point: TRENDware */
/**/{0x001560,  "-hp-      ", "Hewlett-Packard, station"},
    {0x001562,  "Cisco     ", "Cisco Systems, access-point"},
    {0x00156d,  "Ubiquiti  ", "Ubiquiti Networks"},
    {0x0015af,  "AzureWave ", "AzureWave Technologies"},
    {0x001601,  "Buffalo   ", "Baffalo Inc., station"},
/**/{0x001635,  "-hp-      ", "Hewlett-Packard, station"},
    {0x0016b6,  "Linksys(C)", "Linksys by Cisco, access-point"},
    {0x0016cb,  "Apple     ", "Apple"},
    {0x0016ce,  "Foxconn   ", "Hon Hai Precision, Windows Notebook"},
    {0x00173f,  "Belkin    ", "Belkin, access-point"},
    {0x00179a,  "D-Link    ", "D-Link, access-point"},
    {0x0017c5,  "SonicWALL ", "SonicWALL, access-point"},
    {0x001802,  "Alpha Net ", "Alpha Networks"},
    {0x001839,  "Linksys(C)", "Linksys by Cisco, access-point"},
    {0x00183a,  "Westell   ", "Westell, access-point"},
    {0x00184d,  "Netgear   ", "Netgear, access-point"},
    {0x0018f3,  "ASUStek   ", "ASUStek, access-point"},
    {0x00195b,  "D-Link    ", "D-Link, access-point"},
    {0x0019aa,  "Cisco     ", "Cisco Systems, access-point"},
    {0x0019c5,  "Sony      ", "Sony Computer Entertainment Inc."},
    {0x0019d2,  "Intel     ", "Intel Centrino PRO/Wireless"},
    {0x0019e3,  "Apple     ", "Apple, access-point"},
    {0x001a70,  "Linksys(C)", "Linksys by Cisco, access-point"},
    {0x001a73,  "GemTek    ", "GemTek Technology Company"},
    {0x001b11,  "D-Link    ", "D-Link, access-point"},
    {0x001b2f,  "Netgear   ", "Netgear, access-point"},
    {0x001b9e,  "Askey     ", "Askey Computer Corp"},
    {0x001210,  "Linksys(C)", "Linksys by Cisco, access-point"},
    {0x001644,  "Lite-On   ", "Lite-On Computer Corporation"},
    {0x001c10,  "Linksys(C)", "Linksys by Cisco, access-point"},
    {0x001cb3,  "Apple     ", "Apple, access-point"},
    {0x001cbf,  "Intel     ", "Intel Centrino PRO/Wireless"},
    {0x001cf0,  "D-Link    ", "D-Link, access-point"},
    {0x001d7e,  "Linksys(C)", "Linksys by Cisco, access-point"},
    {0x001e13,  "Cisco     ", "Cisco Systems"}, /* [00:1e:13:42:d2:40] access-point: attwifi */
    {0x001e2a,  "Netgear   ", "Netgear, access-point"},
    {0x001e58,  "D-Link    ", "D-Link, access-point"},
    {0x001ee5,  "Linksys(C)", "Linksys by Cisco, access-point"},
    {0x001f33,  "Netgear   ", "Netgear, access-point"},
    {0x001f3b,  "Intel     ", "Intel Centrino PRO/Wireless, Sony Vaio?"},/* [00:1f:3b:02:72:03] station: Windows Notebook, Sony VAIO */
    {0x001f5B,  "Apple     ", "Apple MacBook? iPhone?"}, /* [00:1f:5b:dc:15:1f] station: MacBook Air, [00:1f:5b:5b:bf:77] iPhone*/
    {0x001fb3,  "2wire     ", "2Wire, access-point"},
    {0x001fc4,  "Netopia(M)", "Motorola Connected Home Solutions (CHS), Netopia access-point"}, /* [00:1f:c4:7a:47:80] access-point Royal Oak 1, Netopia 3347-02 */
    {0x001fe1,  "Foxconn   ", "Hon Hai Precision, Windows Notebook"},
/**/{0x002000,  "Lexmark   ", "Lexmark Printer"},
    {0x002100,  "GemTek    ", "GemTek, Motorola, access-point"},
/**/{0x002106,  "BLACKBERRY", "RIM Testing Services"},
    {0x002129,  "Linksys(C)", "Linksys by Cisco, access-point"},
    {0x00215a,  "-hp-      ", "Hewlett-Packard, printer?"},
    {0x00216b,  "Intel     ", "Intel Centrino PRO/Wireless"},
    {0x00217c,  "2wire     ", "2Wire, access-point"},
    {0x002191,  "D-Link    ", "D-Link, access-point"},
    {0x0021e9,  "AppleiPhon", "Apple iPhone?"}, /*[00:21:e9:6e:48:3c] iPhone */
    {0x00223f,  "Netgear   ", "Netgear, access-point"},
    {0x002241,  "AppleiPhon", "Apple, iPhone?"}, /*[00:22:41:16:a8:ff] iPhone */
    {0x002269,  "Foxconn   ", "Hon Hai Precision, Windows Notebook"},
    {0x00226b,  "Linksys(C)", "Linksys by Cisco, access-point"},
    {0x002275,  "Belkin    ", "Belkin, access-point"},
    {0x00227f,  "Ruckus    ", "Ruckus Wireless, Hotels/Education/Health/Warehouse/Branch, access-point"},
    {0x0022b0,  "D-Link    ", "D-Link"},
    {0x002312,  "AppleiPhon", "Apple iPhone"}, /* [00:23:12:d6:66:fe]  station: iPhone */
/**/{0x002331,  "Nintendo  ", "Nintendo"},
    {0x00234d,  "Foxconn   ", "Hon Hai Precision, Windows Notebook"},
    {0x00234e,  "Foxconn   ", "Hon Hai Precision, Windows Notebook"},
    {0x002351,  "2wire     ", "2Wire, access-point"},
    {0x002369,  "Linksys(C)", "Linksys by Cisco, access-point"},
    {0x00236c,  "Apple     ", "Apple iPhone? MacBook?"}, /* [00:23:6c:1b:bb:15] station: iPhone */
    {0x00237a,  "BLACKBERRY", "Research In Motion"},
    {0x0023df,  "Apple     ", "Apple"}, /* [00:23:df:21:12:fa] station: ?? */
    {0x002401,  "D-Link    ", "D-Link"},
/**/{0x002403,  "Nokia     ", "Nokia"},
/**/{0x002404,  "Nokia     ", "Nokia"},
    {0x00242b,  "Foxconn   ", "Hon Hai Precision, Windows Notebook"}, /*[00:25:56:20:56:86] station: WinXP notebook */	
    {0x00242c,  "Foxconn   ", "Hon Hai Precision, Windows Notebook"},
    {0x002436,  "Apple     ", "Apple MacBook"},
    {0x002437,  "Motorola  ", "Motorola BSG (Broadband Services Group), also BHS (Broadband Home Systems)"},
    {0x002450,  "Cisco     ", "Cisco Systems, access-point"},
    {0x002451,  "Cisco     ", "Cisco Systems, access-point"},
    {0x002456,  "2wire     ", "2Wire, access-point"},
/**/{0x00247c,  "Nokia     ", "Nokia"},
/**/{0x00247d,  "Nokia     ", "Nokia"},
    {0x002481,  "-hp-      ", "Hewlett-Packard"},
    {0x00248D,  "Sony      ", "Sony Computer Entertainment Inc."},
/**/{0x002490,  "Samsung   ", "Samsung"},
    {0x002493,  "Motorola  ", "Motorola, Netopia?"},
/**/{0x00249f,  "BLACKBERRY", "RIM Testing Services"},
    {0x0024b2,  "Netgear   ", "Netgear, access-point"},
    {0x0024c3,  "Cisco     ", "Cisco Systems, access-point"},
    {0x0024d2,  "Askey     ", "Askey Computer Corp"},
    {0x0024d6,  "Intel     ", "Intel Centrino PRO/Wireless"},
    {0x0024d7,  "Intel     ", "Intel Centrino PRO/Wireless"},
    {0x0024f7,  "Cisco     ", "Cisco Systems, access-point"},
    {0x002500,  "Apple     ", "Apple"},
    {0x00253c,  "2wire     ", "2Wire, access-point"},
    {0x002545,  "Cisco     ", "Cisco Systems, access-point"},
/**/{0x002547,  "Nokia     ", "Nokia"},
/**/{0x002548,  "Nokia     ", "Nokia"},
    {0x00254b,  "AppleiPhon", "Apple iPhone"},
    {0x002556,  "Foxconn   ", "Hon Hai Precision, Windows Notebook"}, /*[00:24:2b:70:86:78] station: WinXP notebook */	
    {0x002557,  "BLACKBERRY", "Research In Motion"},
/**/{0x002566,  "Samsung   ", "Samsung"},
/**/{0x002567,  "Samsung   ", "Samsung"},
    {0x002583,  "Cisco     ", "Cisco Systems, access-point"},
    {0x0025a0,  "Nintendo  ", "Nintendo, DS handheld?"},
    {0x0025b4,  "Cisco     ", "Cisco Systems, access-point"},
    {0x0025bc,  "AppleiPhon", "Apple iPhone"},
    {0x0025d3,  "AzureWave ", "AzureWave"},
/**/{0x0025CF,  "Nokia     ", "Nokia"},
    {0x002608,  "AppleiPhon", "Apple iPhone"},
/**/{0x002637,  "Samsung   ", "Samsung"},
    {0x00264a,  "AppleiPhon", "Apple iPhone"}, /* [00:26:4a:d8:f2:05] station: iPhone */
    {0x00264d,  "Arcadyan  ", "Arcadyan"},
    {0x00265e,  "Foxconn   ", "Hon Hai Precision, Windows Notebook"},
/**/{0x002668,  "Nokia     ", "Nokia"},
/**/{0x002669,  "Nokia     ", "Nokia"},
    {0x002682,  "GemTek    ", "GemTek, Motorola, access-point"},
    {0x0026b0,  "Apple     ", "Apple"},
    {0x0026b6,  "Askey     ", "Askey Computer Corp"},
    {0x0026b8,  "Actiontec ", "Actiontec Electronics, Inc"},
    {0x0026BA,  "MotorolaPH", "Motorola Mobile Devices"},
    {0x0026bb,  "Apple     ", "Apple"},
    {0x0026C6,  "Intel     ", "Intel Centrino PRO/Wireless"},
    {0x0026C7,  "Intel     ", "Intel Centrino PRO/Wireless"},
/**/{0x0026cc,  "Nokia     ", "Nokia"},
/**/{0x0026e8,  "Murata    ", "Murata Manufacturing Co., Ltd."},
    {0x0026f2,  "Netgear   ", "Netgear, access-point"},
    {0x0026ff,  "BLACKBERRY", "Research In Motion"},
    {0x002710,  "Intel     ", "Intel Centrino PRO/Wireless"},
    {0x00601d,  "Lucent    ", "Lucent Technologies"},
/**/{0x00BD3A,  "Nokia     ", "Nokia"},
    {0x00c0a8,  "GVC       ", "GVC Corporation, modem/fax/phone"},
    {0x041e64,  "Apple     ", "Apple"},
    {0x0c6076,  "Foxconn   ", "Hon Hai Precision, Windows Notebook"}, /*[00:24:2b:70:86:78] station: WinXP notebook */	
/**/{0x0CDDEF,  "Nokia     ", "Nokia"},
    {0x0CEEE6,  "Foxconn   ", "Hon Hai Precision"},
    {0x1c4bd6,  "AzureWave ", "AzureWave Technologies"},
    {0x2C8158,  "Foxconn   ", "Hon Hai Precision"},
    {0x2ca835,  "BLACKBERRY", "Research In Motion"},
    {0x307c30,  "BLACKBERRY", "Research In Motion"},
    {0x34159e,  "Apple     ", "Apple"},
/**/{0x347e39,  "Nokia     ", "Nokia"},
    {0x38E7D8,  "Htc       ", "HTC Corporation"},
/**/{0x3CF72A,  "Nokia     ", "Nokia"},
 
    {0x40d32d,  "Apple     ", "Apple"},
    {0x506313,  "Foxconn   ", "Hon Hai Precision"},
    {0x58B035,  "Apple     ", "Apple"},
/**/{0x5C57C8,  "Nokia     ", "Nokia"},
    {0x5C5948,  "Apple     ", "Apple"},
    {0x60334B,  "Apple     ", "Apple"},
    {0x60fb42,  "Apple     ", "Apple"},
    {0x64b9e8,  "Apple     ", "Apple"},
    {0x701a04,  "Lite-On   ", "Lite-On Computer Corporation"},
    {0x70f104,  "Lite-On   ", "Lite-On Computer Corporation"},
    {0x70f1a1,  "Lite-On   ", "Lite-On Computer Corporation"},
    {0x78E400,  "Foxconn   ", "Hon Hai Precision"},
    {0x7C6D62,  "Apple     ", "Apple"},
    {0x7CC537,  "Apple     ", "Apple"},
    {0x78DD08,  "Foxconn   ", "Hon Hai Precision, Windows Notebook"},
/**/{0x80501B,  "Nokia     ", "Nokia"},
    {0x9027E4,  "Apple     ", "Apple"},
    {0x904CE5,  "Foxconn   ", "Hon Hai Precision"},

    {0x90840D,  "Apple     ", "Apple"},
    {0x9068c3,  "Motorola  ", "Motorola"}, /* Motorola */
    {0x9268c3,  "(Android) ", "(Android)"}, /* Motorola */
    {0x9ce635,  "Nintendo  ", "Nintendo"},
    {0x9ee635,  "Nintendo  ", "Nintendo"},
/**/{0xA04E04,  "Nokia     ", "Nokia"},
    {0xA4ED4E,  "MotorolaPH", "Motorola Mobile Devices"},
/**/{0xA87B39,  "Nokia     ", "Nokia"},
    {0xb482fe,  "Askey     ", "Askey Computer Corp"},
/**/{0xC038F9,  "Nokia     ", "Nokia"},
    {0xc42c03,  "Apple     ", "Apple"},
    {0xC417FE,  "Foxconn   ", "Hon Hai Precision"},
    {0xC44619,  "Foxconn   ", "Hon Hai Precision, Windows Notebook"},
    {0xC83A35,  "Tenda     ", "Tenda Technology Co., Ltd."},
    {0xd49a20,  "Apple     ", "Apple"},
    {0xD83062,  "Apple     ", "Apple"},
/**/{0xD87533,  "Nokia     ", "Nokia"},
    {0xD8A25E,  "Apple     ", "Apple"},
    {0xDAA119,  "(Android) ", "(Android)"},
    {0xE80688,  "Apple     ", "Apple"},
/**/{0xE8E5D6,  "Samsung   ", "Samsung"},
/**/{0xEC9B5B,  "Nokia     ", "Nokia"},
    {0xF07BCB,  "Foxconn   ", "Hon Hai Precision, Windows Notebook"},
    {0xf40b93,  "BLACKBERRY", "Research In Motion"},
    {0xf81edf,  "Apple     ", "Apple"},
    {0xF87B7A,  "MotorolaPH", "Motorola Mobile Devices"},
    {0xFFFFFFFF, "", ""}
}; 

struct Manufs *ymanufs = NULL;
unsigned ymanufs_count = 0;
unsigned ymanufs_max = 0;

/**
 * Add an IEEE OUI manufacturer ID to the list that was parsed from a
 * a file.
 */
static void
manufs_add(unsigned oui, const char *shortname, const char *description)
{
    unsigned i;

    /* Allocate more space when the list grows larger */
    if (ymanufs_count + 1 >= ymanufs_max) {
        struct Manufs *newmanufs;
        unsigned newmax = ymanufs_max*2+1;

        newmanufs = (struct Manufs*)malloc(newmax * sizeof(*newmanufs));
        if (ymanufs) {
            memcpy(newmanufs, ymanufs, ymanufs_count*sizeof(*ymanufs));
            free(ymanufs);
        }
        ymanufs = newmanufs;
        ymanufs_max = newmax;
    }

    /* Create a new entry */
    i = ymanufs_count++;
    ymanufs[i].oui = oui;
    sprintf_s(ymanufs[i].str, sizeof(ymanufs[i].str), "%s", shortname);
    ymanufs[i].desc = strdup(description);
}

unsigned from_hex(char c)
{
    if ('0' <= c && c <= '9')
        return c - '0';
    else if ('a' <= c && c <= 'f')
        return c - 'a' + 10;
    else if ('A' <= c && c <= 'F')
        return c - 'A' + 10;
    else
        return 0;
}

/**
 * Parses a 24-bit number encoded like:
 * 012345
 * 01:23:45
 * 01-23-45
 * 0x012345
 */
unsigned parse_oui(const char *p, unsigned *bytes_parsed)
{
    const char *start = p;
    unsigned result = 0;
    unsigned i;

    while (*p && isspace(*p))
        p++;

    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X'))
        p += 2;

    for (i=0; i<6; i++) {
        if (ispunct(*p))
            p++;
        if (!isxdigit(*p))
            return 0xFFFFFFFF;
        else
            result = result * 16 + from_hex(*p);
        p++;
    }

    *bytes_parsed = (unsigned)(p - start);
    return result;
}

int is_empty(const char *line)
{
	while (*line) {
		if (!isspace((*line)&0xFF))
			return 0;
		line++;
	}
	return 1;
}

int is_hex(const char *line)
{
	unsigned i;

	for (i=0; i<8; i++) {
		if (!(isxdigit(line[i]&0xFF) || line[i] == '-'))
			return 0;
	}
	return 1;
}

static unsigned hexval(int c)
{
	if ('0' <= c && c <= '9')
		return c-'0';
	if ('a' <= c && c <= 'f')
		return c-'a'+10;
	if ('A' <= c && c <= 'F')
		return c-'A'+10;
	return 0xA3;
}

static unsigned parse_oui2(const char *line, unsigned *offset)
{
	unsigned oui = 0;
	unsigned i;

	while (line[*offset] && isspace(line[*offset]))
		(*offset)++;

	for (i=0;  i<3;  i++) {
		unsigned val;

		if (!isxdigit(line[*offset]))
			fprintf(stderr, "parse error\n");

		val = hexval(line[(*offset)++]);
		if (isxdigit(line[*offset]))
			val = val*16 + hexval(line[(*offset)++]);
		if (line[*offset] == '-' || line[*offset] == ' ')
			(*offset)++;
		else
			fprintf(stderr, "unexpected char\n");

		oui = (oui<<8) | val;
	}

	while (line[*offset] && isspace(line[*offset]))
		(*offset)++;

	if (memcmp(line+(*offset), "(hex)", 5) != 0) {
		fprintf(stderr, "expected (hex): %s\n", line+*offset);
	} else
		(*offset) += 5;

	while (line[*offset] && isspace(line[*offset]&0xFF))
		(*offset)++;

	return oui;
}

static void manufs_load_from_oui_file(const char *filename)
{
	char line[256];
	FILE *fp;

	fp = fopen(filename, "rt");
	if (fp == NULL) {
		perror(filename);
		return;
	}

	while (fgets(line, sizeof(line), fp)) {
		unsigned oui;
		unsigned offset = 0;

		/* Skip the empty lines between sections */
		if (is_empty(line))
			continue;

		/* make sure the section starts with a hex string */
		if (!is_hex(line)) {
			while (fgets(line, sizeof(line), fp) && !is_empty(line))
				;
			continue;
		}

		/* parse the hex and name */
		while (*line && isspace(line[strlen(line)-1]&0xFF))
			line[strlen(line)-1] = '\0';

		oui = parse_oui2(line, &offset);

		{
			char shortname[12];
			memcpy(shortname, line+offset, 12);
			shortname[11] = '\0';
			manufs_add(oui, shortname, line+offset);
		}

	}

	fclose(fp);
}

/**
 * Load IEEE OUI manufacturer IDs from a file, which is "manuf" located
 * in the current working directory.
 */
static void 
manufs_load_from_file()
{
    unsigned i;
    FILE *fp;
    unsigned char line[256];


	manufs_load_from_oui_file("oui.txt");


    fp = fopen("manuf", "rt");
    if (fp == NULL) {
        ymanufs = xmanufs;
        perror("manuf");
        return;
    }

    /* read all lines from the file and parse them */
    while (fgets((char*)line, sizeof(line), fp)) {
        unsigned oui;
        unsigned x;
        char *shortname;
        char *description;

        while (isspace(*line))
            memmove(line, line+1, strlen((char*)line));
        while (isspace(line[strlen((char*)line)-1]&0xFF))
            line[strlen((char*)line)-1] = '\0';

        /* Ignore comments or empty lines */
        if (*line == '\0' || ispunct(*line) || !isxdigit(*line))
            continue;

        /* Parse the oui */
        oui = 0;
        oui = parse_oui((char*)line, &x);
        if (oui == 0 || oui > 0xFFFFFF)
            continue;

        memmove(line, line+x, strlen((char*)line)+1-x);
        if (!isspace(*line))
            continue;
        while (isspace(*line))
            memmove(line, line+1, strlen((char*)line));

        shortname = (char*)line;
        description = shortname;
        for (i=0; i<10; i++)
            if (*description)
                description++;
        *description = '\0';
        description++;
        while (isspace(*description))
            description++;

        manufs_add(oui, shortname, description);
    }

    manufs_add(0xFFFFFFFF, "", "");
    fclose(fp);
    
}


/*===========================================================================
 *===========================================================================*/
struct Changes {
	const char *original;
	const char *changeto;
} changes[] = {
	{"Apple     ",	"Apple     "},
	{"AppleiPhon",	"Apple     "},
	{"AppleCompu",	"Apple     "},
	{"Apple Compu", "Apple     "},
	{"Apple Inc",	"Apple     "},
	{"Apple, Inc.", "Apple     "},
	{"Apple, Inc",	"Apple     "},

	{"Agere Syste", "Agere     "},
	{"ALLIED TELE", "Allied Tele"},
	{"Allied Tele", "Allied Tele"},
	{"ALPS ELECTR", "Alps Electr"},

	{"Arcadyan Te", "Arcadyan  "},
	{"ASKEY COMPU",	"Askey     "},
	{"Askey Compu", "Askey     "},
	{"Askey     ",	"Askey     "},

	{"AsustekCom",	"AsusTek   "},
	{"ASUSTek COM", "AsusTek   "},
	{"AzureWave T", "AzureWave "},
	{"Azurewave T", "AzureWave "},

	{"BelkinInte",	"Belkin    "},
	{"BelkinComp",	"Belkin    "},

	{"Buffalo, In",	"Buffalo   "},
	{"Buffalo Inc",	"Buffalo   "},
	{"BUFFALO INC", "Buffalo   "},
	
	{"CANON INC.",	"Canon     "},

	{"Cisco-Link",	"Linksys(C)"},
	{"Cisco Syste", "Cisco     "},
	
	{"GemTek Tech", "GemTek    "},
	{"Gemtek Tech", "GemTek    "},

	{"HonHaiPrec",	"Foxconn   "},
	{"Hon Hai Pre",	"Foxconn   "},

	{"HighTechCo",	"HTC-phone "},
	{"High Tech C",	"HTC-phone "},
	{"Htc",			"HTC-phone "},
	{"Htc       ",	"HTC-phone "},
	{"Htc        ",	"HTC-phone "},
	{"HTC Corpora",	"HTC-phone "},

	{"Huawei Devi", "Huawei    "},
	{"HUAWEI TECH", "Huawei    "},

	{"IntelCorpo",	"Intel     "},
	{"Intel Corpo", "Intel     "},
	{"Intel Corp",	"Intel     "},

	{"KYOCERA COR", "Kyocera   "},
	{"LiteonTech",	"Lite-On   "},
	{"Liteon Tech", "Lite-On   "},
	{"Logitec Cor", "Logitec   "},
	
	{"LG Innotek",  "LG        "},
	{"LG Innotek ", "LG        "},
	{"LG Electron", "LG        "},
	{"Microsoft C", "Microsoft "},
	{"Microsoft M", "Microsoft "},
	{"Motorola Mo", "Motorola  "},
	{"Murata Manu", "Murata    "},

	{"NokiaDanma",	"Nokia     "},
	{"Nokia Corpo",	"Nokia     "},
	{"Nokia Danma", "Nokia     "},

	{"Nintendo Co",	"Nintendo  "},

	{"NEC CORPORA", "NEC       "},
	{"NEC AccessT", "NEC       "},
	{"NEC Corpora", "NEC       "},

	{"OnePLus Tec",	"OnePlus   "},
	{"Palm, Inc",	"-hp- Palm "},
	{"Proxim Wire", "Proxim    "},

	{"Quanta Micr", "Quanta    "},
	{"QuantaMicr",	"Quanta    "},
	{"QUANTA COMP", "Quanta    "},

	{"Ruckus Wire", "Ruckus    "},

	{"RimTesting",	"BLACKBERRY"},
	{"ResearchIn",	"BLACKBERRY"},
	{"RIM",			"BLACKBERRY"},
	{"Research In", "BLACKBERRY"},

	{"SHARP CORPO", "Sharp #   "},
	{"SHARP Corpo", "Sharp #   "},

	{"Symbol Tech",	"Symbol    "},
	{"SymbolTech",	"Symbol    "},
	{"SYMBOL TECH", "Symbol    "},
	
	{"Sonicwall ",	"SonicWALL "},

	{"SamsungEle",	"Samsung   "},
	{"SAMSUNG ELE", "Samsung   "},
	{"Samsung Ele", "Samsung   "},

	{"Sony Ericss",	"SonyEricsn"},
	{"Sony Comput", "Sony      "},

	{"HewlettPac",	"-hp-      "},
	{"hp        ",	"-hp-      "},
	{"HP        ",	"-hp-      "},
	{"Hewlett Pac", "-hp-      "},
	{"zte corpora", "ZTE       "},
	{0,0}
};

const char *translate_name(const char *name)
{
	unsigned i;

	for (i=0; changes[i].original; i++)
		if (strcmp(changes[i].original, name) == 0)
			return changes[i].changeto;

	return name;
}

/*===========================================================================
 *===========================================================================*/
const char *
manuf_from_mac(const unsigned char *mac_address)
{
    struct Manufs *manufs = &xmanufs[0];
    unsigned i;
    unsigned oui = mac_address[0]<<16 | mac_address[1]<<8 | mac_address[2];

    /* Look first in the     hard-coded list */
    for (i=0; manufs[i].oui != 0xFFFFFFFF; i++) {
        if (manufs[i].oui == oui) {
            const char *result;
            result = manufs[i].str;
            if (strcmp(result, "AppleiPhon") == 0)
                result = "Apple     ";
            return result;
        }
    }

    /* Now look in the loaded list */
    if (ymanufs == NULL) {
        manufs_load_from_file();
    }
    manufs = ymanufs;
    for (i=0; manufs[i].oui != 0xFFFFFFFF; i++) {
        if (manufs[i].oui == oui) {
			const char *result;

			result = translate_name(manufs[i].str);
            return result;
        }
    }

    if ((mac_address[0] & 0x03) == 0x02)
        return "(random)";
    return "";
}

/*===========================================================================
 *===========================================================================*/
const char *
manuf2_from_mac(const unsigned char *mac_address)
{
    struct Manufs *manufs = &xmanufs[0];
    unsigned i;
    unsigned oui = mac_address[0]<<16 | mac_address[1]<<8 | mac_address[2];

    for (i=0; manufs[i].oui != 0xFFFFFFFF; i++) {
        if (manufs[i].oui == oui)
            return manufs[i].desc;
    }
    /* Now look in the loaded list */
    if (ymanufs == NULL) {
        manufs_load_from_file();
    }
    manufs = ymanufs;
    for (i=0; manufs[i].oui != 0xFFFFFFFF; i++) {
        if (manufs[i].oui == oui)
            return manufs[i].desc;
    }
    return "";
}

