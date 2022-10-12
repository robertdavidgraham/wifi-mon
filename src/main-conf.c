#include "main-conf.h"
#include "squirrel.h"
#include "sift.h"
//#include <assert.h>
#include <ctype.h>
#include <stdio.h>
//#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
//#include <time.h>
#include <sys/stat.h>
//#include <signal.h>
//#include "util-extract.h"
//#include "stack-frame.h"
#include "util-hexval.h"
//#include "squirrel.h"
//#include "sqdb2.h"
//#include "mongoose.h"
//#include "util-pixie.h"
#include "util-annexk.h"

#ifdef WIN32
#include <direct.h> /* for Posix mkdir(), getcwd() */
#else
#include <unistd.h>
#endif

//#include "pcap-file.h"
//#include "pcap-live.h"
//#include "util-stratom.h"

int debug=1;

/* Forward declarations */
static void
squirrel_set_parameter(struct Squirrel *squirrel, const char *name, const char *value, unsigned depth);


/**
 * Provide help, either an overview, or more help on a specific option.
 */
static void main_help(void)
{
    fprintf(stderr,"options:\n");
    fprintf(stderr," -i <adapter>    Sniffs the wire(less) attached to that network adapter. \n");
    fprintf(stderr,"                 Must have libpcap or winpcap installed to work.\n");
    fprintf(stderr," -r <files>      Read files in off-line mode. Can use wildcards, such as \n");
    fprintf(stderr,"                 using \"squirrel -r *.pcap\". Doesn't need libpcap to work.\n");
    fprintf(stderr," -c <file>       Reads in more advanced parameters from a file.\n");
}



static unsigned
cfg_prefix(const char *name, const char *prefix, unsigned offset)
{
    unsigned i, p;

    if (name[offset] == '.')
        offset++;

    for (i=offset, p=0; name[i] && prefix[p]; i++, p++)
        if (name[i] != prefix[p])
            return 0;
    if (prefix[p] == '\0')
        return i;
    else
        return 0;
}

static unsigned
parse_boolean(const char *value)
{
    switch (value[0]) {
        case '1': /*1*/
        case 'y': /*yes*/
        case 'Y': /*YES*/
        case 'e': /*enabled*/
        case 'E': /*ENABLED*/
        case 't': /*true*/
        case 'T': /*TRUE*/
            return 1;
        case 'o': /*on/off*/
        case 'O': /*ON/OFF*/
            if (value[1] == 'n' || value[1] == 'N')
                return 1;
    }
    return 0;
}
/**
 * Parse a MAC address from hex input. It can be in a number of
 * formats, such as:
 *    [00:00:00:00:00:00]
 *  00-00-00-00-00-00
 *  000000000000
 */
void
parse_mac_address(unsigned char *dst, size_t sizeof_dst, const char *src)
{
    unsigned i=0;
    unsigned found_non_xdigit=0;
    unsigned premature_end=0;

    if (*src == '[')
        src++;

    while (*src && i<6) {
        if (!isxdigit(*src)) {
            found_non_xdigit = 1;
            src++;
        } else {
            unsigned c;

            c = hexval(*src);
            src++;
            if (*src == '\0')
                premature_end=1;
            else if (!isxdigit(*src))
                found_non_xdigit = 1;
            else {
                c = c<<4 | hexval(*src);
                src++;
            }

            if (i<sizeof_dst)
                dst[i++] = (unsigned char)c;

            if (*src && ispunct(*src))
                src++;
        }
    }

    if (found_non_xdigit)
        fprintf(stderr, "parse_mac_address: non hex-digit found\n");
}
/**
 * Figures out whether the specified filename is a directory or normal
 * file. This is useful when recursing directories -- such as reading in
 * all packet-capture files in a directory structure for testing.
 */
static int
is_directory(const char *filename)
{
    struct stat s;

    if (stat(filename, &s) != 0) {
        /* Not found, so assume a "file" instead of "directory" */
        return 0;
    } else if (!(s.st_mode & S_IFDIR)) {
        /* Directory flag not set, so this is a "file" not a "directory" */
        return 0;
    }
    return 1;
}

void add_port_filter(unsigned **r_ports, unsigned *r_port_count, unsigned port)
{
    unsigned *new_ports;
    unsigned new_count = *r_port_count + 1;

    if (port >= 65536)
        return;

    new_ports = (unsigned*)malloc(sizeof(unsigned) * (new_count));
    if (*r_ports) {
        memcpy(new_ports, *r_ports, sizeof(unsigned) * (new_count));
        free(*r_ports);
    }
    *r_ports = new_ports;
    new_ports[*r_port_count] = port;
    *r_port_count = new_count;
}

unsigned filter_has_port(unsigned *list, unsigned count, unsigned port)
{
    unsigned i;
    for (i=0; i<count; i++) {
        if (list[i] == port)
            return 1;
    }
    return 0;
}


void squirrel_parse_file(struct Squirrel *squirrel, unsigned depth, const char *filename) {
    FILE *fp;
    char line[2048];

    fp = fopen(filename, "rt");
    if (fp == NULL) {
        fprintf(stderr, "%sreading configuration file\n", "ERR:CFG: ");
        perror(filename);
        return;
    }

    while (fgets(line, sizeof(line), fp)) {
        char *name;
        char *value;

        name = line;
        value = strchr(line, '=');
        if (value == NULL)
            continue;
        *value = '\0';
        value++;

        while (*name && isspace(*name))
            memmove(name, name+1, strlen(name));
        while (*value && isspace(*value))
            memmove(value, value+1, strlen(value));
        while (*name && isspace(name[strlen(name)-1]))
            name[strlen(name)-1] = '\0';
        while (*value && isspace(value[strlen(value)-1]))
            value[strlen(value)-1] = '\0';

        squirrel_set_parameter(squirrel, name, value, depth+1);

    }
}

static void
squirrel_set_parameter(struct Squirrel *squirrel, const char *name, const char *value, unsigned depth)
{
    unsigned x=0;

    if (depth > 10)
        return;

    /* This macro is defined to match the leading keyword */
#define MATCH(str) cfg_prefix(name, str, x) && ((x=cfg_prefix(name, str, x))>0)

    if (MATCH("config")) {
        if (MATCH("echo")) {
            squirrel->cfg.echo = strdup(value);
        } else if (MATCH("quiet")) {
            squirrel->cfg.quiet = parse_boolean(value);
        } else {
            fprintf(stderr, "%sunknown parm: %s=%s\n", "ERR:CFG: ", name, value);
        }
    } else if (MATCH("webroot")) {
        if (squirrel->webroot)
            free(squirrel->webroot);
        squirrel->webroot = strdup(value);
        {
            char foo[512];
            fprintf(stderr, "Set root: %s %s\n", getcwd(foo, sizeof(foo)), squirrel->webroot);
        }
    } else if (MATCH("interface")) {
        if (MATCH("checkfcs")) {
            squirrel->cfg.interface_checkfcs = parse_boolean(value);
        } else if (MATCH("scan")) {
            squirrel->cfg.interface_scan = parse_boolean(value);
        } else if (MATCH("interval")) {
            if (MATCH("inactive"))
                squirrel->interface_interval_inactive = (unsigned)strtoul(value,0,0);
            else if (MATCH("active"))
                squirrel->interface_interval_active = (unsigned)strtoul(value,0,0);

        }
    } else if (MATCH("vector")) {
        if (MATCH("mode")) {
            if (strcmp(value, "none")==0)
                squirrel->cfg.no_vectors = 1;
        }
    } else if (MATCH("filter")) {
        squirrel->filter.is_filtering = 1;
        if (MATCH("mac")) {
            /* Parse the MAC address in the value field and add it
             * to the end of our list of MAC address filters.
             * TODO: we should probably sort these and/or check
             * for duplicates */
            unsigned char **newfilters = (unsigned char**)malloc((squirrel->filter.mac_address_count+1)*sizeof(unsigned char*));
            unsigned i;
            for (i=0; i<squirrel->filter.mac_address_count; i++)
                newfilters[i] = squirrel->filter.mac_address[i];
            newfilters[i] = (unsigned char*)malloc(6);
            memset(newfilters[i], 0xa3, 6);
            parse_mac_address(newfilters[i], 6, value);
            if (squirrel->filter.mac_address)
                free(squirrel->filter.mac_address);
            squirrel->filter.mac_address = newfilters;
            squirrel->filter.mac_address_count++;
        } else if (MATCH("ssh")) {
            squirrel->filter.is_ssh = 1;
            squirrel->filter.something_tcp = 1;
        } else if (MATCH("tcp")) {
            add_port_filter(&squirrel->filter.tcp_ports, &squirrel->filter.tcp_port_count, (unsigned)strtoul(value,0,0));
            squirrel->filter.something_tcp = 1;
        } else if (MATCH("udp")) {
            add_port_filter(&squirrel->filter.udp_ports, &squirrel->filter.udp_port_count, (unsigned)strtoul(value,0,0));
        } else if (MATCH("snap.oui")) {
            add_port_filter(&squirrel->filter.snap_ouis, &squirrel->filter.snap_oui_count, (unsigned)strtoul(value,0,0));
        } else
            printf("unknowwn filter %s\n", name);
    } else if (MATCH("include")) {
        squirrel_parse_file(squirrel, depth, value);
    } else if (MATCH("statistics")) {
        squirrel->cfg.statistics_print = parse_boolean(value);
    } else if (MATCH("sniffer")) {
        if (MATCH("dir")) {
            const char *directory_name = value;
            size_t directory_length = strlen(directory_name);
            char *p;

            if (directory_length > sizeof(squirrel->output.directory)-1) {
                fprintf(stderr, "%sparameter too long: %s=%s\n", "ERR:CFG: ", name, value);
                return;
            }
            if (squirrel->output.directory[0]) {
                fprintf(stderr, "%sparameter exists: old: %s=%s\n", "ERR:CFG: ", name, squirrel->output.directory);
                fprintf(stderr, "%sparameter exists: new: %s=%s\n", "ERR:CFG: ", name, value);
                return;
            }

            /* Remove trailing spaces and slashes */
            p = squirrel->output.directory;
            while (*p && (isspace(p[strlen(p)-1]) || p[strlen(p)-1]=='/' || p[strlen(p)-1]=='\\'))
                p[strlen(p)-1] = '\0';

            strcpy_s(squirrel->output.directory, sizeof(squirrel->output.directory), directory_name);
            return;
        } else if (MATCH("filename")) {
            if (is_directory(value)) {
                squirrel_set_parameter(squirrel, "sniffer.directory", value, depth);
                return;
            }
            strcpy_s(squirrel->output.filename, sizeof(squirrel->output.filename), value);
            if (squirrel->output.sniff == FERRET_SNIFF_NONE)
                squirrel->output.sniff = FERRET_SNIFF_MOST;
            if (squirrel->output.noappend == 0)
                squirrel->output.noappend = 1;
        } else if (MATCH("mode")) {
            if (strcmp(value, "all")==0)
                squirrel->output.sniff = FERRET_SNIFF_ALL;
            else if (strcmp(value, "most")==0)
                squirrel->output.sniff = FERRET_SNIFF_MOST;
            else if (strcmp(value, "ivs")==0)
                squirrel->output.sniff = FERRET_SNIFF_IVS;
            else if (strcmp(value, "sift")==0)
                squirrel->output.sniff = FERRET_SNIFF_SIFT;
            else if (strcmp(value, "none")==0)
                squirrel->output.sniff = FERRET_SNIFF_NONE;
            else {
                fprintf(stderr, "%sparameter unknown: %s=%s\n", "ERR:CFG: ", name, value);
                return;
            }
        } else if (MATCH("noappend")) {
            squirrel->output.noappend = parse_boolean(value);
        } else
            fprintf(stderr, "%sunknown parm: %s=%s\n", "ERR:CFG: ", name, value);
    } else if (MATCH("snarfer")) {
        if (MATCH("dir")) {
            const char *directory_name = value;
            size_t directory_length = strlen(directory_name);
            char *p;

            if (directory_length > sizeof(squirrel->snarfer.directory)-1) {
                fprintf(stderr, "%sparameter too long: %s=%s\n", "ERR:CFG: ", name, value);
                return;
            }
            if (squirrel->snarfer.directory[0]) {
                fprintf(stderr, "%sparameter exists: old: %s=%s\n", "ERR:CFG: ", name, squirrel->snarfer.directory);
                fprintf(stderr, "%sparameter exists: new: %s=%s\n", "ERR:CFG: ", name, value);
                return;
            }

            /* Remove trailing spaces and slashes */
            p = squirrel->snarfer.directory;
            while (*p && (isspace(p[strlen(p)-1]) || p[strlen(p)-1]=='/' || p[strlen(p)-1]=='\\'))
                p[strlen(p)-1] = '\0';

            strcpy_s(squirrel->snarfer.directory, sizeof(squirrel->snarfer.directory), directory_name);
            return;
        } else if (MATCH("mode")) {
            if (strcmp(value, "all")==0)
                squirrel->snarfer.mode = FERRET_SNIFF_ALL;
            else if (strcmp(value, "most")==0)
                squirrel->snarfer.mode = FERRET_SNIFF_MOST;
            else if (strcmp(value, "none")==0)
                squirrel->snarfer.mode = FERRET_SNIFF_NONE;
            else {
                fprintf(stderr, "%sparameter unknown: %s=%s\n", "ERR:CFG: ", name, value);
                return;
            }
        } else
            fprintf(stderr, "%sunknown parm: %s=%s\n", "ERR:CFG: ", name, value);

    } else
        fprintf(stderr, "%sunknown parm: %s=%s\n", "ERR:CFG: ", name, value);

}

/**
 * Parse the command-line arguments
 */
void
main_conf(int argc, char **argv, struct Squirrel *squirrel)
{
    int i;

    for (i=1; i<argc; i++) {
        const char *arg = argv[i];

        /* See if a <name=value> style configuration parameter was
         * given on the command-line */
        if (arg[0] != '-' && strchr(argv[i],'=')) {
            char name[256];
            size_t name_length;
            const char *value;
            unsigned j;

            /* Extract the name */
            name_length = strchr(argv[i], '=') - argv[i];
            if (name_length > sizeof(name)-1)
                name_length = sizeof(name)-1;
            memcpy(name, argv[i], name_length);
            while (name_length && isspace(name[name_length-1]))
                name_length--;
            while (name_length && isspace(name[0]))
                memmove(name, name+1, --name_length);
            name[name_length] = '\0';
            for (j=0; j<name_length; j++)
                name[j] = (char)tolower(name[j]);

            /* Extract the value */
            value = strchr(argv[i],'=') + 1;
            while (*value && isspace(*value))
                value++;

            /* Set the configuration parameter */
            squirrel_set_parameter(squirrel, name, value,1);

            continue; /*loop to next command-line parameter*/
        }

        if (arg[0] != '-')
            continue;

        if (arg[1] == '-') {
            if (strcasecmp_s(arg, "--server") == 0)
                squirrel_set_parameter(squirrel, "mode", "server", 0);
            else if (strcasecmp_s(arg, "--webroot") == 0)
                squirrel_set_parameter(squirrel, "webroot", argv[++i], 0);
            continue;
        }

        switch (arg[1]) {
            case 'c':
                if (arg[2] == '\0')
                    squirrel_set_parameter(squirrel, "include", argv[++i], 0);
                else
                    squirrel_set_parameter(squirrel, "include", argv[i]+2, 0);
                break;
            case 'd':
                debug++;
                break;
            case 'h':
            case 'H':
            case '?':
                main_help();
                exit(0);
                break;

            case 'q':
                squirrel_set_parameter(squirrel, "config.quiet", "true", 0);
                break;

            case 'F':
                squirrel_set_parameter(squirrel, "interface.checkfcs", "true", 0);
                break;
            case 'S':
                squirrel_set_parameter(squirrel, "statistics.print", "true", 0);
                break;

            case 'r':
                if (squirrel->is_live) {
                    fprintf(stderr,"ERROR: cannot process live and offline data at the same time\n");
                    squirrel->is_error = 1;
                }
                squirrel->is_offline = 1;
                if (argv[i][2] == '\0') {
                    while (i+1<argc) {
                        const char *filename = argv[i+1];
                        if (filename[0] == '-' || strchr(filename, '='))
                            break;
                        else
                            i++;
                    }
                }
                break;
            case 'i':
                if (squirrel->is_offline) {
                    fprintf(stderr,"Cannot process live and offline data at the same time\n");
                    squirrel->is_error = 1;
                } else {
                    if (arg[2] == '\0' && i+1<argc) {
                        strcpy_s(squirrel->interface_name, sizeof(squirrel->interface_name), argv[i+1]);
                        i++;
                        squirrel->is_live = 1;
                        /* TODO: validate*/
                    } else if (isdigit(arg[2])) {
                        strcpy_s(squirrel->interface_name, sizeof(squirrel->interface_name), arg+2);
                        squirrel->is_live = 1;
                    } else {
                        fprintf(stderr, "%s: invalid argument, expected something like \"-i1\" or \"-i eth0\"\n", argv[i]);
                        squirrel->is_error = 1;
                    }
                }
                break;
            case 'W':
                squirrel->is_live = 1;
                break;
            case 'w':
                if (arg[2] == '\0')
                    squirrel_set_parameter(squirrel, "sniffer.filename", argv[++i], 0);
                else
                    squirrel_set_parameter(squirrel, "sniffer.filename", argv[i]+2, 0);

                squirrel_set_parameter(squirrel, "sniffer.mode", "most", 0);
                break;
        }
    }
}

