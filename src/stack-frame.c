#include "stack-frame.h"
#include "squirrel.h"
#include "sqdb2.h"
#include "util-extract.h"
#include <string.h>

static int
wifi_frequency_to_channel(int frequency)
{
    /* 2.4 GHz 802.11b/g/n */
    if (2402 <= frequency && frequency <= 2472) {
        return 1 + ((frequency - 2412) / 5);
    } else if (frequency == 2484) {
        return 14; /* Japan */
    } else if (5150 <= frequency && frequency <= 5350) {
        /* U-NII-1 = 5150 - 5250 max 50 mW */
        /* U-NII-2 = 5250 - 5350 max 250 mW */
        return 30 + ((frequency - 5150) / 5 );
    } else if (5470 <= frequency && frequency <= 5720) {
        /* U-NII-2e =  */
        return 94 + ((frequency - 5470) / 5 );
    } else if (5720 <= frequency && frequency <= 5865) {
        /* U-NII-2e =  */
        return 144 + ((frequency - 5720) / 5 );
    } else
        return -1;
}

void
stack_parse_frame(struct Squirrel *squirrel,
                  struct StackFrame *frame,
                  const unsigned char *px, unsigned length)
{
    squirrel->sqdb->kludgex = frame;

    /* Clear the 'wifi' information. We'll fill in this structure
     * from the radiotap header, if it exists. */
    memset(&frame->wifi, 0, sizeof(frame->wifi));

    /* Record the current time */
    if (squirrel->now != (time_t)frame->time_secs) {
        squirrel->now = (time_t)frame->time_secs;

        if (squirrel->first == 0)
            squirrel->first = frame->time_secs;
    }



    /* Clear the information that we will set in the frame */
    frame->flags.clear = 0;
    squirrel->something_new_found = 0;


    switch (frame->layer2_protocol) {
        case 1: /* Ethernet */
            squirrel_ethernet_frame(squirrel, frame, px, length);
            break;
        case 0x69: /* WiFi */
            squirrel_wifi_frame(squirrel, frame, px, length);
            break;
        case 119: /* DLT_PRISM_HEADER */
            /* This was original created to handle Prism II cards, but now we see this
             * from other cards as well, such as the 'madwifi' drivers using Atheros
             * chipsets.
             *
             * This starts with a "TLV" format, a 4-byte little-endian tag, followed by
             * a 4-byte little-endian length. This TLV should contain the entire Prism
             * header, after which we'll find the real header. Therefore, we should just
             * be able to parse the 'length', and skip that many bytes. I'm told it's more
             * complicated than that, but it seems to work right now, so I'm keeping it
             * this way.
             */
            if (length < 8) {
                FRAMERR(frame, "unknown linktype = %d (expected Ethernet or wifi)\n", frame->layer2_protocol);
                return;
            }
            if (ex32le(px+0) != 0x00000044) {
                FRAMERR(frame, "unknown linktype = %d (expected Ethernet or wifi)\n", frame->layer2_protocol);
                return;
            } else {
                unsigned header_length = ex32le(px+4);

                if (header_length >= length) {
                    FRAMERR(frame, "unknown linktype = %d (expected Ethernet or wifi)\n", frame->layer2_protocol);
                    return;
                }

                /*
                 * Ok, we've skipped the Prism header, now let's process the
                 * wifi packet as we would in any other case. TODO: in the future,
                 * we should parse the Prism header and extract some of the
                 * fields, such as signal strength.
                 */
                squirrel_wifi_frame(squirrel, frame, px+header_length, length-header_length);
            }
            break;

        case 127: /* Radiotap headers */

            if (length < 8) {
                squirrel->stats.frame_too_short++;
                return;
            } else {
                struct {
                    unsigned revision;
                    unsigned length;
                    uint64_t present;
                    unsigned flags;
                } hdr = {0};
                unsigned offset;

                hdr.revision = px[0];
                hdr.length = ex16le(px+2);
                hdr.present = ex64le(px+4);

                /* Check for corruption */
                if (hdr.revision != 0 || hdr.length >= length) {
                    squirrel->stats.frame_header_corrupt++;
                    return;
                }

                /* All fields are 'aligned' on even boundaries, depending on
                 * the size of elements. */
#define __ALIGN_MASK(x,mask)    (((x)+(mask))&~(mask))
#define ALIGN(x,n)              __ALIGN_MASK(x,n-1)
#define _SKIP(offset, max, n) (offset)+=(n)
#define _ALGN(offset, max, n) (offset)=ALIGN(offset,n);if ((offset) + (n) > (max)) return

                /* Check for chained "present" flags */
                offset = 4;
                for (;;) {
                    unsigned it_present;
                    _ALGN(offset, hdr.length, 4);
                    it_present = ex32le(px+offset);
                    _SKIP(offset, hdr.length, 4);

                    /* Continue processing 'present' fields until the
                     * high-order bit is  clear, incrementing the 'offset'
                     * field by 4 each time. */
                    if (offset & 0x80000000)
                        continue;
                    else
                        break;
                }

                /* bit: TSFT: MAC timestamp */
                if (hdr.present & 0x000001) {
                    _ALGN(offset, hdr.length, 8);
                    _SKIP(offset, hdr.length, 8);
                }

                /* bit: flags */
                if (hdr.present & 0x000002) {
                    _ALGN(offset, hdr.length, 1);
                    hdr.flags = px[offset];
                    _SKIP(offset, hdr.length, 1);

                    if (hdr.flags & 0x01)
                        squirrel->stats.frame_unknown_flags++;
                    if (hdr.flags & 0x02)
                        ;//squirrel->stats.frame_unknown_flags++;
                    if (hdr.flags & 0x04) {
                        /* WEP??? */
                        squirrel->stats.frame_unknown_flags++;
                    }
                    if (hdr.flags & 0x08) {
                        /* Fragmentation?? */
                        squirrel->stats.frame_unknown_flags++;
                    }

                    /* FCS present */
                    if (hdr.flags & 0x10) {
                        /* remove it from end of packet */
                        length -= 4;
                        if (hdr.length >= length) {
                            squirrel->stats.frame_header_corrupt++;
                            return;
                        }
                    }

                    if (hdr.flags & 0x20)
                        squirrel->stats.frame_unknown_flags++;

                    /* FCS error */
                    if (hdr.flags & 0x40) {
                        squirrel->stats.frame_fcs_error++;
                        return;
                    }

                    if (hdr.flags & 0x80)
                        squirrel->stats.frame_unknown_flags++;

                }

                /* bit: rate */
                if (hdr.present & 0x000004) {
                    _ALGN(offset, hdr.length, 1);
                    _SKIP(offset, hdr.length, 1);
                }

                /* bit 3: channel
                 * align = 2-bytes
                 * size = 4-bytes */
                if (hdr.present & 0x000008) {
                    unsigned frequency;
                    unsigned flags;

                    _ALGN(offset, hdr.length, 2);
                    frequency = ex16le(px+offset);
                    flags = ex16le(px+offset+2);
                    _SKIP(offset, hdr.length, 4);

                    frame->wifi.channel = wifi_frequency_to_channel(frequency);
                }

                /* bit: FHSS */
                if (hdr.present & 0x000010) {
                    _ALGN(offset, hdr.length, 2);
                    _SKIP(offset, hdr.length, 2);
                }
                /* bit: signal strength */
                if (hdr.present & 0x000020) {
                    _ALGN(offset, hdr.length, 1);
                    frame->wifi.dbm = ((signed char*)px)[offset];
                    _SKIP(offset, hdr.length, 1);
                }

                /* bit: noise */
                if (hdr.present & 0x000040) {
                    _ALGN(offset, hdr.length, 1);
                    frame->wifi.dbm_noise = ((signed char*)px)[offset];
                    _SKIP(offset, hdr.length, 1);
                }

                /* bit: lock quality */
                if (hdr.present & 0x000080) {
                    _ALGN(offset, hdr.length, 1);
                    _SKIP(offset, hdr.length, 1);
                }

                squirrel_wifi_frame(squirrel, frame, px+hdr.length, length-hdr.length);
            }
            break;
        default:
            FRAMERR(frame, "unknown linktype = %d (expected Ethernet or wifi)\n", frame->layer2_protocol);
            break;
    }
}

