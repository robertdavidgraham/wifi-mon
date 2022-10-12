#include "stack-frame.h"
#include "squirrel.h"
#include "sqdb2.h"
#include "util-extract.h"

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
    /* Record the current time */
    if (squirrel->now != (time_t)frame->time_secs) {
        squirrel->now = (time_t)frame->time_secs;

        if (squirrel->first == 0)
            squirrel->first = frame->time_secs;

        squirrel->sqdb->kludge.time_stamp = frame->time_secs;
    }

    squirrel->sqdb->kludge.dbm = 0;
    squirrel->sqdb->kludge.channel = 0;

    /* Clear the information that we will set in the frame */
    //squirrel->frame.flags2 = 0;
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
            if (length < 4) {
                //FRAMERR(frame, "radiotap headers too short\n");
                return;
            }
        {
            unsigned version = px[0];
            unsigned header_length = ex16le(px+2);
            unsigned features = ex32le(px+4);
            unsigned flags = px[16];
            unsigned offset;
            int dbm_noise = 0;
            unsigned lock_quality = 0;

            frame->dbm = 0;

            if (version != 0 || header_length > length) {
                FRAMERR(frame, "radiotap headers corrupt\n");
                return;
            }

            /* If FCS is present at the end of the packet, then change
             * the length to remove it */
            if (features & 0x4000) {
                unsigned fcs_header = ex32le(px+header_length-4);
                unsigned fcs_frame = ex32le(px+length-4);
                if (fcs_header == fcs_frame)
                    length -= 4;
                if (header_length >= length) {
                    FRAMERR(frame, "radiotap headers corrupt\n");
                    return;
                }
            }

            offset = 8;

            if (features & 0x000001) offset += 8;    /* TSFT - Timestamp */
            if (features & 0x000002) {
                flags = px[offset];
                offset += 1;

                /* If there's an FCS at the end, then remove it so that we
                 * don't try to decode it as payload */
                if (flags & 0x10)
                    length -= 4;
            }
            if (features & 0x000004) offset += 1;    /* Rate */
            if (features & 0x000008 && offset+2<header_length) {
                unsigned frequency = ex16le(px+offset);
                int channel;
                channel = wifi_frequency_to_channel(frequency);
                squirrel->sqdb->kludge.channel = channel;
                offset += 2;
            }
            if (features & 0x000008 && offset+2<header_length) {
                /*unsigned channel_flags = ex16le(px+offset);*/
                offset += 2;
            }
            if (features & 0x000010) offset += 2;    /* FHSS */
            if (features & 0x000020 && offset+1<header_length) {
                frame->dbm = ((signed char*)px)[offset];
                squirrel->sqdb->kludge.dbm = frame->dbm;
                offset += 1;
            }
            if (features & 0x000040 && offset+1<header_length) {
                dbm_noise = ((signed char*)px)[offset];

            }
            if (features & 0x000080 && offset+1<header_length) {
                lock_quality = ((unsigned char*)px)[offset];
            }

            if (flags & 0x40) {
                /* FCS/CRC error */
                return;
            }


            squirrel_wifi_frame(squirrel, frame, px+header_length, length-header_length);

        }
            break;
        default:
            FRAMERR(frame, "unknown linktype = %d (expected Ethernet or wifi)\n", frame->layer2_protocol);
            break;
    }
}

