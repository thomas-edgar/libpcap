/* 
 * pcap_dnp3_linux.c: Packet capture for serial DNP3 frames
 * 
 * Copyright © 2014, Battelle Memorial Institute. All rights reserved.
 * 
 * Battelle Memorial Institute (hereinafter Battelle) hereby grants 
 * permission to any person or entity lawfully obtaining a copy of this 
 * software and associated documentation files (hereinafter “the Software”) 
 * to redistribute and use the Software in source and binary forms, with or 
 * without modification.  Such person or entity may use, copy, modify, merge, 
 * publish, distribute, sublicense, and/or sell copies of the Software, and may 
 * permit others to do so, subject to the following conditions:
 * 1. Redistributions of source code must retain the above copyright notice, 
 *    this list of conditions and the following disclaimers. 
 * 2. Redistributions in binary form must reproduce the above copyright notice, 
 *    this list of conditions and the following disclaimer in the documentation 
 *    and/or other materials provided with the distribution. 
 * 3. Other than as used herein, neither the name Battelle Memorial Institute 
 *    or Battelle may be used in any form whatsoever without the express written 
 *    consent of Battelle.  
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED. IN NO EVENT SHALL BATTELLE OR CONTRIBUTORS BE LIABLE FOR ANY 
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND 
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF 
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This Software was produced by Battelle under Contract No. DE-AC05-76RL01830 
 * with the Department of Energy (hereinafter “DOE”).  The Government is 
 * granted for itself and others acting on its behalf a nonexclusive, paid-up, 
 * irrevocable worldwide license in the portion of the Software produced at 
 * least in part with Government funds to reproduce, prepare derivative works, 
 * and perform publicly and display publicly, and to permit others to do so.  
 * The specific term of the Government license can be identified by inquiry made 
 * to Battelle or DOE.  Neither the United States Government nor the DOE, nor 
 * any of their employees, makes any warranty, express or implied, or assumes 
 * any legal liability or responsibility for the accuracy, completeness or 
 * usefulness of any data, apparatus, product or process disclosed, or represents 
 * that its use would not infringe privately owned rights.  
 *
 * Author: Thomas W. Edgar
 * 
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "pcap-int.h"
#include "pcap-serial-linux.h"
#include "pcap-dnp3-linux.h"
#include "pcap/serial.h"

#ifdef NEED_STRERROR_H
#include "strerror.h"
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <termios.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <dirent.h>
#include <byteswap.h>
#include <time.h>

#define SYNCH_1  0x05
#define SYNCH_2  0x64


/* forward declaration */
static int dnp_read_linux(pcap_t *, int, pcap_handler, u_char *);
static int dnp_inject_linux(pcap_t *, const void *, size_t);
static int dnp_setfilter_linux(pcap_t *, struct bpf_program *);
static int dnp_setdirection_linux(pcap_t *, pcap_direction_t );
static int dnp_stats_linux(pcap_t *, struct pcap_stat *);
static u_int dnp_calculate_crc(u_char *, u_int);

int
dnp_configure_datalink(pcap_t *handle)
{
    struct pcap_serial_linux *handlep = handle->priv;

    handle->linktype = DLT_DNP3;
    handle->read_op = dnp_read_linux;
    handle->stats_op = dnp_stats_linux;
    handle->inject_op = dnp_inject_linux;
    handle->setfilter_op = dnp_setfilter_linux;
    handle->setdirection_op = dnp_setdirection_linux;
    handlep->read_pointer = 0;
    handlep->write_pointer = 0;
}


static int
dnp_read_linux(pcap_t *handle, int max_packets, pcap_handler callback, u_char *user)
{
    unsigned short length;
    int numRead, packet_count;
    u_char *packet_data;
    u_char *crc_data;
    struct pcap_pkthdr pkth;
    u_char datachunk[1000];
    u_int header_crc, last;
    struct pcap_serial_linux *handlep = handle->priv;

    packet_count = 0;
    numRead = listen_serial_port(handle->fd, datachunk, sizeof(datachunk));

    /* Check I/O for more data and if so add it to the buffer */
    if (numRead > 0 && numRead < buffer_size_free(handle)) {
        printf("Adding data to buffer %d\n", numRead);
        buffer_add_data(handle, datachunk, numRead);
    }

    /* Parse up to number of packets requested from buffer */
     while (handlep->read_pointer != handlep->write_pointer && packet_count < max_packets) {
        // look for a sync token
         printf("read pointer = %d write pointer = %d\n", handlep->read_pointer, handlep->write_pointer);
         if(buffer_get_byte(handle, handlep->read_pointer, 0) == SYNCH_1 &&
                 buffer_get_byte(handle, handlep->read_pointer, 1) == SYNCH_2)
         {
             printf("Found Sync bytes\n");
             /* Found a potential packet; check a few more things to know for sure */
             /* Check for enough bytes for header */
             if(buffer_get_data_size(handle) < 10 ) {
                 /* Not enough data to parse */
                 printf("Not enough data to parse\n");
                 break;
             }
             /* Check for valid header crc */
             header_crc = ((u_int) buffer_get_byte(handle, handlep->read_pointer, 9) << 8 | buffer_get_byte(handle, handlep->read_pointer, 8));
             crc_data = malloc(8);
             buffer_get_data(handle, handlep->read_pointer, crc_data, 8);
             if(header_crc != (dnp_calculate_crc(crc_data, 8))) {
                 /* The header CRC didn't match so either not a packet or problem sending;
                  * either way can't frame it  so move forward in buffer and skip it */
                 printf("Invalid CRC found %d expected %d\n", header_crc, dnp_calculate_crc(handle->buffer, 8));
                 buffer_move_read_pointer(handle, handlep->read_pointer, 1);
             }
             else {
               /* Found a packet; parse length and send to callback */
                 printf("Found packet\n");
                length = (unsigned short) buffer_get_byte(handle, handlep->read_pointer, 2);
                if((length-5)%16 > 0) last = 2;
                else last = 0;
                length += 3 + 2 + ((length-5)/16)*2 + last;
                if(buffer_get_data_size(handle) >= length) {
                    /* send to callback */
                    //printf("have enough data for packet %d %d\n", buffer_get_data_size(handle), length);
                    pkth.caplen = length;
                    pkth.len = length;
                    gettimeofday(&pkth.ts, NULL);
                    packet_data = malloc(length);
                    buffer_remove_data(handle, handlep->read_pointer, packet_data, length);
                    callback(user, &pkth, packet_data);
                    packet_count++;
                }
                else if(length > handle->bufsize) {
                    /* packet is too big for buffer which is not possible so skip ahead
                     and keep processing*/
                    buffer_move_read_pointer(handle, handlep->read_pointer, 1);
                }
                else {
                    /* Not enough data to parse */
                    break;
                }
            }
         }
         else buffer_move_read_pointer(handle, handlep->read_pointer, 1);
         free(crc_data);
     }
    return packet_count;
}

static int
dnp_inject_linux(pcap_t *handle, const void *buf, size_t size)
{
	snprintf(handle->errbuf, PCAP_ERRBUF_SIZE, "inject not supported on "
		"Serial devices");
	return (-1);
}

static int
dnp_stats_linux(pcap_t *handle, struct pcap_stat *stats)
{
	struct pcap_serial_linux *handlep = handle->priv;

	stats->ps_recv = handlep->ps_recv;
	stats->ps_drop = handlep->ps_drop;
	stats->ps_ifdrop = handlep->ps_ifdrop;
	return 0;
}

static int
dnp_setfilter_linux(pcap_t *p, struct bpf_program *fp)
{
	return 0;
}

static int
dnp_setdirection_linux(pcap_t *p, pcap_direction_t d)
{
	p->direction = d;
	return 0;
}

static u_short crctable[256] =
{
 0x0000, 0x365E, 0x6CBC, 0x5AE2, 0xD978, 0xEF26, 0xB5C4, 0x839A,
 0xFF89, 0xC9D7, 0x9335, 0xA56B, 0x26F1, 0x10AF, 0x4A4D, 0x7C13,
 0xB26B, 0x8435, 0xDED7, 0xE889, 0x6B13, 0x5D4D, 0x07AF, 0x31F1,
 0x4DE2, 0x7BBC, 0x215E, 0x1700, 0x949A, 0xA2C4, 0xF826, 0xCE78,
 0x29AF, 0x1FF1, 0x4513, 0x734D, 0xF0D7, 0xC689, 0x9C6B, 0xAA35,
 0xD626, 0xE078, 0xBA9A, 0x8CC4, 0x0F5E, 0x3900, 0x63E2, 0x55BC,
 0x9BC4, 0xAD9A, 0xF778, 0xC126, 0x42BC, 0x74E2, 0x2E00, 0x185E,
 0x644D, 0x5213, 0x08F1, 0x3EAF, 0xBD35, 0x8B6B, 0xD189, 0xE7D7,
 0x535E, 0x6500, 0x3FE2, 0x09BC, 0x8A26, 0xBC78, 0xE69A, 0xD0C4,
 0xACD7, 0x9A89, 0xC06B, 0xF635, 0x75AF, 0x43F1, 0x1913, 0x2F4D,
 0xE135, 0xD76B, 0x8D89, 0xBBD7, 0x384D, 0x0E13, 0x54F1, 0x62AF,
 0x1EBC, 0x28E2, 0x7200, 0x445E, 0xC7C4, 0xF19A, 0xAB78, 0x9D26,
 0x7AF1, 0x4CAF, 0x164D, 0x2013, 0xA389, 0x95D7, 0xCF35, 0xF96B,
 0x8578, 0xB326, 0xE9C4, 0xDF9A, 0x5C00, 0x6A5E, 0x30BC, 0x06E2,
 0xC89A, 0xFEC4, 0xA426, 0x9278, 0x11E2, 0x27BC, 0x7D5E, 0x4B00,
 0x3713, 0x014D, 0x5BAF, 0x6DF1, 0xEE6B, 0xD835, 0x82D7, 0xB489,
 0xA6BC, 0x90E2, 0xCA00, 0xFC5E, 0x7FC4, 0x499A, 0x1378, 0x2526,
 0x5935, 0x6F6B, 0x3589, 0x03D7, 0x804D, 0xB613, 0xECF1, 0xDAAF,
 0x14D7, 0x2289, 0x786B, 0x4E35, 0xCDAF, 0xFBF1, 0xA113, 0x974D,
 0xEB5E, 0xDD00, 0x87E2, 0xB1BC, 0x3226, 0x0478, 0x5E9A, 0x68C4,
 0x8F13, 0xB94D, 0xE3AF, 0xD5F1, 0x566B, 0x6035, 0x3AD7, 0x0C89,
 0x709A, 0x46C4, 0x1C26, 0x2A78, 0xA9E2, 0x9FBC, 0xC55E, 0xF300,
 0x3D78, 0x0B26, 0x51C4, 0x679A, 0xE400, 0xD25E, 0x88BC, 0xBEE2,
 0xC2F1, 0xF4AF, 0xAE4D, 0x9813, 0x1B89, 0x2DD7, 0x7735, 0x416B,
 0xF5E2, 0xC3BC, 0x995E, 0xAF00, 0x2C9A, 0x1AC4, 0x4026, 0x7678,
 0x0A6B, 0x3C35, 0x66D7, 0x5089, 0xD313, 0xE54D, 0xBFAF, 0x89F1,
 0x4789, 0x71D7, 0x2B35, 0x1D6B, 0x9EF1, 0xA8AF, 0xF24D, 0xC413,
 0xB800, 0x8E5E, 0xD4BC, 0xE2E2, 0x6178, 0x5726, 0x0DC4, 0x3B9A,
 0xDC4D, 0xEA13, 0xB0F1, 0x86AF, 0x0535, 0x336B, 0x6989, 0x5FD7,
 0x23C4, 0x159A, 0x4F78, 0x7926, 0xFABC, 0xCCE2, 0x9600, 0xA05E,
 0x6E26, 0x5878, 0x029A, 0x34C4, 0xB75E, 0x8100, 0xDBE2, 0xEDBC,
 0x91AF, 0xA7F1, 0xFD13, 0xCB4D, 0x48D7, 0x7E89, 0x246B, 0x1235
};

/* calculates crc given a buffer of characters and a length of buffer */
static u_int
dnp_calculate_crc(u_char *data, u_int len) {
  u_int crc = 0;
  const u_char *p = (const u_char *)data;
  while(len-- > 0)
    crc = crctable[(crc ^ *p++) & 0xff] ^ (crc >> 8);
  return (~crc) & 0xFFFF;
}

