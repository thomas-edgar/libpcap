/* 
 * serialtest.c: Test program for serial capture capability.
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
#include "pcap-int.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <pcap.h>

static void displayMessage(const u_char *, int);
void serialtest_callback(u_char *, const struct pcap_pkthdr *, const u_char *);

int main(int argc, char **argv)
{
  int status;
  int linktype = 0;
  pcap_if_t *alldevs;
  pcap_if_t *d;
  pcap_if_t *serial = NULL;
  pcap_if_t *serial2 = NULL;
  pcap_t *descr1, *descr2;
  pcap_dumper_t *pd;
  char errbuf[PCAP_ERRBUF_SIZE+1];
  char filename[] = "./test.pcap";
  int packet_count = 0;
  FILE *f;
  int mode;
  int packet_total;

  if(argc < 7) {
  	printf("Error too few arguments.\n Usage serialtest mode device1 baud1 device2 baud2 packets output\n Modes: sscp | modbus | dnp | serial\nDevice example: ttyS1\nBauds: 300, 1200, 2400, 4800, 9600, 19200, 38400, 56000\nPackets is the number of packets to capture\nOutput is the filename for the output pcap file\n");  
	return -1;
  } 

  if(!strcmp(argv[1], "sscp")) mode = 2;
  else if(!strcmp(argv[1], "modbus")) mode = 3;
  else if(!strcmp(argv[1], "dnp")) mode = 4;
  else if(!strcmp(argv[1], "serial")) mode = 1;
  else {
    /* Unsupported argument; print error message and quit */
    printf("Unsupported argument.  The supported values are:\n");
    printf("sscp, modbus, dnp, and no argument\n");
  }


  packet_total = atoi(argv[6]);

printf("SerialTest | Mode : ");
if(mode ==1 ) printf ("Serial\n");
else printf("%s\n", argv[1]);

  /* Open pcap file to save output */

#if !defined(WIN32) && !defined(MSDOS)
        f = fopen(argv[7], "w");
#else
        f = fopen(argv[7], "wb");
#endif
        if (f == NULL) {
            printf("Error opening pcap file. %s\n", filename);
                return 0;
        }

  descr1 = pcap_create(argv[2], errbuf);
  if((status = pcap_set_snaplen(descr1, 32768)) < 0) {
      printf("Error configuring serial port %d.\n", status);
      exit(1);
  }
  if((status = pcap_configure_serial(descr1, atoi(argv[3]), 8, 1, 0)) != 1) {
      switch(status) {
	case PCAP_ERROR_BAUD: {
	  printf("Error configuring serial port: Unsupported BAUD rate\n");
	  break;
	}
	case PCAP_ERROR_DATABITS: {
	  printf("Error configuring serial port: Unsupported databits\n");
	  break;
	}
	case PCAP_ERROR_STOPBITS: {
	  printf("Error configuring serial port: Unsupported stopbits\n");
	  break;
	}
	case PCAP_ERROR_PARITY: {
	  printf("Error configuring serial port: Unsupported parity\n");
	  break;
	}
	default: break;
	}
      exit(1);
  }
  if((status = pcap_activate(descr1)) < 0) {
      printf("Error activating serial port %d.\n", status);
      exit(1);
  }


  printf("mode = %d\n", mode);

  switch(mode) {
      case 2: {
        pcap_set_datalink(descr1, DLT_SSCP);
        break;
      }
      case 3: {
        pcap_set_datalink(descr1, DLT_MODBUS);
        break;
      }
      case 4: {
          pcap_set_datalink(descr1, DLT_DNP3);
          break;
      }
      case 1: /* do nothing */
      default:
          break;
  }

  printf("Opened %s\n", descr1->opt.source);


  descr2 = pcap_create(argv[4], errbuf);
  if((status = pcap_set_snaplen(descr2, 32768)) < 0) {
      printf("Error configuring serial port %d.\n", status);
      exit(1);
  }
    if(!(status = pcap_configure_serial(descr2, atoi(argv[5]), 8, 1, 0))) {
       switch(status) {
	case PCAP_ERROR_BAUD: {
	  printf("Error configuring serial port: Unsupported BAUD rate\n");
	  break;
	}
	case PCAP_ERROR_DATABITS: {
	  printf("Error configuring serial port: Unsupported databits\n");
	  break;
	}
	case PCAP_ERROR_STOPBITS: {
	  printf("Error configuring serial port: Unsupported stopbits\n");
	  break;
	}
	case PCAP_ERROR_PARITY: {
	  printf("Error configuring serial port: Unsupported parity\n");
	  break;
	}
	default: break;
	}
      exit(1);
  }
    if((status = pcap_activate(descr2)) < 0) {
      printf("Error activating serial port %d.\n", status);
      exit(1);
  }

    switch(mode) {
      case 2: {
        pcap_set_datalink(descr2, DLT_SSCP);
        break;
      }
      case 3: {
        pcap_set_datalink(descr2, DLT_MODBUS);
        break;
      }
      case 4: {
          pcap_set_datalink(descr2, DLT_DNP3);
          break;
      }
      case 1: /* do nothing */
      default:
          break;
  }

  printf("Opened %s\n", descr2->opt.source);

  printf("Opening dump file for both streams...");
    if((pd = pcap_dump_fopen(descr1, f)) == NULL) {
      printf("Error opening pcap file. %s\n", pcap_geterr(descr1));
      exit(-1);
  }
  printf("Complete\n");
  printf("Configured %s and %s\n", descr1->opt.source, descr2->opt.source);
  printf("%d\n", pcap_dispatch(descr1, 10, serialtest_callback, (char *)pd));
  while(packet_count < packet_total) {
      packet_count += pcap_dispatch(descr1, 10, serialtest_callback, (char *)pd);
      //printf("packet count %d\n", packet_count);
      packet_count += pcap_dispatch(descr2, 10, serialtest_callback, (char *)pd);
      //printf("packet count %d\n", packet_count);
  }
  printf("Found all packets\n");

  pcap_dump_close(pd);
  pcap_close(descr1);
  pcap_close(descr2);
  exit(0);
}

void serialtest_callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    printf("Recieved Packet\n");
    displayMessage(packet, pkthdr->caplen);
    pcap_dump(useless, pkthdr, packet);
}





static void displayMessage(const u_char* data, int size) {
    int i;

    for (i = 0; i < size; i++) {
        if (data[i] == '\0')
            printf("0x00 ");
        else
            printf("0x%x ", data[i]);
    }
    printf("\n");
}
