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

static void ifprint(pcap_if_t *d);
static char *iptos(bpf_u_int32 in);
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

  if(argc > 1) {
      if(!strcmp(argv[1], "sscp")) mode = 2;
      else if(!strcmp(argv[1], "modbus")) mode = 3;
      else if(!strcmp(argv[1], "dnp")) mode = 4;
      else {
          /* Unsupported argument; print error message and quit */
          printf("Unsupported argument.  The supported values are:\n");
          printf("sscp, modbus, dnp, and no argument\n");
      }
  }
  else mode = 1;

  if(mode == 1) printf("SerialTest | Mode : Serial\n");
  else printf("SerialTest | Mode : %s\n", argv[1]);

/*
  if (pcap_findalldevs(&alldevs, errbuf) == -1)
  {
    fprintf(stderr,"Error in pcap_findalldevs: %s\n",errbuf);
    exit(1);
  }
  for(d=alldevs;d;d=d->next)
  {
    ifprint(d);
    if((strncmp(d->name, "ttyS0", 5) == 0 || strncmp(d->name, "ttyS1", 5) == 0 ||
            strncmp(d->name, "ttyS2", 5) == 0 || strncmp(d->name, "ttyS3", 5) == 0 ||
            strncmp(d->name, "ttyUSB0", 7) == 0 || strncmp(d->name, "ttyUSB1", 7) == 0 ||
            strncmp(d->name, "ttyUSB2", 7) == 0 || strncmp(d->name, "ttyUSB3", 7) == 0)) {
        printf("Found a serial interface.\n");
        if(serial == NULL) serial = d;
        else if(serial2 == NULL) serial2 = d;
    }
  }


  if(serial == NULL || serial2 == NULL) {
    fprintf(stderr,"Error: Did not find two serial interfaces.\n");
    exit(1);
  }
*/
  /* Open pcap file to save output */

#if !defined(WIN32) && !defined(MSDOS)
        f = fopen(filename, "w");
#else
        f = fopen(filename, "wb");
#endif
        if (f == NULL) {
            printf("Error opening pcap file. %s\n", filename);
                return 0;
        }


  descr1 = pcap_create("ttyS1", errbuf);
  if((status = pcap_set_snaplen(descr1, BUFSIZ)) < 0) {
      printf("Error configuring serial port %d.\n", status);
      exit(1);
  }
  if((status = pcap_configure_serial(descr1, 9600, 8, 1, 0)) != 1) {
      printf("Error configuring serial port %d.\n", status);
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


  descr2 = pcap_create("ttyS2", errbuf);
  if((status = pcap_set_snaplen(descr2, BUFSIZ)) < 0) {
      printf("Error configuring serial port %d.\n", status);
      exit(1);
  }
    if(!(status = pcap_configure_serial(descr2, 9600, 8, 1, 0))) {
      printf("Error configuring serial port %d.\n", status);
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
  while(packet_count < 6) {
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

static void ifprint(pcap_if_t *d)
{
  pcap_addr_t *a;
#ifdef INET6
  char ntop_buf[INET6_ADDRSTRLEN];
#endif

  printf("%s\n",d->name);
  if (d->description)
    printf("\tDescription: %s\n",d->description);
  printf("\tLoopback: %s\n",(d->flags & PCAP_IF_LOOPBACK)?"yes":"no");

  for(a=d->addresses;a;a=a->next) {
    switch(a->addr->sa_family)
    {
      case AF_INET:
        printf("\tAddress Family: AF_INET\n");
        if (a->addr)
          printf("\t\tAddress: %s\n",
            inet_ntoa(((struct sockaddr_in *)(a->addr))->sin_addr));
        if (a->netmask)
          printf("\t\tNetmask: %s\n",
            inet_ntoa(((struct sockaddr_in *)(a->netmask))->sin_addr));
        if (a->broadaddr)
          printf("\t\tBroadcast Address: %s\n",
            inet_ntoa(((struct sockaddr_in *)(a->broadaddr))->sin_addr));
        if (a->dstaddr)
          printf("\t\tDestination Address: %s\n",
            inet_ntoa(((struct sockaddr_in *)(a->dstaddr))->sin_addr));
        break;
#ifdef INET6
      case AF_INET6:
        printf("\tAddress Family: AF_INET6\n");
        if (a->addr)
          printf("\t\tAddress: %s\n",
            inet_ntop(AF_INET6,
               ((struct sockaddr_in6 *)(a->addr))->sin6_addr.s6_addr,
               ntop_buf, sizeof ntop_buf));
        if (a->netmask)
          printf("\t\tNetmask: %s\n",
            inet_ntop(AF_INET6,
              ((struct sockaddr_in6 *)(a->netmask))->sin6_addr.s6_addr,
               ntop_buf, sizeof ntop_buf));
        if (a->broadaddr)
          printf("\t\tBroadcast Address: %s\n",
            inet_ntop(AF_INET6,
              ((struct sockaddr_in6 *)(a->broadaddr))->sin6_addr.s6_addr,
               ntop_buf, sizeof ntop_buf));
        if (a->dstaddr)
          printf("\t\tDestination Address: %s\n",
            inet_ntop(AF_INET6,
              ((struct sockaddr_in6 *)(a->dstaddr))->sin6_addr.s6_addr,
               ntop_buf, sizeof ntop_buf));
        break;
#endif
      default:
        printf("\tAddress Family: Unknown (%d)\n", a->addr->sa_family);
        break;
    }
  }
  printf("\n");
}

/* From tcptraceroute */
#define IPTOSBUFFERS	12
static char *iptos(bpf_u_int32 in)
{
	static char output[IPTOSBUFFERS][3*4+3+1];
	static short which;
	u_char *p;

	p = (u_char *)&in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output[which];
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

