#ifndef _PCAP_SERIAL_STRUCTS_H__
#define _PCAP_SERIAL_STRUCTS_H__

#define SERIAL_PARSER_TIMEOUT   500
#define QUEUE_MAX 100

/*
 * Contains the location of the start of the packet and the time the packet was
 * recieved.  Used by the time based packet parser and circular buffer.
 * fields are in network byte order
 */
typedef struct _pcap_serial_packet_pointer {
	u_int32_t position;
        u_int32_t length;
        struct timeval ts;
} pcap_serial_packet_pointer;

#endif