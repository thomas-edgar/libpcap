/* 
 * File:   pcap_serial_linux.h
 * Author: Thomas W. Edgar
 *
 * Created on February 4, 2010, 6:52 PM
 */

#ifndef _PCAP_SERIAL_LINUX_H
#define	_PCAP_SERIAL_LINUX_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Prototypes for Serial-related functions
 */
int serial_platform_finddevs(pcap_if_t **alldevsp, char *err_str);
pcap_t *serial_create(const char *device, char *ebuf);
int listen_serial_port(int portDeviceID, unsigned char* listenbuf, int buf_size);

int buffer_get_space_size(pcap_t* handle, int start, int end);
int buffer_size_free(pcap_t* handle);
int buffer_get_data_size(pcap_t* handle);
int buffer_get_packet_len(pcap_t* handle, int start, int end);
void buffer_add_data(pcap_t* handle, unsigned char *data, int size);
void buffer_get_data(pcap_t* handle, int pos, unsigned char * data, int size);
void buffer_remove_data(pcap_t* handle, int pos, unsigned char * data, int size);
void buffer_move_read_pointer(pcap_t* handle, int pos, int size);
u_char buffer_get_byte(pcap_t* handle, int pos, int offset);
void buffer_clear(pcap_t* handle);
void clear_queue(pcap_t* handle);


#ifdef	__cplusplus
}
#endif

#endif	/* _PCAP_SERIAL_LINUX_H */