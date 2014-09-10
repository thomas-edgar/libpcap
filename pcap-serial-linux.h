/* 
 * File:   pcap_serial_linux.h
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

#ifndef _PCAP_SERIAL_LINUX_H
#define	_PCAP_SERIAL_LINUX_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Prototypes for Serial-related functions
 */
int serial_findalldevs(pcap_if_t **alldevsp, char *err_str);
pcap_t *serial_create(const char *device, char *ebuf, int *is_ours);
int serial_configure(pcap_t *p, int baud, int databits, int stopbits, int parity);
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