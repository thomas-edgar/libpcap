/* 
 * pcap_modbus_linux.c: Packet capture for serial Modbus RTU frames
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
#include "pcap-modbus-linux.h"
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

/* forward declaration */
static int modbus_inject_linux(pcap_t *, const void *, size_t);
static int modbus_setfilter_linux(pcap_t *, struct bpf_program *);
static int modbus_setdirection_linux(pcap_t *, pcap_direction_t );
static int modbus_stats_linux(pcap_t *, struct pcap_stat *);

int
modbus_configure_datalink(pcap_t *handle)
{
    struct pcap_serial_linux *handlep = handle->priv;

    handle->linktype = DLT_MODBUS;
    handle->stats_op = modbus_stats_linux;
    handle->inject_op = modbus_inject_linux;
    handle->setfilter_op = modbus_setfilter_linux;
    handle->setdirection_op = modbus_setdirection_linux;
    handlep->read_pointer = 0;
    handlep->write_pointer = 0;
}

static int
modbus_inject_linux(pcap_t *handle, const void *buf, size_t size)
{
	snprintf(handle->errbuf, PCAP_ERRBUF_SIZE, "inject not supported on "
		"Serial devices");
	return (-1);
}

static int
modbus_stats_linux(pcap_t *handle, struct pcap_stat *stats)
{
	struct pcap_serial_linux *handlep = handle->priv;

	stats->ps_recv = handlep->ps_recv;
	stats->ps_drop = handlep->ps_drop;
	stats->ps_ifdrop = handlep->ps_ifdrop;
	return 0;
}

static int
modbus_setfilter_linux(pcap_t *p, struct bpf_program *fp)
{
	return 0;
}

static int
modbus_setdirection_linux(pcap_t *p, pcap_direction_t d)
{
	p->direction = d;
	return 0;
}

