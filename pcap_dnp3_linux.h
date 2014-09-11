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

#ifndef _PCAP_DNP3_LINUX_H
#define _PCAP_DNP3_LINUX_H

#ifdef __cplusplus
extern "C" {
#endif

int dnp_configure_datalink(pcap_t *handle);

#ifdef __cplusplus
}
#endif

#endif /* _PCAP_DNP3_LINUX_H */