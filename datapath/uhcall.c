/*
 * @UBERXMHF_LICENSE_HEADER_START@
 *
 * uber eXtensible Micro-Hypervisor Framework (Raspberry Pi)
 *
 * Copyright 2018 Carnegie Mellon University. All Rights Reserved.
 *
 * NO WARRANTY. THIS CARNEGIE MELLON UNIVERSITY AND SOFTWARE ENGINEERING
 * INSTITUTE MATERIAL IS FURNISHED ON AN "AS-IS" BASIS. CARNEGIE MELLON
 * UNIVERSITY MAKES NO WARRANTIES OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
 * AS TO ANY MATTER INCLUDING, BUT NOT LIMITED TO, WARRANTY OF FITNESS FOR
 * PURPOSE OR MERCHANTABILITY, EXCLUSIVITY, OR RESULTS OBTAINED FROM USE OF
 * THE MATERIAL. CARNEGIE MELLON UNIVERSITY DOES NOT MAKE ANY WARRANTY OF
 * ANY KIND WITH RESPECT TO FREEDOM FROM PATENT, TRADEMARK, OR COPYRIGHT
 * INFRINGEMENT.
 *
 * Released under a BSD (SEI)-style license, please see LICENSE or
 * contact permission@sei.cmu.edu for full terms.
 *
 * [DISTRIBUTION STATEMENT A] This material has been approved for public
 * release and unlimited distribution.  Please see Copyright notice for
 * non-US Government use and distribution.
 *
 * Carnegie Mellon is registered in the U.S. Patent and Trademark Office by
 * Carnegie Mellon University.
 *
 * @UBERXMHF_LICENSE_HEADER_END@
 */

/*
 * Author: Amit Vasudevan (amitvasudevan@acm.org)
 *
 */

/*
 * uhcall -- guest interface for micro hypervisor hypercall
 *
 * author: amit vasudevan (amitvasudevan@acm.org)
 */

#include <linux/types.h>
#include <linux/kernel.h>

#include "uhcall.h"


static void uhcall_hvc(uint32_t uhcall_function, void *uhcall_buffer, uint32_t uhcall_buffer_len) {
    asm volatile
    ( " mov r0, %[in_0]\r\n"
      " mov r1, %[in_1]\r\n"
      " mov r2, %[in_2]\r\n"
      ".long 0xE1400071 \r\n"
      : 
      : [in_0] "r" (uhcall_function), [in_1] "r" (uhcall_buffer), [in_2] "r" (uhcall_buffer_len)
      : "r0", "r1", "r2"
      );
}
  

//////
// uhcall micro-hypervisor hypercall interface
// return true on success, false on error
//////
bool uhcall(uint32_t uhcall_function, uint32_t uhcall_buffer_pa, uint32_t uhcall_buffer_len){
	
#if 0
  //get buffer physical address
  uhcall_buffer_paddr=virt_to_phys(uhcall_buffer);	
#endif

  uhcall_hvc(uhcall_function, (void *)uhcall_buffer_pa, uhcall_buffer_len);

  //hypercall succeeded
  return true;
}
