#include <linux/types.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/numa.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include "uhcall.h"
#include "uhsign.h"

//#include <linux/irqflags.h>

void hyp_hmac(char * data, int len, unsigned char * digest) {
  struct page *k_page = alloc_page(GFP_KERNEL | __GFP_ZERO);
  uhsign_param_t *uhcp = (uhsign_param_t *)page_address(k_page);
  memcpy(uhcp->pkt, data, len);
  uhcp->pkt_size=len;
  uhcp->vaddr=(uint32_t)uhcp;
  //  local_irq_disable();
  uhcall(UAPP_UHSIGN_FUNCTION_SIGN, (uint32_t)page_to_phys(k_page), sizeof(uhsign_param_t));
  //local_irq_enable();  
  memcpy(digest, uhcp->digest, HMAC_DIGEST_SIZE);
  __free_page(k_page);
}
