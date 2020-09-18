#include <linux/types.h>
#include <linux/string.h>
#include <linux/kernel.h>
#include <linux/numa.h>
#include <linux/gfp.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include "uhcall.h"
#include "uhsign.h"

void do_uhsign(void *bufptr) {
  uhsign_param_t *ptr_uhcp = (uhsign_param_t *)bufptr;
  uhcall(UAPP_UHSIGN_FUNCTION_SIGN, ptr_uhcp, sizeof(uhsign_param_t));
}

void hyp_hmac(char * data, int len, unsigned char * digest) {
  struct page *k_page;
  k_page = alloc_page(GFP_KERNEL | __GFP_ZERO);
  uhsign_param_t *uhcp = (uhsign_param_t *)page_address(k_page);
  memcpy(uhcp->pkt, data, len);
  uhcp->pkt_size=len;
  uhcp->vaddr=(uint32_t)uhcp;
  uhcall(UAPP_UHSIGN_FUNCTION_SIGN, (uint32_t)page_to_phys(k_page), sizeof(uhsign_param_t));
  memcpy(digest, uhcp->digest, HMAC_DIGEST_SIZE);
  __free_page(k_page);

}
