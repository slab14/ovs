#include <linux/types.h>
#include <linux/string.h>
#include "uhcall.h"
#include "uhsign.h"

__attribute__((aligned(4096))) __attribute__((section(".data"))) uhsign_param_t uhcp;

void do_uhsign(void *bufptr) {
  uhsign_param_t *ptr_uhcp = (uhsign_param_t *)bufptr;
  uhcall(UAPP_UHSIGN_FUNCTION_SIGN, ptr_uhcp, sizeof(uhsign_param_t));
}

void hyp_hmac(char * data, int len, unsigned char * digest) {
  memcpy(&uhcp.pkt, data, len);
  uhcp.pkt_size=len;
  uhcp.vaddr=(uint32_t)&uhcp;
  do_uhsign((void *)&uhcp);
  memcpy(digest, &uhcp.digest, HMAC_DIGEST_SIZE);
}
