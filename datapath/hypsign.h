#ifndef __HYPSIGN_H__
#define __HYPSIGN_H__

#ifndef __ASSEMBLY__

void do_uhsign(void *bufptr);
void hyp_hmac(char * data, int len, unsigned char * digest);

#endif //__ASSEMBLY__

#endif //__HYPSIGN_H__
