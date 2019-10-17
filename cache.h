
#ifndef __CACHE_H__
#define __CACHE_H__

void cache_synack(struct fourtuple *fourtp, unsigned char ttl);
void cache_rst(struct fourtuple *fourtp, unsigned char ttl);
void cache_rstack(struct fourtuple *fourtp, unsigned char ttl);


#endif

