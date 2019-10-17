
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "globals.h"
#include "hping2.h"
#include "logging.h"
#include "redis.h"
#include "util.h"

#define SYN_ACK_TIMEOUT 5
#define RST_TIMEOUT 5
#define RST_ACK_TIMEOUT 1
#define RST_ATTACK_TIMEOUT 90


static void set_aflag(u_int32_t saddr, u_int32_t daddr)
{
    char key[64];
    sprintf(key, "rst:attack:%u_%u", saddr, daddr);
    set_int_ex(key, 1, RST_ATTACK_TIMEOUT);
}

static int get_aflag(u_int32_t saddr, u_int32_t daddr)
{
    char key[64];
    sprintf(key, "rst:attack:%u_%u", saddr, daddr);
    return get_int(key);
}


void cache_synack(struct fourtuple *fourtp, unsigned char ttl)
{
    char key[100];
    //sprintf(key, "synack:%u_%hu_%u_%hu", fourtp->daddr, fourtp->dport, fourtp->saddr, fourtp->sport);
    //unsigned char oldttl = get_int(key);
    //if (oldttl && oldttl != ttl) {
        /* received fake syn-ack */
    //}

    //set_int_ex(key, ttl, SYN_ACK_TIMEOUT);

    if (ttl >= legal_ttl - 1 && ttl <= legal_ttl + 1) {
        /* considers it as a legal rstack */
        return;
    }

    succsynack = 1;
}

void cache_rst(struct fourtuple *fourtp, unsigned char ttl)
{
    char key[100];

    //sprintf(key, "rst:%u_%hu_%u_%hu", fourtp->daddr, fourtp->dport, fourtp->saddr, fourtp->sport);
    //set_int_ex(key, ttl, RST_TIMEOUT);

    //unsigned int oldttl = get_int(key);
    
    if (ttl >= legal_ttl - 1 && ttl <= legal_ttl + 1) {
        /* considers it as a legal rstack */
        return;
    }

    /* Triggered Type 1 Reset */
    log_exp("Probably Type 1 Reset triggered!!!");
    type1rst = 1;
}

void cache_rstack(struct fourtuple *fourtp, unsigned char ttl)
{
    char key[100];

    if (ttl >= legal_ttl - 1 && ttl <= legal_ttl + 1) {
        /* considers it as a legal rstack */
        return;
    }

    succrst = 1;

    sprintf(key, "rstack:%u_%hu_%u_%hu", fourtp->daddr, fourtp->dport, fourtp->saddr, fourtp->sport);
    unsigned int oldttl = get_int(key);
    
    if (oldttl) {
        /* Triggered Type 2 Reset */
        log_exp("Probably Type 2 Reset triggered!!!");
        type2rst = 1;
        succrst = 0;
        set_aflag(fourtp->daddr, fourtp->saddr);
    }
    set_int_ex(key, ttl, RST_ACK_TIMEOUT);
}


