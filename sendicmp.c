/* 
 * $smu-mark$ 
 * $name: sendicmp.c$ 
 * $author: Salvatore Sanfilippo <antirez@invece.org>$ 
 * $copyright: Copyright (C) 1999 by Salvatore Sanfilippo$ 
 * $license: This software is under GPL version 2 of license$ 
 * $date: Fri Nov  5 11:55:49 MET 1999$ 
 * $rev: 8$ 
 */ 

/* $Id: sendicmp.c,v 1.9 2003/07/25 11:42:10 njombart Exp $ */

#include <sys/types.h> /* this should be not needed, but ip_icmp.h lacks it */
#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <errno.h>

#include "hping2.h"


//static int _icmp_seq = 0;

void send_icmp_echo(void);
void send_icmp_other(int opt_icmptype, int opt_icmpcode, char* icmpSrcIP, char* icmpDstIP, int srcPort, int dstPort, char* srcIP, char* dstIP, int ttl);
void send_icmp_timestamp(void);
void send_icmp_address(void);

void send_icmp(int opt_icmptype, int opt_icmpcode, char* icmpSrcIP, char* icmpDstIP, int srcPort, int dstPort, char* srcIP, char* dstIP, int ttl)
{
	switch(opt_icmptype)
	{
		case ICMP_ECHO:			/* type 8 */
		case ICMP_ECHOREPLY:		/* type 0 */
//			send_icmp_echo();
			break;
		case ICMP_DEST_UNREACH:		/* type 3 */
		case ICMP_SOURCE_QUENCH:	/* type 4 */
		case ICMP_REDIRECT:		/* type 5 */
		case ICMP_TIME_EXCEEDED:	/* type 11 */
			send_icmp_other(opt_icmptype, opt_icmpcode, icmpSrcIP, icmpDstIP, srcPort, dstPort, srcIP, dstIP, ttl);
			break;
		case ICMP_TIMESTAMP:
		case ICMP_TIMESTAMPREPLY:
//			send_icmp_timestamp();
			break;
		case ICMP_ADDRESS:
		case ICMP_ADDRESSREPLY:
//			send_icmp_address();
			break;
		default:
            printf("[send_icmp] Unsupported icmp type!\n");
            exit(1);
	}
}


void send_icmp_other(int opt_icmptype, int opt_icmpcode, char* icmpSrcIP, char* icmpDstIP, int srcPort, int dstPort, char* srcIP, char* dstIP, int ttl)
{
    int data_size = 0;
	char *packet, *data, *ph_buf;
	struct myicmphdr *icmp;
	struct myiphdr icmp_ip;
	struct myudphdr *icmp_udp;
	int udp_data_len = 0;
	struct pseudohdr *pseudoheader;
	int left_space = IPHDR_SIZE + UDPHDR_SIZE + data_size;
    
    struct sockaddr_in icmpSrcAddr;
    struct sockaddr_in icmpDstAddr;
    icmpSrcAddr.sin_family = AF_INET;
    icmpDstAddr.sin_family = AF_INET;
    // store this IP address in struct sockaddr_in:
    inet_pton(AF_INET, icmpSrcIP, &(icmpSrcAddr.sin_addr));
    inet_pton(AF_INET, icmpDstIP, &(icmpDstAddr.sin_addr));
    

    struct sockaddr_in srcAddr;
    struct sockaddr_in dstAddr;
    srcAddr.sin_family = AF_INET;
    dstAddr.sin_family = AF_INET;
    // store this IP address in struct sockaddr_in:
    inet_pton(AF_INET, srcIP, &(srcAddr.sin_addr));
    inet_pton(AF_INET, dstIP, &(dstAddr.sin_addr));

	packet = (char*)malloc(ICMPHDR_SIZE + IPHDR_SIZE + UDPHDR_SIZE + data_size);
	ph_buf = (char*)malloc(PSEUDOHDR_SIZE + UDPHDR_SIZE + udp_data_len);
	if (packet == NULL || ph_buf == NULL) {
		perror("[send_icmp] malloc");
		return;
	}

	memset(packet, 0, ICMPHDR_SIZE + IPHDR_SIZE + UDPHDR_SIZE + data_size);
	memset(ph_buf, 0, PSEUDOHDR_SIZE + UDPHDR_SIZE + udp_data_len);

	icmp = (struct myicmphdr*) packet;
	data = packet + ICMPHDR_SIZE;
	pseudoheader = (struct pseudohdr *) ph_buf;
	icmp_udp = (struct myudphdr *) (ph_buf + PSEUDOHDR_SIZE);

	/* fill icmp hdr */
	icmp->type = opt_icmptype;	/* ICMP_TIME_EXCEEDED */
	icmp->code = opt_icmpcode;	/* should be 0 (TTL) or 1 (FRAGTIME) */
	icmp->checksum = 0;
//	if (opt_icmptype == ICMP_REDIRECT)
//		memcpy(&icmp->un.gateway, &icmp_gw.sin_addr.s_addr, 4);
//	else
		icmp->un.gateway = 0;	/* not used, MUST be 0 */

	/* concerned packet headers */
	/* IP header */
	icmp_ip.version  = icmp_ip_version;		/* 4 */
	icmp_ip.ihl      = icmp_ip_ihl;			/* IPHDR_SIZE >> 2 */
	icmp_ip.tos      = icmp_ip_tos;			/* 0 */
   
    icmp_ip_tot_len = 0;

	icmp_ip.tot_len  = htons((icmp_ip_tot_len ? icmp_ip_tot_len : (icmp_ip_ihl<<2) + UDPHDR_SIZE + udp_data_len));

//	int size  = (icmp_ip_ihl<<2) + UDPHDR_SIZE + udp_data_len;
//    cout << "size: " << size << endl;
    //printf("icmp_ip.tot_len: %", icmp_ip.tot_len);
//    cout << "icmp_ip.tot_len: " << icmp_ip.tot_len << endl;
//    cout << "icmp_ip_protocol: " << icmp_ip_protocol << endl;

   
	icmp_ip.id       = 0;
	icmp_ip.frag_off = 0;				/* 0 */
	icmp_ip.ttl      = ttl;				/* 64 */
	icmp_ip.protocol = icmp_ip_protocol;		/* 6 (TCP) */
	icmp_ip.check	 = 0;
	//memcpy(&icmp_ip.saddr, &icmp_ip_src.sin_addr.s_addr, 4);
	memcpy(&icmp_ip.saddr, &srcAddr.sin_addr.s_addr, 4);
	memcpy(&icmp_ip.daddr, &dstAddr.sin_addr.s_addr, 4);
	icmp_ip.check	 = cksum((__u16 *) &icmp_ip, IPHDR_SIZE);

	/* UDP header */
	memcpy(&pseudoheader->saddr, &srcPort, 4);
	memcpy(&pseudoheader->daddr, &dstPort, 4);
	pseudoheader->protocol = icmp_ip.protocol;
	pseudoheader->length = icmp_ip.tot_len;
	icmp_udp->uh_sport = htons(srcPort);
	icmp_udp->uh_dport = htons(dstPort);
	icmp_udp->uh_ulen  = htons(UDPHDR_SIZE + udp_data_len);
	icmp_udp->uh_sum   = cksum((__u16 *) ph_buf, PSEUDOHDR_SIZE + UDPHDR_SIZE + udp_data_len);

	/* filling icmp body with concerned packet header */

	/* fill IP */

	if (left_space == 0) goto no_space_left;
	memcpy(packet+ICMPHDR_SIZE, &icmp_ip, left_space);
	left_space -= IPHDR_SIZE;
	data += IPHDR_SIZE;
	if (left_space <= 0) goto no_space_left;

	/* fill UDP */

	memcpy(packet+ICMPHDR_SIZE+IPHDR_SIZE, icmp_udp, left_space);
	left_space -= UDPHDR_SIZE;
	data += UDPHDR_SIZE;
//    printf("udp header size: %d\n", UDPHDR_SIZE);
//    printf("left space: %d\n", left_space);
	if (left_space <= 0) goto no_space_left;

	/* fill DATA */
	data_handler(data, left_space);
no_space_left:

	/* icmp checksum */
	if (icmp_cksum == -1)
		icmp->checksum = cksum((u_short*)packet, ICMPHDR_SIZE + IPHDR_SIZE + UDPHDR_SIZE + data_size);
	else
		icmp->checksum = icmp_cksum;

	/* send packet */
    // 2 indicates ICMP packet
//	send_ip_handler(2, (char*)&icmpSrcAddr.sin_addr, (char*)&icmpDstAddr, packet, ICMPHDR_SIZE + IPHDR_SIZE + UDPHDR_SIZE + data_size);
    printf("sendicmp.c -- %s -> %s\n", icmpSrcIP, icmpDstIP);
	send_ip_handler(2, 64, icmpSrcIP, icmpDstIP, packet, ICMPHDR_SIZE + IPHDR_SIZE + UDPHDR_SIZE + data_size);
	free(packet);
	free(ph_buf);
}
