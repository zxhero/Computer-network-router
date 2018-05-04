#include "icmp.h"
#include "ip.h"
#include "rtable.h"
#include "arp.h"
#include "base.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// send icmp packet
void icmp_send_packet(const char *in_pkt, int len, u8 type, u8 code)
{
	fprintf(stderr, "TODO: malloc and send icmp packet.\n");
	struct iphdr *ip_hdr = packet_to_ip_hdr(in_pkt);
	u32 dst = ntohl(ip_hdr->daddr);
	struct icmphdr *icmp = (struct icmphdr *)IP_DATA(ip_hdr);
        if(type == ICMP_ECHOREPLY && code == 0){
            ;
        }
        else{
            len = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + 16 + IP_BASE_HDR_SIZE;
            memcpy((char *)icmp+8,ip_hdr,IP_HDR_SIZE(ip_hdr)+8);
            memset((char *)icmp+4,0,4);
            //struct iphdr *ip_new = packet_to_ip_hdr(icmp_packet);
            ip_init_hdr(ip_hdr,ntohl(ip_hdr->daddr),ntohl(ip_hdr->saddr),2 *IP_HDR_SIZE(ip_hdr) + 2*ICMP_COPIED_DATA_LEN,IPPROTO_ICMP);
        }
        icmp->code = code;
        icmp->type = type;
        icmp->checksum = icmp_checksum(icmp,len-ETHER_HDR_SIZE-IP_BASE_HDR_SIZE);
	fprintf(stderr, IP_FMT,LE_IP_FMT_STR(dst));
        ip_send_packet(in_pkt,len);
}
