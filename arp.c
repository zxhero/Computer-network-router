#include "arp.h"
#include "base.h"
#include "types.h"
#include "packet.h"
#include "ether.h"
#include "arpcache.h"
#include "ip.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// #include "log.h"

// send an arp request: encapsulate an arp request packet, send it out through
// iface_send_packet
void arp_send_request(iface_info_t *iface, u32 dst_ip)
{
	fprintf(stderr, "TODO: send arp request when lookup failed in arpcache.\n");
	int i,len;
	len = ETHER_HDR_SIZE + sizeof(struct ether_arp);
	char *packet = malloc(len);
	memset(packet,0,len);
	struct ether_arp *req_hdr = (struct ether_arp *)(packet + ETHER_HDR_SIZE);
	struct ether_header *eh = (struct ether_header *)packet;
	req_hdr->arp_op = htons(ARPOP_REQUEST);
	memcpy(req_hdr->arp_sha,iface->mac,ETH_ALEN);
	req_hdr->arp_spa = htonl(iface->ip);
	req_hdr->arp_hln = 6;
	req_hdr->arp_hrd = htons(1);
	req_hdr->arp_pro = htons(0x0800);
	req_hdr->arp_pln = 4;
	req_hdr->arp_tpa = htonl(dst_ip);
	memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
	eh->ether_type = htons(ETH_P_ARP);
	for(i = 0;i < ETH_ALEN;i++)
        eh->ether_dhost[i] = 0xff;
    iface_send_packet(iface,packet,len);
}

// send an arp reply packet: encapsulate an arp reply packet, send it out
// through iface_send_packet
void arp_send_reply(iface_info_t *iface, struct ether_arp *req_hdr)
{
	fprintf(stderr, "TODO: send arp reply when receiving arp request.\n");
	char *packet = malloc(ETHER_HDR_SIZE + sizeof(struct ether_arp));
	struct ether_arp *rply_hdr = (struct ether_arp *)(packet + ETHER_HDR_SIZE);
	struct ether_header *eh = (struct ether_header *)packet;
	rply_hdr->arp_hln = req_hdr->arp_hln;
	rply_hdr->arp_hrd = req_hdr->arp_hrd;
	rply_hdr->arp_op = htons(ARPOP_REPLY);
	rply_hdr->arp_pln = req_hdr->arp_pln;
	rply_hdr->arp_pro = req_hdr->arp_pro;
	rply_hdr->arp_tpa = req_hdr->arp_spa;
	memcpy(rply_hdr->arp_tha,req_hdr->arp_sha,ETH_ALEN);
	memcpy(rply_hdr->arp_sha,iface->mac,ETH_ALEN);
	rply_hdr->arp_spa = htonl(iface->ip);
	memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
	eh->ether_type = htons(ETH_P_ARP);
	memcpy(eh->ether_dhost,rply_hdr->arp_tha,ETH_ALEN);
	iface_send_packet(iface, packet, ETHER_HDR_SIZE + sizeof(struct ether_arp));
}

void handle_arp_packet(iface_info_t *iface, char *packet, int len)
{
	fprintf(stderr, "TODO: process arp packet: arp request & arp reply.\n");
	struct ether_arp *arp_hdr = (struct ether_arp *)(packet + ETHER_HDR_SIZE);
	//u32 ip = ntohl(arp_hdr->arp_tpa);
	//fprintf(stderr, IP_FMT,LE_IP_FMT_STR(ip));
	//fprintf(stderr, IP_FMT,LE_IP_FMT_STR(iface->ip));
	//fprintf(stderr, "arpop: %d\n",ntohs(arp_hdr->arp_op));
	if(ntohs(arp_hdr->arp_op) == ARPOP_REQUEST && ntohl(arp_hdr->arp_tpa) == iface->ip){
	arpcache_insert(ntohl(arp_hdr->arp_spa),arp_hdr->arp_sha);        
	arp_send_reply(iface,arp_hdr);
	}
	else if(ntohs(arp_hdr->arp_op) == ARPOP_REPLY){
        arpcache_insert(ntohl(arp_hdr->arp_spa),arp_hdr->arp_sha);
	}
}

// send (IP) packet through arpcache lookup
//
// Lookup the mac address of dst_ip in arpcache. If it is found, fill the
// ethernet header and emit the packet by iface_send_packet, otherwise, pending
// this packet into arpcache, and send arp request.
void iface_send_packet_by_arp(iface_info_t *iface, u32 dst_ip, char *packet, int len)
{
	struct ether_header *eh = (struct ether_header *)packet;
	memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
	eh->ether_type = htons(ETH_P_IP);

	u8 dst_mac[ETH_ALEN];
	int found = arpcache_lookup(dst_ip, dst_mac);
	if (found) {
		// log(DEBUG, "found the mac of %x, send this packet", dst_ip);
		fprintf(stderr, "FIND :");
		
		memcpy(eh->ether_dhost, dst_mac, ETH_ALEN);
		fprintf(stderr, IP_FMT,LE_IP_FMT_STR(dst_ip));
		iface_send_packet(iface, packet, len);
		//fprintf(stderr, IP_FMT,LE_IP_FMT_STR(dst_ip));
	}
	else {
		// log(DEBUG, "lookup %x failed, pend this packet", dst_ip);
		arpcache_append_packet(iface, dst_ip, packet, len);
		//arp_send_request(iface,dst_ip);
	}
}
