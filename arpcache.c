#include "arpcache.h"
#include "arp.h"
#include "ether.h"
#include "packet.h"
#include "icmp.h"
#include "ip.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

static arpcache_t arpcache;

// initialize IP->mac mapping, request list, lock and sweeping thread
void arpcache_init()
{
	bzero(&arpcache, sizeof(arpcache_t));

	init_list_head(&(arpcache.req_list));

	pthread_mutex_init(&arpcache.lock, NULL);

	pthread_create(&arpcache.thread, NULL, arpcache_sweep, NULL);
}

// release all the resources when exiting
void arpcache_destroy()
{
	pthread_mutex_lock(&arpcache.lock);

	struct arp_req *req_entry = NULL, *req_q;
	list_for_each_entry_safe(req_entry, req_q, &(arpcache.req_list), list) {
		struct cached_pkt *pkt_entry = NULL, *pkt_q;
		list_for_each_entry_safe(pkt_entry, pkt_q, &(req_entry->cached_packets), list) {
			list_delete_entry(&(pkt_entry->list));
			free(pkt_entry->packet);
			free(pkt_entry);
		}

		list_delete_entry(&(req_entry->list));
		free(req_entry);
	}

	pthread_kill(arpcache.thread, SIGTERM);

	pthread_mutex_unlock(&arpcache.lock);
}

// lookup the IP->mac mapping
//
// traverse the hash table to find whether there is an entry with the same IP
// and mac address with the given arguments
int arpcache_lookup(u32 ip4, u8 mac[ETH_ALEN])
{
	fprintf(stderr, "TODO: lookup ip address in arp cache.\n");
	int i;
	pthread_mutex_lock(&arpcache.lock);
	fprintf(stderr, IP_FMT,LE_IP_FMT_STR(ip4));
	for(i = 0;i < MAX_ARP_SIZE;i++){
	
        if(arpcache.entries[i].ip4 == ip4 && arpcache.entries[i].valid == 1){
		//fprintf(stderr, "TODO: I find address in arp cache.\n");
            memcpy(mac,arpcache.entries[i].mac,ETH_ALEN);
            pthread_mutex_unlock(&arpcache.lock);
            return 1;
        }
        else
            continue;
	}
	pthread_mutex_unlock(&arpcache.lock);
	return 0;
}

// append the packet to arpcache
//
// Lookup in the hash table which stores pending packets, if there is already an
// entry with the same IP address and iface (which means the corresponding arp
// request has been sent out), just append this packet at the tail of that entry
// (the entry may contain more than one packet); otherwise, malloc a new entry
// with the given IP address and iface, append the packet, and send arp request.
void arpcache_append_packet(iface_info_t *iface, u32 ip4, char *packet, int len)
{
	fprintf(stderr, "TODO: append the ip address if lookup failed, and send arp request if necessary.\n");
	pthread_mutex_lock(&arpcache.lock);
	struct arp_req *arp_entry = NULL;
	struct cached_pkt *pkt_ptr = NULL;
	int flag = 0;
	list_for_each_entry(arp_entry,&arpcache.req_list,list){
        if(arp_entry->ip4 == ip4 && arp_entry->iface == iface){
            flag = 1;
            break;
        }
	}
	pkt_ptr = malloc(sizeof(struct cached_pkt));
    init_list_head(&(pkt_ptr->list));
    pkt_ptr->packet = packet;
    pkt_ptr->len = len;
	if(flag == 0){
        arp_entry = malloc(sizeof(struct arp_req));
        arp_entry->iface = iface;
        arp_entry->ip4 = ip4;
        arp_entry->retries = 1;
        arp_entry->sent = time(NULL);
        init_list_head(&(arp_entry->cached_packets));
        init_list_head(&(arp_entry->list));
        list_add_tail(&arp_entry->list, &arpcache.req_list);
        arp_send_request(iface,ip4);
	}
	list_add_tail(&pkt_ptr->list, &arp_entry->cached_packets);
	pthread_mutex_unlock(&arpcache.lock);
}

// insert the IP->mac mapping into arpcache, if there are pending packets
// waiting for this mapping, fill the ethernet header for each of them, and send
// them out
void arpcache_insert(u32 ip4, u8 mac[ETH_ALEN])
{
	fprintf(stderr, "TODO: insert ip->mac entry, and send all the pending packets.\n");
	pthread_mutex_lock(&arpcache.lock);
	struct cached_pkt *pkt_ptr = NULL,*pkt_nptr;
	int i ;
	struct arp_req *arp_entry = NULL,*arp_nentry;
	struct ether_header *eh;
	for(i = 0;i < MAX_ARP_SIZE;i++){
            if(arpcache.entries[i].valid == 0){
                arpcache.entries[i].ip4 = ip4;
		fprintf(stderr, IP_FMT,LE_IP_FMT_STR(ip4));
                memcpy(arpcache.entries[i].mac,mac,ETH_ALEN);
                arpcache.entries[i].valid = 1;
                arpcache.entries[i].added = time(NULL);
                break;
            }
	}
	list_for_each_entry_safe(arp_entry,arp_nentry,&arpcache.req_list,list){
        if(arp_entry->ip4 == ip4){
            list_for_each_entry_safe(pkt_ptr,pkt_nptr,&arp_entry->cached_packets,list){
                eh = (struct ether_header *)(pkt_ptr->packet);
                memcpy(eh->ether_dhost, mac, ETH_ALEN);
                iface_send_packet(arp_entry->iface, pkt_ptr->packet, pkt_ptr->len);
                list_delete_entry(&(pkt_ptr->list));
		fprintf(stderr, "TODO: 1.\n");
                //free(pkt_ptr->packet);
		fprintf(stderr, "TODO: 2.\n");
                free(pkt_ptr);
            }
		fprintf(stderr, "TODO: 2.\n");
            list_delete_entry(&(arp_entry->list));
		fprintf(stderr, "TODO: 3.\n");
            free(arp_entry);
            break;
        }
	}
	fprintf(stderr, "TODO: 4.\n");
	pthread_mutex_unlock(&arpcache.lock);
}

// sweep arpcache periodically
//
// For the IP->mac entry, if the entry has been in the table for more than 15
// seconds, remove it from the table.
// For the pending packets, if the arp request is sent out 1 second ago, while
// the reply has not been received, retransmit the arp request. If the arp
// request has been sent 5 times without receiving arp reply, for each
// pending packet, send icmp packet (DEST_HOST_UNREACHABLE), and drop these
// packets.
void *arpcache_sweep(void *arg)
{
	while (1) {
		sleep(1);
		fprintf(stderr, "TODO: sweep arpcache periodically: remove old entries, resend arp requests .\n");
		int i;
		struct arp_req *arp_entry = NULL, *arp_nentry;
		pthread_mutex_lock(&arpcache.lock);
		time_t  sec = time(NULL);
		for(i = 0;i < MAX_ARP_SIZE;i++){
            if(arpcache.entries[i].valid == 1 && (sec - arpcache.entries[i].added) > 15){
                arpcache.entries[i].valid = 0;
            }
        }
        list_for_each_entry_safe(arp_entry,arp_nentry,&arpcache.req_list,list){
            if(sec - arp_entry->sent >= 1){
                if(arp_entry->retries == 5){
                    struct cached_pkt *pkt_ptr = NULL,*pkt_nptr;
                    list_for_each_entry_safe(pkt_ptr,pkt_nptr,&arp_entry->cached_packets,list){
                        icmp_send_packet(pkt_ptr->packet,pkt_ptr->len,ICMP_DEST_UNREACH,1);
                        list_delete_entry(&(pkt_ptr->list));
                        free(pkt_ptr->packet);
                        free(pkt_ptr);
                    }
                    list_delete_entry(&(arp_entry->list));
                    free(arp_entry);
                }
                else{
                    arp_send_request(arp_entry->iface,arp_entry->ip4);
                    arp_entry->retries++;
                }
            }
        }
        pthread_mutex_unlock(&arpcache.lock);
	}
	return NULL;
}
