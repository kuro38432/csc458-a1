/** probably not needed, but to keep it look like I know what I'm doing! :P */
#include "sr_router.h"
#include "sr_arpcache.h"

// packet is an ICMP echo request and its checksum is valid -- send ICMP echo reply

// packet contains TCP or UDP

// ip forwarding
	// check ARP cache for the next-hop IP

/** uint8_t *packet is a pointer to sr_ip_hdr_t */

void ip_forwarding(struct sr_instance* sr, uint8_t *packet, unsigned int len, char* interface){
	/** ARP cache */
	sr_arpcache cache = sr->sr_arpcache;
	/** routing table */
	sr_rt *rt_table = sr->routing_talbe;
	/** IP header of the packet */
	sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(packet);
	/** source address for the packet */
	uint32_t ip_src_add = iphdr->ip_src;
	/** destination address for the packet */
	uint32_t ip_dst_add = iphdr->ip_dst;
	/** Destination IP address from the routing table*/
	uint32_t ip_dst = check_routing_table(rt_table, ip_dst_add);
	/** ARP entry for finding the destination MAC address */
	sr_arpentry *dst_arp = sr_arpcache_lookup(*cache, ip_dst);

	// sanity check fails
	if(valid_pkt(iphdr) == 0){
		printf("%s\n", "sanity check fails");
	}
	// decrement TTL, check if TTL=0
	if(updateTTL() > 0){
		// MAC address known, send the package
		// TODO check if used the correct function
		if(*dst_arp){
			sr_send_packet(sr, iphdr, len, interface);
			free(dst_arp);
		}
		// MAC address unknown, send an ARP requst, add the packet to the queue
		else{			
			// send ARP request, I don't think I'm doing this rights
			sr_arpreq *new_req = (sr_arpreq *) malloc(sizeof(sr_arpreq));
			new_req->ip = ip_dst;
			new_req->sent = 0;
			new_req->times_sent = 0;
			new_req->packets = NULL;
			new_req->next = NULL;
			
			//queue the packet TODO: check len and interface input
			sr_arpreq *add_request = sr_arpcache_queuereq(*cache, ip_dst, iphdr, len, interface);
			free(iphdr);

			if(add_request->times_sent > 5){
				//TODO: icmp code for too many arp request sent
				create_icmp(ip_protocol_icmp, icmp_code);
			}

			// if cache exists, send packet to destination
		}
	}
}

/** Check the destination IP address from the routing table*/
uint32_t check_routing_table(sr_rt *rt_table, uint32_t ip_dst_add){
	struct sr_rt* rt_walker = rt_table;
	struct in_addr max_mask = 0;
	struct in_addr gw = 0;
	struct in_addr mask = 0;
	struct in_addr dest = 0;
	unsigned long temp;

	while(rt_walker->next){
		mask = rt_walker->mask;
		dest = rt_walker->dest;
		temp = ip_dst_add & mask;
		if(temp == dest && mask > max_mask){
			gw = rt_walker->gw;
			max_mask = mask;
		}
	}
	// there doesn't exists route to destination IP
	if(gw == 0){
		//TODO: ICMP code for no route to destination IP
		create_icmp(ip_protocol_icmp, icmp_code);
		// TODO: needs return?
	}
	return (uint32_t)gw;
}


// TODO: reculculate checksum and redo header, didn't I calculated it in valid_pkt?
uint8_t updateTTL(uint8_t *packet){
	/** IP header of the packet */
	sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(packet);
	/** time to live of the packet */
	uint8_t ttl = iphdr->ip_ttl;
	ttl -= 1;
	if(ttl == 0){
		// need code from Renata, send ICMP packet
		create_icmp(ip_protocol_icmp, icmp_code);
		return -1;
	}
	return ttl;
}
