/** probably not needed, but to keep it look like I know what I'm doing! :P */
#include "sr_router.h"
#include "sr_arpcache.h"

// IP packet destinated for one of router's IP address

	// packet is an ICMP echo request and its checksum is valid -- send ICMP echo reply

	// packet contains TCP/UDP, send ICMP port unreachable to the sending host

	// else, ignore

// IP packet destinated elsewhere - IP forwarding
	// sanity check the packet (minimum length and checksum)
	
	// decrement TTL by 1, recompute checksum

	// find out which entry in the routhing table has longest prefix match with destination IP address

	// check ARP cache for next-hop MAC address corresponding to the next-hop IP
		// in the cache, send it

		// not in the cache, send ARP request for the next-hop IP every second, 
		// add packet to ARP request que

/** sr_instance* sr is a pointer to a router instance
	uint8_t *packet is a pointer to sr_ip_hdr_t
	len is the length of the ethernet packet  (WHAT PACKET)???
	char* interface is a pointer to a router's interfaces */
void ip_forwarding(struct sr_instance* sr, uint8_t *ip_hdr, unsigned int len, char* interface){
	/** ip packet length */
	unsigned int ip_len = len - sizeof(struct sr_ip_hdr_t);
	/** ARP cache */
	sr_arpcache cache = sr->cache;
	/** routing table */
	sr_rt *rt_table = sr->routing_talbe;
	/** source address for the packet */
	uint32_t ip_src_add = ip_hdr->ip_src;
	/** destination address for the packet */
	uint32_t ip_dst_add = ip_hdr->ip_dst;
	/** Destination IP address from the routing table */
	uint32_t ip_dst = check_routing_table(rt, ip_dst_add);
	/** ARP containing MAC address corresponding to the destionation IP address*/
	struct sr_arpentry *arp_dest = sr_arpcache_lookup(*cache, ip_dst);


	/** sanity check fails */
	if(valid_pkt(ip_hdr) == 0){
		printf("%s\n", "sanity check fails");
		/** TODO: send ICMP to host notify the error. */
	}

	/** TTL > 0, the packet is still alive, 
	    from updateTTL(), update TTL and recompute checksum */
	if(updateTTL() > 0){
		/** MAC address known, send the package */
		if(*arp_dst){
			printf("%s\n", "mac exists in the cache.");
			/** TODO: length */
			sr_send_packet(sr, *(arp_dst->ip), len, interface);
			free(arp_dst);
		}
		/** MAC address unknown, send an ARP requst, add the packet to the queue */
		else{			
			// create the ARP request
			sr_arp_hdr_t *arp_request = create_arp_request(interface, *ip_hdr);
			// TODO: what is the tosend_arp??
			sr_ethernet_hdr_t *eth_arp_request = create_arp_eth(interface, arp_request, sr_arp_hdr_t *tosend_arp);
			// TODO: send the ARP request for the next-hop IP EVERY SECOND
			// TODO: calculate the length
			unsigned int eth_arp_req_len;
			sr_send_packet(sr, eth_arp_request, eth_arp_req_len, interface);
			
			//queue the packet
			sr_arpreq *queue_request = sr_arpcache_queuereq(*cache, ip_hdr, 
				eth_arp_request, eth_arp_req_len, interface);
			free(eth_arp_request);

			/** Not sure if this part is still needed, appears in handle_arpreq 
			if(queue_request->times_sent > 5){
				//TODO: icmp code for too many arp request sent
				create_icmp(ip_protocol_icmp, icmp_code);
			}
			*/
		}
	}
	/** TTL < 0, do nothing and drop the packet */
}

/** Check the destination IP address from the routing table, 
	if the destination exists, return the gateway of the address, 
	else, return -1. */
uint32_t check_routing_table(struct sr_instance* sr, uint32_t ip_dst_add){
	struct sr_rt* rt_walker = sr->routing_talbe;
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
		//TODO: Create a type 3 code 0 ICMP packet
		sr_icmp_t3_hdr_t *dest_net_unreach = create_icmp_t3(uint8_t type, uint8_t code, sr_ip_hdr_t *ip_hdr);
		//TODO: create ip packet and ethernet packet
		create_ip();
		uint8_t *eht_packet = create_ehternet();
		// TODO: send it back to the host -- len and interface??
		sr_send_packet(sr, eht_packet, len, interface);
		return -1;
	}
	return (uint32_t)gw;
}

/** Return the arp entry containing the mac for the IP address MIGHT NOT BE NEEDED */
struct sr_arpentry *ip_mac_mapping(struct sr_arpcache *cache, uint32_t ip){
	/** if the IP destination exists in routing table, check MAC in arp cache */
	if(gw != -1){
		/** ARP entry for the destination MAC address */
		sr_arpentry *dst_arp = sr_arpcache_lookup(*cache, ip);
		mac = dst_arp->mac;
		return *mac;
	}
	/** the IP destination doesn't exsits in routing table*/
	else{
		return *mac;
	}
}

// TODO: check if header is redo correctly
/** update TTL by decrement 1, recalculate checksum and redo header */
uint8_t updateTTL(uint8_t *ip_hdr){
	/** time to live of the packet */
	uint8_t ttl = ip_hdr->ip_ttl;
	/** header length */
	uint16_t hdr_len = ip_hdr->ip_len;
	/** checksum of the id_hdr */
	uint16_t checksum = ip_hdr->ip_sum;
	uint16_t new_sum;

	/** reduce TTL by 1 */
	ttl -= 1;
	/** recalculate checksum */
	new_sum = cksum(ip_hdr, hdr_len);
	checksum = new_sum;

	/** if TTL reaches 0, send ICMP time exceed */
	if(ttl == 0){
		// create ICMP packet of type 11, code 0
		create_icmp(ip_protocol_icmp, icmp_code);
		return -1;
	}
	return ttl;
}
