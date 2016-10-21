/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"



/** function declearations */
void updateTTL(struct sr_instance* sr, sr_ethernet_hdr_t * eth_hdr, 
  sr_ip_hdr_t *ip_hdr, unsigned int len, char* interface);
struct sr_rt* check_routing_table(struct sr_instance* sr, sr_ethernet_hdr_t * eth_hdr,
 sr_ip_hdr_t *ip_hdr, unsigned int len, char* interface);
uint8_t *create_eth_pkt(unsigned char *src_mac, unsigned char *dest_mac, 
  uint16_t packet_type, uint8_t *ip_packet, unsigned int ip_len);
void handle_ip_packet(struct sr_instance* sr, 
        sr_ethernet_hdr_t *eth_hdr,
        sr_ip_hdr_t *ip_hdr,
        unsigned int len,
        char* interface);
void handle_arp_packet(struct sr_instance* sr, 
        sr_ethernet_hdr_t *eth_hdr,
        sr_arp_hdr_t *arp_hdr,
        unsigned int len,
        char* interface);

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /** variables */
  /** ethernet header */
  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
  /** rest of the packet */
  uint8_t *rest = packet + sizeof(size_ether);
  /* ethernet packet type */
  uint16_t ethtype = ethertype(packet);

  if(ethtype == ethertype_ip){
    printf("Received IP packet\n");
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)rest;
    handle_ip_packet(sr, eth_hdr, ip_hdr, len, interface);
  }
  else if(ethtype == ethertype_arp){
    printf("Received ARP packet\n");
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)rest;
    handle_arp_packet(sr, eth_hdr, arp_hdr, len, interface);
  }
  else{
    printf("Not an IP or ARP packet.\n");
  }
}/* end sr_ForwardPacket */

/*---------------------------------------------------------------------
 * Method: handle_ip_packet(struct sr_instance* sr, 
 *            sr_ethernet_hdr_t *eth_hdr,
 *            sr_ip_hdr_t *ip_hdr,
 *            unsigned int len,
 *            char* interface)
 *
 * Handles an IP packet
 *---------------------------------------------------------------------*/
void handle_ip_packet(struct sr_instance* sr, 
        sr_ethernet_hdr_t *eth_hdr,
        sr_ip_hdr_t *ip_hdr,
        unsigned int len,
        char* interface){
  /** interface structure */
  struct sr_if *iface;
  /** ARP cache */
  struct sr_arpcache cache = sr->cache;
  /** IP protocol */
  uint8_t ip_proto;
  /** MAC address for current interface */
  unsigned char *cur_mac;

  iface = sr_get_interface(sr, interface);
  ip_proto = ip_hdr->ip_p;
  cur_mac = iface->addr;

  /** ICMP: the IP packet is for our interface */
  if(iface != 0){
    /** if the packet is an icmp packet*/
    /********** Copyied from the old code ***********/
    if(ip_proto == ip_protocol_icmp){
      printf("Received ICMP packet\n");
      /* extract icmp packet and parse icmp header */
      uint8_t * icmp_packet = (uint8_t *)ip_hdr + size_ip;
      sr_icmp_hdr_t * icmp_hdr = (sr_icmp_hdr_t *) icmp_packet;
      /* if this is a icmp echo request */
      if (icmp_hdr->icmp_type == 8) {
        /* Create ICMP header for response */
        icmp_hdr->icmp_type = 0;
        icmp_hdr->icmp_code = ICMP_ECHO;
        icmp_hdr->icmp_sum = 0;

        uint16_t icmp_cksum = 0;
        int icmp_len = size_icmp_t3 + ICMP_DATA_SIZE;
        icmp_cksum = cksum((const void *)icmp_hdr, icmp_len);
        icmp_hdr->icmp_sum = icmp_cksum;
          
        /* Create IP header. */
        sr_ip_hdr_t *ip_rsp_hdr = create_ip(ip_hdr);
          
        /* Create ethernet frame. */
        sr_ethernet_hdr_t *eth_rsp_hdr = create_icmp_pkt(eth_hdr, ip_rsp_hdr, 
          icmp_hdr, icmp_len);
        
        struct sr_arpcache cache = sr->cache;
        struct sr_rt* rt_entry = check_routing_table(sr, eth_rsp_hdr, ip_rsp_hdr, 
            size_ether + size_ip + icmp_len, interface);
        uint32_t ip_dst = rt_entry->gw.s_addr;
        struct sr_arpentry * arp_dest = sr_arpcache_lookup(&cache, ip_dst);
        if (arp_dest != NULL) {
          memcpy(eth_rsp_hdr->ether_dhost, arp_dest->mac, ETHER_ADDR_LEN);
          sr_send_packet(sr,(uint8_t *)eth_rsp_hdr, size_ether+size_ip+icmp_len, iface->name);
          free(ip_rsp_hdr);
          free(icmp_hdr);
          free(eth_rsp_hdr);
        } else {
          struct sr_arpreq * req = sr_arpcache_queuereq(&cache, ip_rsp_hdr->ip_dst, (uint8_t *)eth_rsp_hdr, size_ether + size_ip + icmp_len, iface->name);
          handle_arpreq(req, sr);
        }
        /******************/
    }
    /* TCP/UDP: if packet contains TCP(code=6)/UDP(code=17) payload */
    else if (ip_proto == 6 || ip_proto == 17) {
      printf("Received TCP/UDP packet\n");
      /** TODO: check the correctness of create and send icmp method */
      create_and_send_icmp(ICMP_NO_DST, 3, ip_hdr, eth_hdr, sr, len, interface);
    }
    else{
      printf("Not an ICMP or TCP/UDP packet\n");
    }
  }
}
  /** the IP packet is not for our interface, enter IP forwarding algorithm */
  else{

    /** if TTL less than 1, send ICMP time exceed */
    if(ip_hdr->ip_ttl <= 1){
      printf("ICMP time exceed\n");
      create_and_send_icmp(ICMP_TIME_EXCEED, 0, ip_hdr, eth_hdr, sr, len, interface);      
    }

    /** packet is still alive */
    /** the returned rt entry with destination IP address and interface */
    struct sr_rt* rt_entry;
    /** Destination IP address from the routing table */
    uint32_t ip_dst;
    /** ARP containing MAC address corresponding to the destionation IP address*/
    struct sr_arpentry *arp_dest;

    rt_entry = check_routing_table(sr, eth_hdr, ip_hdr, len, interface);
    ip_dst = rt_entry->gw.s_addr;
    arp_dest = sr_arpcache_lookup(&cache, ip_dst);

    /** MAC address known, send the packet */
    if(arp_dest != NULL){
        printf("%s\n", "mac exists in the cache.");
        /** find the next hop mac address */
        unsigned char *next_hop_mac = arp_dest->mac;
        /** update TTL by decreamenting 1 */
        updateTTL(sr, eth_hdr, ip_hdr, len, interface);
        /** The next hop interface structure */
        struct sr_if *next_hop_if = sr_get_interface(sr, rt_entry->interface);
        /* create a ehternet packet with new ethernet header */
        uint8_t *eth_packet = create_eth_pkt(cur_mac, next_hop_mac, 
              ethertype_ip, (uint8_t *)ip_hdr, ntohs(ip_hdr->ip_len));
        /** send the packet to the next hop */
        sr_send_packet(sr, eth_packet, len, next_hop_if->name);
        free(arp_dest);
        free(eth_packet);
    }
    /** MAC address unknown, send an ARP requst, add the packet to the queue */
    else{
      /********** Copyied from the old code ***********/
      struct sr_arpreq * req = sr_arpcache_queuereq(&cache, ip_dst, 
              (uint8_t *)eth_hdr, len, interface);
      printf("queued the original packet of size: %d at interface %s\n", len, interface);
      print_hdr_eth((uint8_t *)eth_hdr);
      print_addr_ip_int(ip_dst);
      handle_arpreq(req, sr);
      /*******************************************/
    }
  }
}

/*---------------------------------------------------------------------
 * Method: handle_arp_packet(struct sr_instance* sr, 
 *            sr_ethernet_hdr_t *eth_hdr,
 *            sr_arp_hdr_t *arp_hdr,
 *            unsigned int len,
 *            char* interface)
 *
 * Handles an ARP packet
 *---------------------------------------------------------------------*/
void handle_arp_packet(struct sr_instance* sr, 
        sr_ethernet_hdr_t *eth_hdr,
        sr_arp_hdr_t *arp_hdr,
        unsigned int len,
        char* interface){
  /** interface structure */
  struct sr_if *iface;

  iface = sr_get_interface(sr, interface);

  /********** Copyied from the old code ***********/
  /* ARP REQUEST: if this is an arp request */
  if (ntohs(arp_hdr->ar_op) == arp_op_request) {
    /* send arp reply to sending host */
    sr_arp_hdr_t *tosend_arp = create_arp(iface, arp_hdr);
    /* create an ethernet packet & copy the arp packet into it */
    sr_ethernet_hdr_t *tosend_eth = create_arp_eth(iface, arp_hdr, tosend_arp);
    /* send packet */
    sr_send_packet(sr, (uint8_t *)tosend_eth, len, interface);
    /* free all memory allocated */
    free(tosend_arp);
    free(tosend_eth);
  } 
  /* ARP REPLY: if this is an arp reply */
  else if (ntohs(arp_hdr->ar_op) == arp_op_reply) {
    /* Cache IP-MAC mapping */
    struct sr_arpreq * arpreq = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
    if (arpreq) {
      struct sr_packet *pkt;
      for(pkt = arpreq->packets; pkt != NULL; pkt = pkt->next) {
        /* fill in destination MAC addr */
        sr_ethernet_hdr_t * tosend_eth = (sr_ethernet_hdr_t *)pkt;
        memcpy(tosend_eth->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
        /* send packet */
        sr_send_packet(sr, (uint8_t *)tosend_eth, pkt->len, pkt->iface);
      }
      sr_arpreq_destroy(&sr->cache, arpreq);
    }
  } 
  /* ERROR: if this is neither an arp request or reply */
  else {
    /* ignore packet */
  }
  /********************************************/
}

/*---------------------------------------------------------------------
 * Method: updateTTL(uint8_t *ip_hdr, struct sr_if *iface)
 * Scope: local
 *
 * Returns: the TTL of the ip packet
 *
 * The method updates TTL by decrement 1 and recalculate checksum 
 * to redo the header.
 * TODO: check if header is redone correctly
 *---------------------------------------------------------------------*/
void updateTTL(struct sr_instance* sr, sr_ethernet_hdr_t * eth_hdr, 
  sr_ip_hdr_t *ip_hdr, unsigned int len, char* interface){
  /** TTL */
  uint8_t ttl;
  /** new checksum after ttl is updated*/
  uint16_t new_sum;

  ttl = ip_hdr->ip_ttl;

  /** packet still alive */
  /** reduce TTL by 1 */
  ttl -= 1;
  /** recalculate checksum */
  new_sum = cksum(ip_hdr, ntohs(ip_hdr->ip_len));
  /** update the checksum of the id_hdr */
  ip_hdr->ip_sum = new_sum;
}

/*---------------------------------------------------------------------
 * Method: check_routing_table(struct sr_instance* sr, uint32_t ip_dst_add)
 * Scope: local
 *
 * Return the IP address of the next hop with longest prefix 
 * that is not the source address.
 * 
 * This method checks the destination IP address from the routing table, 
 * if the destination exists, return the gateway of the address, 
 * else, return -1. 
 *---------------------------------------------------------------------*/
struct sr_rt* check_routing_table(struct sr_instance* sr, sr_ethernet_hdr_t * eth_hdr,
 sr_ip_hdr_t *ip_hdr, unsigned int len, char* interface){
  /** destination ip address */
  uint32_t ip_dst_add = ip_hdr->ip_dst;
  /** routing table entry */
  struct sr_rt* rt_walker = sr->routing_table;
  
  uint32_t max_mask = 0;
  uint32_t mask = 0;
  uint32_t dest = 0;
  uint32_t temp = 0;
  struct sr_rt* ret;

  while(rt_walker->next){
    mask = rt_walker->mask.s_addr;
    dest = rt_walker->dest.s_addr;
    /** masked destination IP address */
    temp = ip_dst_add & mask;
    /** masked next hop IP address */
    dest = dest & mask;
    if(temp == dest && mask > max_mask){
      ret = rt_walker;
      max_mask = mask;
    }
    rt_walker = rt_walker->next;
  }

  /** there doesn't exists route to destination IP */
  if(ret == NULL){
    create_and_send_icmp(ICMP_NO_DST, 0, ip_hdr, eth_hdr, sr, len, interface);
    return ret;
  }
  return ret;
}


/*---------------------------------------------------------------------
 * Method: uint8_t *create_eth_pkt(uint8_t src_mac, uint8_t dest_mac, 
  uint16_t packet_type, uint8_t *ip_packet, unsigned int ip_len)
 * Scope: local
 *
 * Return a pointer to a ethernet packet that is newly created 
 *---------------------------------------------------------------------*/
uint8_t *create_eth_pkt(unsigned char *src_mac, unsigned char *dest_mac, 
  uint16_t packet_type, uint8_t *ip_packet, unsigned int ip_len){
  /** create a new ethernet header */
  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *) malloc(size_ether);
  eth_hdr->ether_dhost[ETHER_ADDR_LEN] = *src_mac;
  eth_hdr->ether_shost[ETHER_ADDR_LEN] = *dest_mac;
  eth_hdr->ether_type = htons(packet_type);
  /** create the ethernet packet with the ip packet in it */
  uint8_t *eth_pkt = malloc(size_ether + ip_len);
  /** copy the content in ethernet header over to the ethernet packet */
  memcpy(eth_pkt, eth_hdr, size_ether);
  /** copy the content in ip packet over to the ethernet packet */
  memcpy(eth_pkt + size_ether, ip_packet, ip_len);
  return eth_pkt;
}

/** Not needed, should be removed */
void print_arp_req(struct sr_arpreq *arpreq){
  struct sr_arpreq *cur;
  for(cur = arpreq; cur!=NULL; cur = cur->next){
    printf("======== ip: ");
    printf("%d\n", cur->ip);
    /**print_addr_ip_int(cur->ip);*/
    printf("sent: %d, times sent: %d\n", cur->sent, cur->times_sent);
    struct sr_packet *pkts;
    for(pkts = cur->packets; pkts != NULL; pkts = pkts->next){
      print_hdr_eth(pkts->buf);
      print_hdr_ip(pkts->buf + sizeof(size_ether));
    }
  }
}