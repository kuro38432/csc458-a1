/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
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

/** Function declearation goes here */
int valid_pkt(sr_ip_hdr_t *pkt);
uint32_t check_routing_table(struct sr_instance* sr, sr_ip_hdr_t *ip_hdr, 
      struct sr_if *iface);
uint8_t updateTTL(sr_ip_hdr_t *ip_hdr);
/** TODO: fix this! */
uint32_t update_arp_req(sr_ethernet_hdr_t *eth_arp_request, struct sr_arpreq *arp_req);


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
  printf("Interface: %s\n", interface);
  print_hdrs((uint8_t *)packet, len);

  /* fill in code here */
  /* useful structs */
  struct sr_if * iface = sr_get_interface(sr, interface); 
  printf("%s\n", iface->name);
  sr_ethernet_hdr_t * eth_hdr = (sr_ethernet_hdr_t *)packet;
  
  /* get ethernet type */
  uint16_t ethtype = ethertype(packet);
  
  /* IP: if packet contains an ip packet */
  if (ethtype == ethertype_ip) {
    printf("Received IP packet\n");
    /* extract ip packet and parse ip header */
    uint8_t * ip_packet = packet + size_ether;
    sr_ip_hdr_t * ip_hdr = (sr_ip_hdr_t *) ip_packet;
    /* ADDED BY EMILY : not sure why but the interface is always eth3 even if it was sent
                        to another one of our interfaces. So I added this piece of code and
                        a function in sr_if.c that searchs for an interface through the ip
                        address and switches it with the current iface if it exists.
                        not sure if this is what we should do, but know ping and traceroute
                        works for the other interfaces too. */
    struct sr_if * iface_ip = sr_get_interface_from_addr(sr, ip_hdr->ip_dst);
    if (iface_ip != 0) {
       iface = iface_ip;
    }
    /* if packet is for our interface */
    if (ip_hdr->ip_dst == iface->ip) {
      /* If the TTL is 0, send an ICMP packet and stop processing the request. */
      if(ip_hdr->ip_ttl == 0) {
        create_and_send_icmp(ICMP_TIME_EXCEED, 0, ip_hdr, eth_hdr, sr, len, interface);
      } /* end of TTL exceed: if(ip_hdr->ip_ttl == 0) */

      /* The packet has sufficient TTL so continue... */
      /* Get the underlying protocol */
      uint8_t ip_proto = ip_protocol(ip_packet);
      
      /* ICMP: if packet contains an icmp packet */
      if (ip_proto == ip_protocol_icmp) {
        /* extract icmp packet and parse icmp header */
        uint8_t * icmp_packet = ip_packet + size_ip;
        sr_icmp_hdr_t * icmp_hdr = (sr_icmp_hdr_t *) icmp_packet;
        /* if this is a icmp echo request */
        if (icmp_hdr->icmp_type == 8) {
          /* Create ICMP header for response */
          icmp_hdr->icmp_type = 0;
          icmp_hdr->icmp_code = ICMP_ECHO;
          icmp_hdr->icmp_sum = 0;

          uint16_t icmp_cksum = 0;
          /*TODO: delete this comment int icmp_len = ntohs(ip_hdr->ip_len)-sizeof(sr_ip_hdr_t); */
          int icmp_len = size_icmp_t3 + ICMP_DATA_SIZE;
          icmp_cksum = cksum((const void *)icmp_hdr, icmp_len);
          icmp_hdr->icmp_sum = icmp_cksum;
          
          /* Create IP header. */
          sr_ip_hdr_t *ip_rsp_hdr = create_ip(ip_hdr);
          
          /* Create ethernet frame. */
          sr_ethernet_hdr_t *eth_rsp_hdr = create_icmp_pkt(eth_hdr, ip_rsp_hdr, icmp_hdr, icmp_len);

          sr_send_packet(sr, (uint8_t *)eth_rsp_hdr, len, interface); 
         
          /* Free ICMP header. */ 
          free(ip_rsp_hdr); 
          free(eth_rsp_hdr);
        } /* end if (icmp_hdr->icmp_type == 8) - echo request */

      /* TCP/UDP: if packet contains TCP(code=6)/UDP(code=17) payload */
      } else if (ip_proto == 6 || ip_proto == 17) {
        create_and_send_icmp(ICMP_NO_DST, 3, ip_hdr, eth_hdr, sr, len, interface);
      /* OTHERWISE: packet contains something other than icmp/tcp/udp */
      } /* end if packet is TCP/UDP - 
         * else if (ip_proto == 6 || ip_proto == 17) */

    /* if packet is not for our interface */
    } else {
      
      /** int valid = valid_pkt(ip_hdr); */
      /* TODO: You can uncomment this if you want to see what it looks like when a ICMP is sent
               because we couldn't find the destination.
         create_and_send_icmp(ICMP_NO_DST, 0, ip_hdr, eth_hdr, sr, len, interface);
       ^ NEED TO DELETE IT LATER
       */
      /* If the packet is valid... */
      /**if (valid) { */
          /** ARP cache */
          struct sr_arpcache cache = sr->cache;
          /** Destination IP address from the routing table */
          uint32_t ip_dst = check_routing_table(sr, ip_hdr, iface);
          /** ARP containing MAC address corresponding to the destionation IP address*/
          struct sr_arpentry *arp_dest = sr_arpcache_lookup(&cache, ip_dst);
          /** struct sr_if * iface - interface */

          /** sanity check fails */
          if(valid_pkt(ip_hdr) == 0){
            printf("%s\n", "sanity check fails");
            /** TODO: send ICMP to host notify the error. */
          }

          /** TTL > 0, the packet is still alive, 
              from updateTTL(), update TTL and recompute checksum */
          if(updateTTL(ip_hdr) > 0){
            /** MAC address known, send the package */
            if(arp_dest != NULL){
              printf("%s\n", "mac exists in the cache.");
              /** TODO: encapsulate the arp and send it */
              /** sr_send_packet(sr, *(arp_dst->ip), len, iface); */
              free(arp_dest);
            }
            /** MAC address unknown, send an ARP requst, add the packet to the queue */
            else{     
              /** Create the ARP request 
              TODO: check if I have the correct IP, is it interface IP of 
              the router that is sending the ARP request? */
              sr_arp_hdr_t *arp_request = create_arp_request(iface, iface->ip);
              /** Create the ethernet packet that wraps the ARP request */
              sr_ethernet_hdr_t *eth_arp_request = create_arp_req_eth(arp_request);
              /** TODO: send the ARP request for the next-hop IP EVERY SECOND */
              /** TODO: how to calculate the ARP length package length?? */
              unsigned int eth_arp_req_len = size_ether + size_ip + sizeof(sr_arp_hdr_t);
              /** TODO: update the times sent of the packet 
              update_arp_req(eth_arp_request); */
              /** send the ARP ethernet packet */
              sr_send_packet(sr, (uint8_t *)eth_arp_request, eth_arp_req_len, interface);
              
              /** queue the packet */
              struct sr_arpreq *queue_request = sr_arpcache_queuereq(&cache, ip_dst, 
                (uint8_t *)eth_arp_request, eth_arp_req_len, interface);
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
    
  /* ARP: if packet contains a arp packet */
  } else if (ethtype == ethertype_arp) {
    /* extract arp packet and parse arp header */
    uint8_t * arp_packet = packet + sizeof(sr_ethernet_hdr_t);
    sr_arp_hdr_t * arp_hdr = (sr_arp_hdr_t *) arp_packet;
    /* ARP REQUEST: if this is an arp request */
    if (ntohs(arp_hdr->ar_op) == arp_op_request) {
      /* send arp reply to sending host */
      /* create an arp packet & fill in information 
      sr_arp_hdr_t * tosend_arp = (sr_arp_hdr_t *) malloc(sizeof(sr_arp_hdr_t));
      tosend_arp->ar_hrd = ntohs(arp_hrd_ethernet);
      tosend_arp->ar_pro = ntohs(ethertype_ip);
      tosend_arp->ar_hln = ETHER_ADDR_LEN;
      tosend_arp->ar_pln = 4;
      tosend_arp->ar_op = ntohs(arp_op_reply);
      memcpy(tosend_arp->ar_sha, iface->addr, ETHER_ADDR_LEN);
      memcpy(tosend_arp->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
      tosend_arp->ar_sip = iface->ip;
      tosend_arp->ar_tip = arp_hdr->ar_sip;

      TODO: RENATA PUT THIS COMMENTED SECTION IN CREATE_ARP FUNCTION BELOW
      */
      sr_arp_hdr_t *tosend_arp = create_arp(iface, arp_hdr);
      /* create an ethernet packet & copy the arp packet into it */
/*
      sr_ethernet_hdr_t * tosend_eth = (sr_ethernet_hdr_t *) malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
      memcpy(((uint8_t *)tosend_eth) + sizeof(sr_ethernet_hdr_t), (uint8_t *)tosend_arp, sizeof(sr_arp_hdr_t)); */
      /* fill in ethernet header */
/*
      memcpy(tosend_eth->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
      memcpy(tosend_eth->ether_shost, iface->addr, ETHER_ADDR_LEN);
      tosend_eth->ether_type = ntohs(ethertype_arp);

      TODO: RENATA PUT THE CREATION OF ETHERNET PACKET IN FUNCTION BELOW
      */
      sr_ethernet_hdr_t *tosend_eth = create_arp_eth(iface, arp_hdr, tosend_arp);
      /* send packet */
      sr_send_packet(sr, (uint8_t *)tosend_eth, len, interface);
      /* free all memory allocated */
      free(tosend_arp);
      free(tosend_eth);
    /* ARP REPLY: if this is an arp reply */
    } else if (ntohs(arp_hdr->ar_op) == arp_op_reply) {
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
    /* ERROR: if this is neither an arp request or reply */
    } else {
      /* ignore packet */
    }
  /* ERROR: if the packet contains something other than arp or ip */
  } else {
    /* ignore packet */
  }

}/* end sr_ForwardPacket */

/*---------------------------------------------------------------------
 * Method: valid_pkt(uint8_t *pkt, uint16_t cksum)
 * Scope: Local 
 *
 * Checks that the packet meets the minimum length and has the correct 
 * checksum.
 *
 *---------------------------------------------------------------------*/

int valid_pkt(sr_ip_hdr_t *pkt) {
  uint16_t orig_cksum = 0;
  uint16_t new_cksum = 0;
  int ret_val = 0;

  /* If packet is IP */
  orig_cksum = pkt->ip_sum;
  pkt->ip_sum = 0;
  new_cksum = cksum((const void *)pkt, sizeof(sr_ip_hdr_t));
  pkt->ip_sum = orig_cksum;
  
  if ((orig_cksum == new_cksum) && (sizeof(*(pkt)) == 20)) {
    ret_val = 1;
  } else {
    ret_val = 0;
  }  
  return ret_val;
} /* end valid_pkt */

/*---------------------------------------------------------------------
 * Method: create_icmp_eth_hdr(sr_ip_hdr_t *ip_hdr, struct sr_if *iface)
 * Scope: local
 *
 * Return a pointer to a ethernet packet that is created 
 * to wrap around the ICMP - IP header  
 *---------------------------------------------------------------------*/
sr_ethernet_hdr_t *create_icmp_eth_hdr(sr_ip_hdr_t *ip_hdr, struct sr_if *iface){
  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *) malloc(size_ether);
  uint32_t client_ip = ip_hdr->ip_src;
  uint32_t router_ip = iface->ip;
  eth_hdr->ether_dhost[ETHER_ADDR_LEN] = client_ip;
  eth_hdr->ether_shost[ETHER_ADDR_LEN] = router_ip;
  eth_hdr->ether_type = ethertype_ip;
  return eth_hdr;
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
uint32_t check_routing_table(struct sr_instance* sr, sr_ip_hdr_t *ip_hdr, 
      struct sr_if *iface){
  uint32_t ip_dst_add = ip_hdr->ip_dst;
  uint32_t ip_src_add = ip_hdr->ip_src;
  struct sr_rt* rt_walker = sr->routing_table;
  const char *interface = iface->name;
  unsigned long max_mask = 0;
  unsigned long gw = 0;
  unsigned long mask = 0;
  unsigned long dest = 0;
  unsigned long temp = 0;

  while(rt_walker->next){
    mask = rt_walker->mask.s_addr;
    dest = rt_walker->dest.s_addr;
    /** Avoid finding the source IP address as the next hop IP */
    if(dest != ip_src_add){
      temp = ip_dst_add & mask;
      if(temp == dest && mask > max_mask){
        gw = rt_walker->gw.s_addr;
        max_mask = mask;
      }
    }
  }
  /** there doesn't exists route to destination IP */
  if(gw == 0){
    /** Create a ICMP packet of type 3 code 0 ICMP packet */
    sr_icmp_t3_hdr_t *dest_net_unreach = create_icmp_t3(ICMP_NO_DST, 0, ip_hdr);
    /** Create the ethernet header that will wrap this ICMP packet */
    sr_ethernet_hdr_t *eth_hdr = create_icmp_eth_hdr(ip_hdr, iface);
    /** Encapsulate the ICMP packet in a ethernet packet with IP header 
      TODO: CHECK THE CORRECTNESS OF create_icmp_pkt_t3, if it has allocated enough memory for the data
    */
    sr_ethernet_hdr_t *type3_code0_icmp_pkt = create_icmp_pkt_t3(eth_hdr, ip_hdr, dest_net_unreach);
    /** TODO: check the correctness of pkt_len */
    unsigned int pkt_len = sizeof(type3_code0_icmp_pkt);
    sr_send_packet(sr, (uint8_t *)type3_code0_icmp_pkt, pkt_len, interface);
    return -1;
  }
  return (uint32_t)gw;
}

/*---------------------------------------------------------------------
 * Method: updateTTL(uint8_t *ip_hdr)
 * Scope: local
 *
 * Returns: the TTL of the ip packet
 *
 * The method updates TTL by decrement 1 and recalculate checksum 
 * to redo the header.
 * TODO: check if header is redone correctly
 *---------------------------------------------------------------------*/
uint8_t updateTTL(sr_ip_hdr_t *ip_hdr){
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
    /** create ICMP packet of type 11, code 0 
    create_icmp(ip_protocol_icmp, icmp_code);*/
    return -1;
  }
  return ttl;
}

/*---------------------------------------------------------------------
 * Method: update_arp_req(struct sr_arpreq *arp_req)
 * Scope: local
 *
 * Returns: the number of times an ARP request has been sent. 
 *
 * The method updates times_send by increamenting 1 every time 
 * the request is sent.
 *---------------------------------------------------------------------*/
uint32_t update_arp_req(sr_ethernet_hdr_t *eth_arp_request, struct sr_arpreq *arp_req){
  /** extract the arp request */
  /** when you creat ARP request, what goes after the header?? 
      Given a ethernet packet that's wrapping the ARP request, 
      how do I find the ARP request?? */
   /** uint8_t arp_header = (uint8_t)eth_arp_request + sizeof(sr_ethernet_hdr_t *) + sizeof(sr_ip_hdr_t *);
       struct sr_arpreq *arp_req = (struct sr_arpreq *) arp_header; */

  uint32_t times_sent = arp_req->times_sent;
  times_sent -= 1;
  return times_sent;
}
