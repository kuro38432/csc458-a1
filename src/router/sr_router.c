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

  /* fill in code here */
  /* useful structs */
  /* Get our interface. */
  struct sr_if *iface = sr_get_interface(sr, interface); 
  sr_ethernet_hdr_t * eth_hdr = (sr_ethernet_hdr_t *)packet;

  /*TODO: remove print. */
  print_hdrs((uint8_t *)eth_hdr, len);

  /* get ethernet type */
  uint16_t ethtype = ethertype(packet);
  
  /* IP: if packet contains an ip packet */
  if (ethtype == ethertype_ip) {
    /* extract ip packet and parse ip header */
    uint8_t *ip_packet = packet + size_ether;
    sr_ip_hdr_t * ip_hdr = (sr_ip_hdr_t *) ip_packet;
    struct sr_if * iface_ip = sr_get_interface_from_addr(sr, ip_hdr->ip_dst); 

    /* Check if IP packet meets minimum length and has correct checksum. */
    if (valid_pkt(ip_hdr) == 1) {
      /* If the packet is for our interface (no need to do TTL)... */
      if (iface_ip) {
        /* Get the IP protocol. */
        uint8_t ip_proto = ip_protocol(ip_packet);
    
        /* If the packet is an ICMP packet. */
        if (ip_proto == ip_protocol_icmp) {

        /* Extract ICMP packet. */
        uint8_t * icmp_packet = ip_packet + size_ip;
        sr_icmp_hdr_t * icmp_hdr = (sr_icmp_hdr_t *) icmp_packet;
       
        /* Received ICMP echo request. */
        if (icmp_hdr->icmp_type == 8) {
          printf("===========================================================\n");
          printf(" RECEIVED ICMP ECHO REQUEST\n");
          /* Create ICMP echo reply. */
          sr_ethernet_hdr_t *eth_rsp_hdr = create_icmp(eth_hdr, iface, ICMP_ECHO, 0);
          print_hdrs((uint8_t *)eth_rsp_hdr, len);
         
          /* Extract the IP header from the Ethernet header we will send out. */
          uint8_t *ip_rsp_pkt = (uint8_t *)eth_rsp_hdr + size_ether;
          sr_ip_hdr_t *ip_rsp_hdr = (sr_ip_hdr_t *)ip_rsp_pkt;
  
          int total_icmp_size = size_ether + size_ip + size_icmp_t3 + ICMP_DATA_SIZE;
         
          /* Look in routing table for next hop IP. */ 
          struct sr_rt *next_dst = check_routing_table(sr, eth_rsp_hdr, ip_rsp_hdr, total_icmp_size, iface);

          /* If we found the next hop destination in our routing table... */
          if (next_dst) {
            /* Handle checking the cache and send an ARP request if needed. */
            handle_next_hop(sr, next_dst, eth_rsp_hdr, total_icmp_size);
          } else {
            /* Send ICMP packet because there is no route to the destination IP. */
            /* ICMP has type 3, code 0. */
            sr_ethernet_hdr_t *eth_rsp_hdr = create_icmp(eth_hdr, iface, ICMP_NO_DST, 0);

            send_icmp_packet(eth_rsp_hdr, sr, iface);

            free(eth_rsp_hdr);
          } 
          printf("===========================================================\n");
          
          /* Free the ICMP packet. */
          free(eth_rsp_hdr);
        }

        } else if (ip_proto == 6 || ip_proto == 17) { /* IP packet is UDP/TCP. */
          /* Send ICMP with type 3, code 3. */
          sr_ethernet_hdr_t *eth_rsp_hdr = create_icmp(eth_hdr, iface, ICMP_NO_PORT, 3);

          send_icmp_packet(eth_rsp_hdr, sr, iface);

          free(eth_rsp_hdr);
           
        }

      /* else IP packet is not for our interface. */
      } else {
        /* We are about to decrement the TTL so if it is 1, it indicates that
           it can no longer be forwarded (the TTL will be 0 after we forward it) */
        if (ip_hdr->ip_ttl > 1) {
          /* Decrement the TTL by 1, recompute checksum, and perform LPM. */
          
        } else {
          /* Send ICMP with type 11 and code 0. */
          sr_ethernet_hdr_t *eth_rsp_hdr = create_icmp(eth_hdr, iface, ICMP_TIME_EXCEED, 0);

          send_icmp_packet(eth_rsp_hdr, sr, iface);

          free(eth_rsp_hdr);

        } 
      } /* end else IP packet is not for our interface. */
    } else {
      /* TODO: send ICMP packet because the IP packet does not meet the minimum
         length or has correct checksum. - or drop. */
    }

  /* We have received an ARP packet not an IP packet. */
  } else if (ethtype == ethertype_arp) {
    /* extract arp packet and parse arp header */
    uint8_t * arp_packet = packet + sizeof(sr_ethernet_hdr_t);
    sr_arp_hdr_t * arp_hdr = (sr_arp_hdr_t *) arp_packet;
    if ((ntohs(arp_hdr->ar_op) == arp_op_request) && (arp_hdr->ar_tip == iface->ip)) { 
      /* ARP request directed to our interface - reply.  We do not have to
       * reply to requests that are not made to our interface. */
      printf("\n\n===========================================================\n");
      printf(" RECEIVED AN ARP REQUEST - MUST REPLY\n");
      sr_ethernet_hdr_t *arp_rep = create_arp_rep(eth_hdr, iface);
      print_hdrs((uint8_t *)arp_rep, len);
      sr_send_packet(sr, (uint8_t *)arp_rep, len, interface);
      printf("===========================================================\n");

      /* Free the ARP reply. */
      free(arp_rep);

    } else if ((ntohs(arp_hdr->ar_op) == arp_op_reply) && (arp_hdr->ar_tip == iface->ip)) {
      /* ARP REPLY directed to our interface. */
      /* Cache the IP->MAC mapping and forward the packets that require this mapping. */
      cache_and_forward(sr, eth_hdr);
    } else {
      /* ARP request or reply not directed to our interface. */
    }
   /* END OF RENATA'S CHANGE. */ 
  } /* end if ethtype == <type> */

}/* end sr_handlepacket */

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

/* TODO: remove this print statement later. 
  printf("-------------------------------------------------------------------\n");
  printf(" PRINT INSIDE VALID_PKT\n");
  printf(" Old checksum: %d, New checksum: %d\n", orig_cksum, new_cksum);
  printf(" Size of normal IP header: %zd\n", sizeof(sr_ip_hdr_t));
  printf(" Size of this IP header: %zd\n", sizeof(*(pkt)));
  printf("-------------------------------------------------------------------\n");
*/
  if ((orig_cksum == new_cksum) && (sizeof(*(pkt)) == 20)) {
    ret_val = 1;
  } else {
    ret_val = 0;
  }  
  return ret_val;
} /* end valid_pkt */


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
 sr_ip_hdr_t *ip_hdr, unsigned int len, struct sr_if *iface){
  char *interface = iface->name;
  uint32_t ip_dst_add = ip_hdr->ip_dst;
  struct sr_rt* rt_walker = sr->routing_table;
  
  uint32_t max_mask = 0;
  uint32_t mask = 0;
  uint32_t dest = 0;
  uint32_t temp = 0;
  struct sr_rt* to_return = NULL;
  while(rt_walker->next){
    mask = rt_walker->mask.s_addr;
    dest = rt_walker->dest.s_addr; 

    /* Avoid finding the source IP address as the next hop IP */
    temp = ip_dst_add & mask;
    dest = dest & mask;
    if(temp == dest && mask > max_mask){
      to_return = rt_walker;
      max_mask = mask;
    }
    rt_walker = rt_walker->next;
  } 
  /* there doesn't exists route to destination IP */
  if(to_return == NULL){
    create_and_send_icmp(ICMP_NO_DST, 0, ip_hdr, eth_hdr, sr, len, interface);
  }
  return to_return;
}

/*---------------------------------------------------------------------
 * Method: updateTTL(uint8_t *ip_hdr, struct sr_if *iface)
 * Scope: local
 *
 * Returns: the TTL of the ip packet
 *
 * The method updates TTL by decrement 1 and recalculate checksum 
 * to redo the header.
 *---------------------------------------------------------------------*/
uint8_t updateTTL(struct sr_instance* sr, sr_ethernet_hdr_t * eth_hdr, 
  sr_ip_hdr_t *ip_hdr, unsigned int len, struct sr_if *iface){

  /** time to live of the packet */
  uint8_t ttl = ip_hdr->ip_ttl;
  /** header length */
  uint16_t hdr_len = ip_hdr->ip_len;
  /** new checksum after ttl is updated*/
  uint16_t new_sum;

  /** reduce TTL by 1 */
  ttl -= 1;
  ip_hdr->ip_sum = 0;
  /** recalculate checksum */
  new_sum = cksum(ip_hdr, hdr_len);
  /** update the checksum of the id_hdr */
  ip_hdr->ip_sum = new_sum;

  return ttl;
}

/* RENATACHANGE BEGIN */

/* Create a full ARP request packet (ethernet header and ARP header. */
sr_ethernet_hdr_t *create_arp_rep(sr_ethernet_hdr_t *eth_hdr, struct sr_if *iface) {

  /* Extract the original ARP header (some values will be used later. */
  uint8_t *arp_orig_pkt = (uint8_t *)eth_hdr + size_ether;
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)arp_orig_pkt;

  /* Total size of the ARP packet. */
  int total_arp_rep_size = size_ether + sizeof(sr_arp_hdr_t);
  
  /* Malloc enough memory to store ARP packet. */
  sr_ethernet_hdr_t *eth_rsp_hdr = (sr_ethernet_hdr_t *) malloc(total_arp_rep_size);

  /* Copy original ARP request into the newly allocated memory. */
  memcpy((uint8_t *)eth_rsp_hdr, (uint8_t *) eth_hdr, total_arp_rep_size);
/* TODO: remove print statement later.
  printf("-------------------------------------------------------------------\n");
  printf(" PRINTING INSIDE CREATE_ARP_REP\n");
  print_hdrs((uint8_t*)eth_rsp_hdr, 42);
  printf("-------------------------------------------------------------------\n");
*/
  /* Extract all of the packets (ethernet, and ARP). */
  uint8_t *arp_pkt = (uint8_t *)eth_rsp_hdr + size_ether;
  sr_arp_hdr_t *arp_rsp_hdr = (sr_arp_hdr_t *) arp_pkt;

  /* Change the values in the ARP header. */
  arp_rsp_hdr->ar_op = htons(arp_op_reply);
  memset(arp_rsp_hdr->ar_sha, 0, ETHER_ADDR_LEN);
  memcpy(arp_rsp_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN);
  memset(arp_rsp_hdr->ar_tha, 0, ETHER_ADDR_LEN);
  memcpy(arp_rsp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
  arp_rsp_hdr->ar_sip = iface->ip;
  arp_rsp_hdr->ar_tip = arp_hdr->ar_sip;

  /* Change values in the Ethernet header. */
  memset(eth_rsp_hdr->ether_dhost, 0, ETHER_ADDR_LEN);
  memcpy(eth_rsp_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
  memset(eth_rsp_hdr->ether_shost, 0, ETHER_ADDR_LEN);
  memcpy(eth_rsp_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);

  return eth_rsp_hdr;

} /* end of create_arp */

/* Create an entire ICMP packet (including ethernet header, IP header, and the ICMP header. */
sr_ethernet_hdr_t *create_icmp(sr_ethernet_hdr_t *eth_hdr, struct sr_if *iface, int type, int code) {
  
  /* Total size of the ICMP packet. */
  int total_icmp_size = size_ether + size_ip + size_icmp_t3 + ICMP_DATA_SIZE; 
  /* Malloc enough memory to store an ICMP packet. */
  sr_ethernet_hdr_t *eth_rsp_hdr = (sr_ethernet_hdr_t *) malloc(total_icmp_size);
  
  /* Copy the original ICMP packet into the newly allocated memory. */

  memcpy((uint8_t *) eth_rsp_hdr, (uint8_t *) eth_hdr, total_icmp_size);

  /* Extract all of the packets (ethernet, IP, and ICMP). */
  uint8_t *ip_pkt = (uint8_t *)eth_rsp_hdr + size_ether;
  sr_ip_hdr_t *ip_rsp_hdr = (sr_ip_hdr_t *)ip_pkt;
  uint8_t *icmp_pkt = (uint8_t *)eth_rsp_hdr + size_ether + size_ip;
  sr_icmp_hdr_t *icmp_rsp_hdr = (sr_icmp_hdr_t *)icmp_pkt;

  /* Change the values in the ethernet field. */
  /* Note: we cannot change the destination yet because we do not know the MAC address. */
  memset(eth_rsp_hdr->ether_shost, 0, ETHER_ADDR_LEN);
  memcpy(eth_rsp_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);

  /* Change the required values in the IP packet. */
  /* The new source is the old destination and vice versa. */
  uint32_t old_ip_src = ip_rsp_hdr->ip_src;
  ip_rsp_hdr->ip_src = ip_rsp_hdr->ip_dst;
  ip_rsp_hdr->ip_dst = old_ip_src;
  ip_rsp_hdr->ip_ttl = ip_rsp_hdr->ip_ttl - 1;
  ip_rsp_hdr->ip_p = htons(ip_protocol_icmp);
  ip_rsp_hdr->ip_sum = 0;
  uint16_t new_cksum = cksum((const void *)ip_rsp_hdr, size_ip);
  ip_rsp_hdr->ip_sum = new_cksum;

  /* Change the values of the ICMP type and code. */
  icmp_rsp_hdr->icmp_type = type;
  icmp_rsp_hdr->icmp_code = code;

  return eth_rsp_hdr;
} /* end of create_icmp */

/* Create a full ARP request packet (ethernet header and ARP header). */
sr_ethernet_hdr_t *create_arp_req(struct sr_if *iface, uint32_t ip) {
  /* Malloc enough memory. */
  sr_ethernet_hdr_t *eth_rsp_hdr = (sr_ethernet_hdr_t *)malloc(size_ether + sizeof(sr_arp_hdr_t));
 
  /* Extract the ARP header. */  
  uint8_t *arp_pkt = (uint8_t *)eth_rsp_hdr + size_ether;
  sr_arp_hdr_t *arp_rsp_hdr = (sr_arp_hdr_t *)arp_pkt;

  /* Set the fields in the ARP header. */
  arp_rsp_hdr->ar_hrd = htons(arp_hrd_ethernet);
  arp_rsp_hdr->ar_pro = htons(ethertype_ip);
  arp_rsp_hdr->ar_hln = ETHER_ADDR_LEN;
  arp_rsp_hdr->ar_pln = 4;
  arp_rsp_hdr->ar_op = htons(arp_op_request);
  memset(arp_rsp_hdr->ar_tha, 0, ETHER_ADDR_LEN);
  memcpy(arp_rsp_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN);
  arp_rsp_hdr->ar_sip = iface->ip;
  arp_rsp_hdr->ar_tip = ip;

  /* Set the fields in the ethernet header. */
  memset(eth_rsp_hdr->ether_dhost, -1, ETHER_ADDR_LEN);
  memcpy(eth_rsp_hdr->ether_shost, arp_rsp_hdr->ar_sha, ETHER_ADDR_LEN);
  eth_rsp_hdr->ether_type = htons(ethertype_arp);

 return eth_rsp_hdr;
} /* end of create_arp_req */

/* Our router needs to send an ARP request! We create the ARP request packet
 * and send it out in this function. Queueing the request is handled as well. */
void handle_next_hop(struct sr_instance *sr, struct sr_rt *dst, sr_ethernet_hdr_t *eth_rsp_hdr, int pkt_size) {
  uint32_t next_ip = dst->gw.s_addr;

  /* Look for the next-hop IP address in the cache. */
  struct sr_arpentry *arp_dest = sr_arpcache_lookup(&(sr->cache), next_ip);
  struct sr_if *next_hop_iface = sr_get_interface(sr, dst->interface);

  /* If the IP->MAC mapping was found in the cache. */
  if (arp_dest) {
    memcpy(eth_rsp_hdr->ether_shost, next_hop_iface->addr, ETHER_ADDR_LEN);
    memcpy(eth_rsp_hdr->ether_dhost, arp_dest->mac, ETHER_ADDR_LEN);
  } else { /* We could not find the MAC addres for the next-hop IP in the cache. */
    sr_ethernet_hdr_t *arp_req = create_arp_req(next_hop_iface, next_ip);
    /* Send the ARP request packet to the next-hop interface. */
    sr_send_packet(sr, (uint8_t *)arp_req, size_ether + sizeof(sr_arp_hdr_t), dst->interface);

    /* Add ARP request to queue for next-hop IP address. */
    sr_arpcache_queuereq(&(sr->cache), ntohl(next_ip), (uint8_t *)eth_rsp_hdr, pkt_size, dst->interface);
  }
} /* end handle_next_hop */

/* Cache IP-MAC mappings taken from ARP reply and forward the packets that rely
 * on this mapping. */

void cache_and_forward(struct sr_instance *sr, sr_ethernet_hdr_t *eth_hdr) {
  /* Extract the ARP response. */
  uint8_t *arp_pkt = (uint8_t *)eth_hdr + size_ether;
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)arp_pkt;
  
  struct sr_arpreq *arpreq = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, htonl(arp_hdr->ar_sip));
  /* Found the list of packets that need to be forwarded now that the mapping exists. */
  if (arpreq) {
    struct sr_packet *pkt;
    for (pkt = arpreq->packets; pkt != NULL; pkt = pkt->next) {
      struct sr_if *pkt_iface = sr_get_interface(sr, pkt->iface);
      
      /* Fill in the destination MAC address. */
      sr_ethernet_hdr_t *tosend_eth = (sr_ethernet_hdr_t *)(pkt->buf);
      memcpy(tosend_eth->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
      memcpy(tosend_eth->ether_shost, pkt_iface->addr, ETHER_ADDR_LEN);
      sr_send_packet(sr, (uint8_t *)tosend_eth, pkt->len, pkt->iface);
      sr_arpreq_destroy(&sr->cache, arpreq);
    }
  }
} /* end cache_and_forward */

/* Send an ICMP packet and handle the ARP forwarding. */
void send_icmp_packet(sr_ethernet_hdr_t *eth_hdr, struct sr_instance *sr, struct sr_if *iface) {
  /* Extract the IP header from the Ethernet header we will send out. */
  uint8_t *ip_rsp_pkt = (uint8_t *)eth_hdr + size_ether;
  sr_ip_hdr_t *ip_rsp_hdr = (sr_ip_hdr_t *)ip_rsp_pkt;

  int total_icmp_size = size_ether + size_ip + size_icmp_t3 + ICMP_DATA_SIZE;

  /* Look in routing table for next hop IP. */
  struct sr_rt *next_dst = check_routing_table(sr, eth_hdr, ip_rsp_hdr, total_icmp_size, iface);

  /* If we found the next hop destination in our routing table... */
  if (next_dst) {
    /* Handle checking the cache and send an ARP request if needed. */
    handle_next_hop(sr, next_dst, eth_hdr, total_icmp_size);
  }

} /* end send_icmp_packet */

/* RENATACHANGE END */
