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
  sr_ethernet_hdr_t * eth_hdr = (sr_ethernet_hdr_t *)packet;
  
  /* get ethernet type */
  uint16_t ethtype = ethertype(packet);
  
  /* IP: if packet contains an ip packet */
  if (ethtype == ethertype_ip) {
    printf("Received IP packet\n");
    /* extract ip packet and parse ip header */
    uint8_t * ip_packet = packet + sizeof(sr_ethernet_hdr_t);
    sr_ip_hdr_t * ip_hdr = (sr_ip_hdr_t *) ip_packet;
    /* if packet is for our interface */
    if (ip_hdr->ip_dst == iface->ip) {
      /* If the TTL is 0, send an ICMP packet and stop processing the request. */
      if(ip_hdr->ip_ttl == 0) {
        sr_icmp_hdr_t *icmp_rsp_hdr = create_icmp(ICMP_TIME_EXCEED, 0);
        sr_ip_hdr_t * ip_rsp_hdr = create_ip(ip_hdr);
        sr_ethernet_hdr_t *eth_rsp_hdr = create_packet(eth_hdr, ip_rsp_hdr, icmp_rsp_hdr);


        /*TODO: am I sending to the right interface? */
        sr_send_packet(sr, (uint8_t *)eth_rsp_hdr, len, interface);
        
        /* Free ICMP header. */
        free(icmp_rsp_hdr);
        free(ip_rsp_hdr);
        free(eth_rsp_hdr);

        /* stop processing packet... */ 
      } /* end of TTL exceed: if(ip_hdr->ip_ttl == 0) */

      /* TODO: check if checksum is valid and IP packet meets minimum length. */

     /*  int valid = valid_pkt(ip_hdr); */

      /* The packet has sufficient TTL so continue... */
      /* Get the underlying protocol */
      uint8_t ip_proto = ip_protocol(ip_packet);
      
      /* ICMP: if packet contains an icmp packet */
      if (ip_proto == ip_protocol_icmp) {
        /* extract icmp packet and parse icmp header */
        uint8_t * icmp_packet = ip_packet + sizeof(sr_ip_hdr_t);
        sr_icmp_hdr_t * icmp_hdr = (sr_icmp_hdr_t *) icmp_packet;
        /* if this is a icmp echo request */
        if (icmp_hdr->icmp_type == 8) {
          /* Create ICMP header for response */
          icmp_hdr->icmp_type = 0;
          icmp_hdr->icmp_code = ICMP_ECHO;
          icmp_hdr->icmp_sum = 0;

          uint16_t icmp_cksum = 0;
          int icmp_len = ntohs(ip_hdr->ip_len)-sizeof(sr_ip_hdr_t);
          icmp_cksum = cksum((const void *)icmp_hdr, icmp_len);
          icmp_hdr->icmp_sum = icmp_cksum;
          
          /* Create IP header. */
          sr_ip_hdr_t * ip_rsp_hdr = create_ip(ip_hdr);
          
          /* Create ethernet frame. */
          sr_ethernet_hdr_t *eth_rsp_hdr = create_packet_wlen(eth_hdr, ip_rsp_hdr, icmp_rsp_hdr);

          sr_send_packet(sr, (uint8_t *)eth_rsp_hdr, len, interface); 
         
          /* Free ICMP header. */ 
          free(icmp_rsp_hdr);
          free(ip_rsp_hdr); 
          free(eth_rsp_hdr);
        } /* end if (icmp_hdr->icmp_type == 8) - echo request */

      /* TCP/UDP: if packet contains TCP(code=6)/UDP(code=17) payload */
      } else if (ip_proto == 6 || ip_proto == 17) {
        sr_icmp_hdr_t * icmp_rsp_hdr = create_icmp(3, 3);
        sr_ip_hdr_t * ip_rsp_hdr = create_ip(ip_hdr);  
        sr_ethernet_hdr_t *eth_rsp_hdr = create_packet(eth_hdr, ip_rsp_hdr, icmp_rsp_hdr);

        sr_send_packet(sr, (uint8_t *)eth_rsp_hdr, len, interface);
        /* Free ICMP header. */
        free(icmp_rsp_hdr);
        free(ip_rsp_hdr);
        free(eth_rsp_hdr);

      /* OTHERWISE: if packet contains something other than icmp/tcp/udp */
      } /* end if packet is TCP/UDP - 
         * else if (ip_proto == 6 || ip_proto == 17) */

    /* if packet is not for our interface */
    } else {
      /* TODO: forward packet:
               Deduct 1 from TTL, and recalculate checksum and redo header.
               Check if TTL is 0 - then send ICMP packet.
               Else look up routing table for IP address, then look in arp cache for MAC address.
                  if there is no route to destination IP, send ICMP
               If cache entry does not exist, send ARP request to broadcasting MAC address
               and queue the packet.
                  keep track of ARP requests - if more than 5 sent, send ICMP
               If cache exists, send packet to destined addresss. */ 
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

  /* TODO: Check packet meets minimum length. */

  /* If packet is IP */
  orig_cksum = pkt->ip_sum;
  pkt->ip_sum = 0;
  new_cksum = cksum((const void *)pkt, sizeof(sr_ip_hdr_t));
  pkt->ip_sum = orig_cksum;
  
  if (orig_cksum == new_cksum) {
    return 1;
  } else {
    return 0;
  }  
} /* end valid_pkt */
