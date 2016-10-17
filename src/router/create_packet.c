/**********************************************************************
 * file: create_packet.c 
 *
 * Description:
 *
 * This file contains all the functions used to create packets. 
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
 * Method: create_icmp(uint8_t type, uint8_t code)
 * Scope: Local
 *
 * Returns a pointer to an ICMP header.
 *
 *---------------------------------------------------------------------*/
sr_icmp_hdr_t * create_icmp(uint8_t type, uint8_t code) {
  uint16_t icmp_cksum = 0;
  sr_icmp_hdr_t * icmp_rsp_hdr = (sr_icmp_hdr_t *) malloc(sizeof(sr_icmp_hdr_t));
  icmp_rsp_hdr->icmp_type = type;
  icmp_rsp_hdr->icmp_code = code;

  icmp_rsp_hdr->icmp_sum = 0;
  icmp_cksum = cksum((const void *)icmp_rsp_hdr, sizeof(sr_icmp_hdr_t));
  icmp_rsp_hdr->icmp_sum = icmp_cksum;

  return icmp_rsp_hdr;
} /* end create_icmp */

/*---------------------------------------------------------------------
 * Method: create_arp(uint8_t type, uint8_t code)
 * Scope: Local
 *
 * Returns a pointer to an ARP header.
 *
 *---------------------------------------------------------------------*/
sr_arp_hdr_t * create_arp(struct sr_if *iface, sr_arp_hdr_t *arp_hdr) {
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

  return tosend_arp;
}


/*---------------------------------------------------------------------
 * Method: create_packet(sr_ip_hdr_t * ip_hdr, sr_icmp_hdr_t * icmp_hdr, sr_arp_hdr_t arp_hdr)
 * Scope: Local
 *
 * Create full ARP packet (Ethernet frame)
 *
 *---------------------------------------------------------------------*/
sr_ethernet_hdr_t * create_arp_eth(struct sr_if *iface, sr_arp_hdr_t *arp_hdr, sr_arp_hdr_t *tosend_arp) {
  sr_ethernet_hdr_t * tosend_eth = (sr_ethernet_hdr_t *) malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
  memcpy(((uint8_t *)tosend_eth) + sizeof(sr_ethernet_hdr_t), (uint8_t *)tosend_arp, sizeof(sr_arp_hdr_t));

  /* fill in ethernet header */
  memcpy(tosend_eth->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
  memcpy(tosend_eth->ether_shost, iface->addr, ETHER_ADDR_LEN);
  tosend_eth->ether_type = ntohs(ethertype_arp);

  return tosend_eth;
}

/*---------------------------------------------------------------------
 * Method: create_ip(sr_ip_hdr_t * ip_hdr)
 * Scope: Local
 *
 * Returns a pointer to an IP header.
 *
 *---------------------------------------------------------------------*/
/* TODO: Figure out how IP packet calculates total length, id, and fragment flag. 
 * I asked some questions on Piazza... still confused. */
sr_ip_hdr_t * create_ip(sr_ip_hdr_t * ip_hdr) {
  sr_ip_hdr_t * ip_rsp_hdr = (sr_ip_hdr_t *) malloc(sizeof(sr_ip_hdr_t));

  memcpy((uint8_t *)ip_rsp_hdr, (uint8_t *)ip_hdr, sizeof(sr_ip_hdr_t));

  /* Modify the changed fields and recompute the checksum. */
  ip_rsp_hdr->ip_id = ip_hdr->ip_id + 1;
  ip_rsp_hdr->ip_sum = 0;

  /* Switch source and destination address. */
  uint32_t old_src = ip_rsp_hdr->ip_src;
  ip_rsp_hdr->ip_src = ip_rsp_hdr->ip_dst;
  ip_rsp_hdr->ip_dst = old_src;
  uint16_t ip_cksum = cksum((const void *)ip_rsp_hdr, sizeof(sr_ip_hdr_t));
  ip_rsp_hdr->ip_sum = ip_cksum;

  return ip_rsp_hdr;
} /* end create_icmp */

/*---------------------------------------------------------------------
 * Method: create_packet(sr_ip_hdr_t * ip_hdr, sr_icmp_hdr_t * icmp_hdr, sr_arp_hdr_t arp_hdr)
 * Scope: Local
 *
 * Returns a pointer to a full Ethernet frame that can be sent on the
 * network.
 *
 *---------------------------------------------------------------------*/
sr_ethernet_hdr_t * create_packet(sr_ethernet_hdr_t * eth_hdr, sr_ip_hdr_t * ip_hdr, sr_icmp_hdr_t * icmp_hdr) {
    /* TODO: implement creation of Ethernet frame containing ARP or IP. */
    sr_ethernet_hdr_t * ether_rsp_hdr = (sr_ethernet_hdr_t *) malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t));
    memcpy(((uint8_t *) ether_rsp_hdr) + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), (uint8_t *)icmp_hdr, sizeof(sr_icmp_hdr_t));
    memcpy(((uint8_t *) ether_rsp_hdr) + sizeof(sr_ethernet_hdr_t), (uint8_t *)ip_hdr, sizeof(sr_ip_hdr_t));

  /* Fill in the ethernet header. */
  memcpy(ether_rsp_hdr->ether_shost, eth_hdr->ether_dhost, ETHER_ADDR_LEN);
  memcpy(ether_rsp_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
  ether_rsp_hdr->ether_type = ntohs(ethertype_ip);
  return ether_rsp_hdr;
}
