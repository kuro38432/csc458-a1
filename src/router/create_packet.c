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
 * Method: create_icmp_t3(uint8_t type, uint8_t code, sr_ip_hdr_t *ip_hdr)
 * Scope: Local
 *
 * Returns a pointer to an ICMP header of type 3 or type 11.
 *
 *---------------------------------------------------------------------*/
sr_icmp_t3_hdr_t * create_icmp_t3(uint8_t type, uint8_t code, sr_ip_hdr_t *ip_hdr) {
  uint16_t icmp_cksum = 0;
  size_t size = 0;
  size = sizeof(sr_icmp_t3_hdr_t);
  sr_icmp_t3_hdr_t *icmp_rsp_hdr = (sr_icmp_t3_hdr_t *) malloc(size);
  /* Copy the IP header. */
  memcpy(icmp_rsp_hdr->data, (uint8_t *)ip_hdr, ICMP_DATA_SIZE);
  /*TODO: copy the first 8 bytes of the data after IP header. */
  /* I wonder what UDP or TCP will print if we tried sending some... */
  icmp_rsp_hdr->icmp_type = type;
  icmp_rsp_hdr->icmp_code = code;

  icmp_rsp_hdr->icmp_sum = 0;
  icmp_cksum = cksum((const void *)icmp_rsp_hdr, size + ICMP_DATA_SIZE);
  icmp_rsp_hdr->icmp_sum = icmp_cksum;

  return icmp_rsp_hdr;
}

/*---------------------------------------------------------------------
 * Method: create_arp(struct sr_if *iface, sr_arp_hdr_t *arp_hdr)
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
 * Method: create_arp_request(struct sr_if *iface, uint8_t ip)
 * Scope: Local
 *
 * Returns a pointer to an ARP header.
 *
 *---------------------------------------------------------------------*/
sr_arp_hdr_t * create_arp_request(struct sr_if *iface, uint32_t ip) {
  sr_arp_hdr_t * tosend_arp = (sr_arp_hdr_t *) malloc(sizeof(sr_arp_hdr_t));

  tosend_arp->ar_hrd = ntohs(arp_hrd_ethernet);
  tosend_arp->ar_pro = ntohs(ethertype_ip);
  tosend_arp->ar_hln = ETHER_ADDR_LEN;
  tosend_arp->ar_pln = 4;
  tosend_arp->ar_op = ntohs(arp_op_request);

  memcpy(tosend_arp->ar_sha, iface->addr, ETHER_ADDR_LEN);

  tosend_arp->ar_sip = iface->ip;
  tosend_arp->ar_tip = ip;

  return tosend_arp;
}

/*---------------------------------------------------------------------
 * Method: create_arp_eth(struct sr_if *iface, sr_arp_hdr_t *arp_hdr, 
 *                        sr_arp_hdr_t *tosend_arp)
 * Scope: Local
 *
 * Create full ARP packet including the ethernet frame.
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
 * Method: create_arp_req_eth(sr_arp_hdr_t *tosend_arp)
 * Scope: Local
 *
 * Create full ARP request packet including the ethernet frame. 
 *
 *---------------------------------------------------------------------*/
sr_ethernet_hdr_t * create_arp_req_eth(sr_arp_hdr_t *tosend_arp) {
  sr_ethernet_hdr_t * tosend_eth = (sr_ethernet_hdr_t *) malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
  memcpy(((uint8_t *)tosend_eth) + sizeof(sr_ethernet_hdr_t), (uint8_t *)tosend_arp, sizeof(sr_arp_hdr_t));

  /* fill in ethernet header */
  memset(tosend_eth->ether_dhost, -1, ETHER_ADDR_LEN);
  memcpy(tosend_eth->ether_shost, tosend_arp->ar_sha, ETHER_ADDR_LEN);
  tosend_eth->ether_type = ntohs(ethertype_arp);

  return tosend_eth;
}

/*---------------------------------------------------------------------
 * Method: create_ip(sr_ip_hdr_t * ip_hdr)
 * Scope: Local
 *
 * Returns a pointer to an IP header with the same protocol as the provided
 * ip_hdr. Source and destination address will be swapped.
 *
 *---------------------------------------------------------------------*/
sr_ip_hdr_t *create_ip(sr_ip_hdr_t * ip_hdr) {
  sr_ip_hdr_t *ip_rsp_hdr = (sr_ip_hdr_t *) malloc(sizeof(sr_ip_hdr_t));

  memcpy((uint8_t *)ip_rsp_hdr, (uint8_t *)ip_hdr, sizeof(sr_ip_hdr_t));

  /* Set cksum to 0 so that we can recompute the cksum. */
  ip_rsp_hdr->ip_sum = 0;

  /* Switch source and destination address. */
  uint32_t old_src = ip_rsp_hdr->ip_src;
  ip_rsp_hdr->ip_src = ip_rsp_hdr->ip_dst;
  ip_rsp_hdr->ip_dst = old_src;
  
  ip_rsp_hdr->ip_p = ip_protocol_icmp;
  ip_rsp_hdr->ip_ttl = ip_hdr->ip_ttl - 1;
  uint16_t ip_cksum = cksum((const void *)ip_rsp_hdr, sizeof(sr_ip_hdr_t));
  ip_rsp_hdr->ip_sum = ip_cksum;

  return ip_rsp_hdr;
}

/*---------------------------------------------------------------------
 * Method: create_icmp_pkt_t3(sr_ethernet_hdr_t *eth_hdr, sr_ip_hdr_t *ip_hdr,
 *                            sr_icmp_t3_hdr_t *icmp_hdr) 
 * Scope: Local
 *
 * Returns a pointer to an Ethernet frame encapsulating an IP header and
 * ICMP type 3 header that can be sent out on the network.
 *
 *---------------------------------------------------------------------*/
sr_ethernet_hdr_t * create_icmp_pkt_t3
  (  sr_ethernet_hdr_t * eth_hdr, 
     sr_ip_hdr_t * ip_hdr, 
     sr_icmp_t3_hdr_t * icmp_hdr ) 
{
  sr_ethernet_hdr_t * ether_rsp_hdr = \
    (sr_ethernet_hdr_t *) malloc(size_ether + size_ip + size_icmp_t3);
  /* Copy the ICMP header into memory. */
  memcpy(((uint8_t *) ether_rsp_hdr) + size_ether + size_ip, 
         (uint8_t *)icmp_hdr, size_icmp_t3);
  /* Copy the IP header into memory. */ 
  memcpy(((uint8_t *) ether_rsp_hdr) + size_ether, (uint8_t *)ip_hdr, size_ip);

  /* Fill in the ethernet header. */
  memcpy(ether_rsp_hdr->ether_shost, eth_hdr->ether_dhost, ETHER_ADDR_LEN);
  memcpy(ether_rsp_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
  ether_rsp_hdr->ether_type = ntohs(ethertype_ip);
  return ether_rsp_hdr;
}

/*---------------------------------------------------------------------
 * Method: create_icmp_pkt(sr_ethernet_hdr_t *eth_hdr, sr_ip_hdr_t *ip_hdr,
 *                         sr_icmp_t3_hdr_t *icmp_hdr, int icmp_len)
 * Scope: Local
 *
 * Returns a pointer to an Ethernet frame encapsulating an IP header and
 * ICMP header that can be sent out on the network.
 *
 *---------------------------------------------------------------------*/
sr_ethernet_hdr_t *create_icmp_pkt
  ( sr_ethernet_hdr_t * eth_hdr, 
    sr_ip_hdr_t * ip_hdr, 
    sr_icmp_hdr_t * icmp_hdr, 
    int icmp_len) 
{
    /* TODO: implement creation of Ethernet frame containing ARP or IP. */
    sr_ethernet_hdr_t * ether_rsp_hdr = \
      (sr_ethernet_hdr_t *) malloc(size_ether + size_ip + icmp_len);
    memcpy(((uint8_t *) ether_rsp_hdr) + size_ether + size_ip, 
           (uint8_t *)icmp_hdr, icmp_len);
    memcpy(((uint8_t *) ether_rsp_hdr) + size_ether, 
           (uint8_t *)ip_hdr, size_ip);

  /* Fill in the ethernet header. */
  memcpy(ether_rsp_hdr->ether_shost, eth_hdr->ether_dhost, ETHER_ADDR_LEN);
  memcpy(ether_rsp_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);
  ether_rsp_hdr->ether_type = ntohs(ethertype_ip);
  return ether_rsp_hdr;
}

/*---------------------------------------------------------------------
 * Method: create_and_send_icmp(uint8_t type, uint8_t code, sr_ip_hdr_t *ip_hdr,
                                sr_eth_hdr_t *eth_hdr, int len, char *interface)
 * Scope: Local
 *
 * Creates and sends an ICMP packet. Frees all structs used before exiting.
 *
 *---------------------------------------------------------------------*/
uint8_t * create_and_send_icmp
  ( uint8_t type, 
    uint8_t code, 
    sr_ip_hdr_t *ip_hdr, 
    sr_ethernet_hdr_t *eth_hdr, 
    struct sr_instance *sr,
    int len, 
    char *interface)
{
  sr_icmp_t3_hdr_t *icmp_rsp_hdr = create_icmp_t3(type, code, ip_hdr);
  sr_ip_hdr_t * ip_rsp_hdr = create_ip(ip_hdr);
  sr_ethernet_hdr_t *eth_rsp_hdr = create_icmp_pkt_t3(eth_hdr, ip_rsp_hdr, icmp_rsp_hdr);
  /** print_hdrs((uint8_t *)eth_rsp_hdr, len);*/
  
  struct sr_arpcache cache = sr->cache;
  uint32_t ip_dst = check_routing_table(sr, eth_rsp_hdr, ip_rsp_hdr, len, sr_get_interface(sr, interface));
  struct sr_arpentry * arp_dest = sr_arpcache_lookup(&cache, ip_dst);
  if (arp_dest != NULL) {
    memcpy(eth_rsp_hdr->ether_dhost, arp_dest->mac, ETHER_ADDR_LEN);
    sr_send_packet(sr,(uint8_t *)eth_rsp_hdr, len, interface);
    free(ip_rsp_hdr);
    free(icmp_rsp_hdr);
    free(eth_rsp_hdr);
  } else {
    struct sr_arpreq * req = sr_arpcache_queuereq(&cache, ip_rsp_hdr->ip_dst, (uint8_t *)eth_rsp_hdr, len, interface);
    handle_arpreq(req, sr);
  }
  return (uint8_t *)eth_rsp_hdr;

  
  /*sr_send_packet(sr, (uint8_t *)eth_rsp_hdr, len, interface);*/

  /* Free all structs. */
  /*free(icmp_rsp_hdr);
  free(ip_rsp_hdr);
  free(eth_rsp_hdr);*/
}
