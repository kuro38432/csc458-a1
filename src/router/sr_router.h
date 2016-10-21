/*-----------------------------------------------------------------------------
 * File: sr_router.h
 * Date: ?
 * Authors: Guido Apenzeller, Martin Casado, Virkam V.
 * Contact: casado@stanford.edu
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_ROUTER_H
#define SR_ROUTER_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>

#include "sr_protocol.h"
#include "sr_arpcache.h"

/* we dont like this debug , but what to do for varargs ? */
#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ## args)
#define DebugMAC(x) \
  do { int ivyl; for(ivyl=0; ivyl<5; ivyl++) printf("%02x:", \
  (unsigned char)(x[ivyl])); printf("%02x",(unsigned char)(x[5])); } while (0)
#else
#define Debug(x, args...) do{}while(0)
#define DebugMAC(x) do{}while(0)
#endif

#define INIT_TTL 255
#define PACKET_DUMP_SIZE 1024
#define ICMP_ECHO 0
#define ICMP_NO_DST 3
#define ICMP_NO_PORT 3
#define ICMP_TIME_EXCEED 11

/* forward declare */
struct sr_if;
struct sr_rt;

/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router.
 *
 * -------------------------------------------------------------------------- */

struct sr_instance
{
    int  sockfd;   /* socket to server */
    char user[32]; /* user name */
    char host[32]; /* host name */ 
    char template[30]; /* template name if any */
    unsigned short topo_id;
    struct sockaddr_in sr_addr; /* address to server */
    struct sr_if* if_list; /* list of interfaces */
    struct sr_rt* routing_table; /* routing table */
    struct sr_arpcache cache;   /* ARP cache */
    pthread_attr_t attr;
    FILE* logfile;
};

/* -- sr_main.c -- */
int sr_verify_routing_table(struct sr_instance* sr);

/* -- sr_vns_comm.c -- */
int sr_send_packet(struct sr_instance* , uint8_t* , unsigned int , const char*);
int sr_connect_to_server(struct sr_instance* ,unsigned short , char* );
int sr_read_from_server(struct sr_instance* );

/* -- sr_router.c -- */
void sr_init(struct sr_instance* );
void sr_handlepacket(struct sr_instance* , uint8_t * , unsigned int , char* );
int valid_pkt(sr_ip_hdr_t *pkt);
uint32_t check_routing_table(struct sr_instance* sr, sr_ethernet_hdr_t * eth_hdr,
 sr_ip_hdr_t *ip_hdr, unsigned int len, struct sr_if *iface);
uint8_t updateTTL(struct sr_instance* sr, sr_ethernet_hdr_t * eth_hdr,
  sr_ip_hdr_t *ip_hdr, struct sr_if *iface);
uint8_t *create_eth_pkt(unsigned char *src_mac, unsigned char *dest_mac,
  uint16_t packet_type, uint8_t *ip_packet, unsigned int ip_len);


/* -- sr_if.c -- */
void sr_add_interface(struct sr_instance* , const char* );
void sr_set_ether_ip(struct sr_instance* , uint32_t );
void sr_set_ether_addr(struct sr_instance* , const unsigned char* );
void sr_print_if_list(struct sr_instance* );

/* -- create_packet.c -- */
sr_icmp_t3_hdr_t *create_icmp_t3(uint8_t type, uint8_t code, sr_ip_hdr_t *ip_hdr);
sr_arp_hdr_t * create_arp(struct sr_if *iface, sr_arp_hdr_t *arp_hdr);
sr_arp_hdr_t * create_arp_request(struct sr_if *iface, uint32_t ip);
sr_ethernet_hdr_t * create_arp_eth(struct sr_if *iface, sr_arp_hdr_t *arp_hdr, sr_arp_hdr_t *tosend_arp);
sr_ethernet_hdr_t * create_arp_req_eth(sr_arp_hdr_t *tosend_arp);
sr_ip_hdr_t * create_ip(sr_ip_hdr_t * ip_hdr);
sr_ethernet_hdr_t * create_icmp_pkt_t3(sr_ethernet_hdr_t * eth_hdr, sr_ip_hdr_t * ip_hdr, sr_icmp_t3_hdr_t * icmp_hdr);
sr_ethernet_hdr_t * create_icmp_pkt(sr_ethernet_hdr_t *eth_hdr, sr_ip_hdr_t * ip_hdr, sr_icmp_hdr_t * icmp_hdr, int icmp_len);
void create_and_send_icmp(uint8_t type, uint8_t code, sr_ip_hdr_t *ip_hdr, sr_ethernet_hdr_t *eth_hdr, struct sr_instance *sr, int len, char *interface);

#endif /* SR_ROUTER_H */
