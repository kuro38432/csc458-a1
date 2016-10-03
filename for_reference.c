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

  /* fill in code here */
  sr_print_if((struct sr_if *) interface);
  uint16_t ethtype = ethertype(packet);
  if (ethtype == ethertype_ip) {
    printf("ip\n");
    uint8_t * ip_packet = packet + sizeof(sr_ethernet_hdr_t);
    uint8_t ip_proto = ip_protocol(ip_packet);
    if (ip_proto == ip_protocol_icmp) {
      printf("icmp\n");
    } else {
      printf("not icmp\n");
    }
  } else if (ethtype == ethertype_arp) {
    printf("arp\n");
    sr_arp_hdr_t * arp_packet = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    if (ntohs(arp_packet->ar_op) == arp_op_request) {
      printf("request\n");
      print_hdr_arp((uint8_t *)arp_packet);
      /* make arp packet */
      sr_arp_hdr_t * arp_reply = (sr_arp_hdr_t *)malloc(sizeof(sr_arp_hdr_t));
      arp_reply->ar_hrd = ntohs(arp_hrd_ethernet);
      arp_reply->ar_pro = ntohs(ethertype_ip);
      arp_reply->ar_hln = ETHER_ADDR_LEN;
      arp_reply->ar_pln = 4;
      arp_reply->ar_op = ntohs(arp_op_reply);
      struct sr_if * iface = sr_get_interface(sr, interface);
      memcpy(arp_reply->ar_sha, iface->addr, ETHER_ADDR_LEN);
      memcpy(arp_reply->ar_tha, arp_packet->ar_sha, ETHER_ADDR_LEN);
      arp_reply->ar_sip = iface->ip;
      arp_reply->ar_tip = arp_packet->ar_sip;
      print_hdr_arp((uint8_t *)arp_reply);
      /* make ethernet packet
      uint8_t * sr_pkt;
      sr_pkt = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
      sr_arp_hdr_t * arp_reply = (sr_arp_hdr_t *)(sr_pkt + sizeof(sr_ethernet_hdr_t));
      arp_reply->ar_hrd = arp_hrd_ethernet;
      arp_reply->ar_pro = ethertype_ip;
      arp_reply->ar_hln = ETHER_ADDR_LEN;
      arp_reply->ar_pln = 4;
      arp_reply->ar_op = arp_op_reply;
      memcpy(arp_reply->ar_sha, ((struct sr_if *)interface)->addr, ETHER_ADDR_LEN);
      memcpy(arp_reply->ar_tha, arp_packet->ar_sha, ETHER_ADDR_LEN);
      arp_reply->ar_sip = ((struct sr_if *)interface)->ip;
      arp_reply->ar_tip = arp_packet->ar_sip;
      sr_ethernet_hdr_t * ether_pkt = (sr_ethernet_hdr_t *)(sr_pkt);
      memcpy(ether_pkt->ether_dhost, arp_packet->ar_sha, ETHER_ADDR_LEN);
      memcpy(ether_pkt->ether_shost, ((struct sr_if *)interface)->addr, ETHER_ADDR_LEN);
      ether_pkt->ether_type = ethertype_arp;
      print_hdrs(sr_pkt, len);
      sr_send_packet(sr, sr_pkt, len, interface);
      free(sr_pkt);*/
    } else if (ntohs(arp_packet->ar_op) == arp_op_reply) {
      printf("reply \n");
    } else {
      printf("opcode: %d \n", ntohs(arp_packet->ar_op));
    }
  } else {
    printf("other\n");
  }

}/* end sr_ForwardPacket */
