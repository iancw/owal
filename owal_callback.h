#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <pcap.h>

#include "owal_info.h" //For if_info_t
#include "ip_lists.h"
#include "owal_vendor.h"

#define ETH_HEADER_SIZE 14
#define IP_ADDR_LEN 4
#define AVS_HEADER_SIZE 64 /* AVS capture header size */
#define DATA_80211_FRAME_SIZE 24 /* header for 802.11 data packet */
#define LLC_HEADER_SIZE 8 /* LLC frame for encapsulation */

struct pcap_loop_args{
  pcap_t* session;
  int num_packets;
  void* packet_callback;
  owal_if_info_p device_info;
  owal_colors_p lists;
};
typedef struct pcap_loop_args * loop_args_p;

void *run_pcap_loop(void* args){
  struct pcap_loop_args *c_args = (struct pcap_loop_args *)args;
  if(pcap_loop(c_args->session, c_args->num_packets, c_args->packet_callback, (u_char*)c_args) == -1){
    fprintf(stderr, "%s", pcap_geterr(c_args->session));
  }
}

void generic_htos(const u_char* address, const char* format, const char* separator, const int addr_len, int increment_size, char* buf){
    int i = addr_len;
    char *pbuf = buf;
    pbuf[1] = 0;
    do{
      sprintf(pbuf, format,(i == addr_len) ? " " : separator,*address++);
      pbuf+=increment_size;
      pbuf[1] = 0;
    }while(--i>0);
}

/*
 * Converts an ethernet host string (MAC address from ether_header->ether_dhost)
 * into a six-segment hex string with bytes separated by colons.
 *
 */
void ether_htos(const u_char* host, char* buf){
  generic_htos(host, "%s%02x", ":", ETHER_ADDR_LEN, 3, buf); 
}

void ip_htos(const u_char* ip, char* buf){
  generic_htos(ip, "%s%d", ".", IP_ADDR_LEN, 2, buf); 
}

/*
 * Checks a given host string to see if its a promiscuous probe.
 * This should only be called using ether_header->ether_dhost since
 * that's the method of probing for promiscuous cards.
 *
 * This function will return true if host is one of the following
 * fake broadcast addresses:
 * FF:FF:FF:FF:FF:FE
 * FF:FF:00:00:00:00
 * FF:00:00:00:00:00
 * 01:00:00:00:00:00
 * 01:00:5E:00:00:00
 * 01:00:5E:00:00:01
 *
 */
int check_promisc_probe(const u_char* host){
  int equal=1;
  int i,j;
  char comp_str[20];
  char host_str[20];
  ether_htos(host, host_str);
  for(i=0; i<NUM_FAKE_MACS; i++){
    equal  = 1;
    const u_char* c_mac = fake_macs[i];
    ether_htos(c_mac, comp_str);
    _owal_trace("Comparing %s to %s...", comp_str, host_str);
    for(j=0; j<ETHER_ADDR_LEN && equal; j++){
      equal &= (host[j] == c_mac[j]);
      _owal_trace("[%d]: %d...", j, equal);
    }
    _owal_trace("\n");
    if(equal) return equal;
  }

 return equal;
}

void print_arp_packet(struct ether_arp* arp_packet){
      printf("HTYPE:\t%u\n", ntohs(arp_packet->ea_hdr.ar_hrd));
      printf("PTYPE:\t%u\n", ntohs(arp_packet->ea_hdr.ar_pro));
      printf("HLEN:\t%u\n", ntohs(arp_packet->ea_hdr.ar_hln));
      printf("PLEN:\t%u\n", ntohs(arp_packet->ea_hdr.ar_pln));
      printf("OPER:\t%u(", ntohs(arp_packet->ea_hdr.ar_op));
      switch(arp_packet->ea_hdr.ar_op){
         case ARPOP_REQUEST: printf("Request to resolve address");
         break;
         case ARPOP_REPLY: printf("Response to previous request");
         break;
         case ARPOP_REVREQUEST: printf("Request protocal address given hardware");
         break;
         case ARPOP_REVREPLY: printf("Response giving protocol address");
         break;
         case ARPOP_INVREQUEST: printf("Request to identify peer");
         break;
         case ARPOP_INVREPLY: printf("Response to identifying peer");
         break;
       }
       printf(")\n");
       printf("Sender address: ");
       int i;
       int len = arp_packet->ea_hdr.ar_pln;
       for(i=0; i<len; i++){
        printf("%d%s", arp_packet->arp_spa[i], i==len-1? "" : ".");
       }
       len = arp_packet->ea_hdr.ar_hln;
       printf(" [");
       for(i=0; i<len; i++){
        printf("%02x%s", arp_packet->arp_sha[i], i==len-1? "" : ":");
       }
       printf("]\n");
       printf("Destination address: ");
       len = arp_packet->ea_hdr.ar_pln;
       for(i=0; i<len; i++){
        printf("%d%s", arp_packet->arp_tpa[i], i==len-1? "" : ".");
       }
       len = arp_packet->ea_hdr.ar_hln;
       printf(" [");
       for(i=0; i<len; i++){
        printf("%02x%s", arp_packet->arp_tha[i], i==len-1? "" : ":");
       }
       printf("]\n");
}

print_packet(const struct pcap_pkthdr* header, const u_char* packet){
  print_packet_hex(header->len, packet, 80);
}

/*
 * Returns the offset of the match, or -1 if no match was found.
 */
int match_in_packet(const u_char* pattern, const u_char* packet, int pattern_len, int packet_len){
  int i;
  int j;
  for(i = 0; i<packet_len; i++){
    int all_match = 1;
    for(j=0; j<pattern_len; j++){
      all_match &= (pattern[j] == packet[i+j]);
    }
    if(all_match){
      return i;
    }
  }
  return -1;
}

/*
 *  Returns 1 if the ip is a peer, as far as we can tell,
 *  and not a broadcast address or gateway
 */
int is_peer(bpf_u_int32 *ip, owal_if_info_p this_info){

  _owal_trace_ip("mask: ", (u_int8_t*)&this_info->mask, "\n");
  _owal_trace_ip("net: ", (u_int8_t*)&this_info->net, "\n");
  _owal_trace_ip("ip: ", (u_int8_t*)ip, "\n");
  bpf_u_int32 masked = (this_info->mask & *ip);
  _owal_trace_ip("masked: ", (u_int8_t*)&masked, "\n"); 
  int is_local = (memcmp(&masked, &this_info->net, 4) == 0);
  int is_broadcast = (memcmp(ip, &this_info->broadcast, 4) == 0);
  int is_self = (memcmp(ip, &this_info->ip, 4) == 0);
  int is_gateway = (memcmp(ip, &this_info->gateway, 4) == 0);
  return is_local && !is_broadcast && !is_self && !is_gateway; 
}

int is_spanning_tree(const u_char *packet){
  const u_int8_t stp_macs[5][6] = {{0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcd}, //CISCO SSTP
    {0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc}, //CDP VTP
   {0x01, 0x80, 0xc2, 0x00, 0x00, 0x00}, //IEEE 802.1d
{0x01, 0x080, 0xc2, 0x00, 0x00, 0x08}, //IEEE 802.1ad
   {0x01, 0x80, 0xc2, 0x00, 0x00, 0x02}}; //IEEE 802.3ah
   int i;
   for(i=0; i<5; i++){
      if(memcmp(packet, stp_macs[i], 6) == 0){
        return 1;
      }
   }
  return 0;
}

void process_arp(owal_colors_p lists, owal_if_info_p this_info, struct ether_arp* arp_packet){
  if(memcmp(arp_packet->arp_sha, this_info->mac, 6)==0){
    //It's just us, get out of here
    return;
  }

  if(check_promisc_probe(arp_packet->arp_tha))
  {
    printf("Detected promiscuous probing...\n");
  }else{
    //Offer ips as potential hosts to check for promiscuous
    if(is_peer((bpf_u_int32*)arp_packet->arp_spa, this_info)){
      _owal_trace_ip("offering ip", (u_int8_t*)arp_packet->arp_spa, "\n");
      owal_offer_ip(lists, (u_int8_t*)arp_packet->arp_spa);
    }
    if(is_peer((bpf_u_int32*)arp_packet->arp_tpa, this_info)){
      _owal_trace_ip("offering ip", (u_int8_t*)arp_packet->arp_tpa, "\n");
      owal_offer_ip(lists, (u_int8_t*)arp_packet->arp_tpa);
    }

    if(memcmp(arp_packet->arp_tha, &this_info->mac, 6) == 0){
      _owal_trace_mac("Peer ", arp_packet->arp_sha, "");
      _owal_trace_ip(" (",  arp_packet->arp_spa, ")");
      _owal_trace(" is ARPing us\n");
      _owal_trace("hw format: %02x, proto fmt: %02x, op: %02x\n", arp_packet->ea_hdr.ar_hrd, arp_packet->ea_hdr.ar_pro, arp_packet->ea_hdr.ar_op);

      switch(ntohs(arp_packet->ea_hdr.ar_op)){
        case ARPOP_REQUEST: _owal_trace("REQUEST"); 
        break;
        case ARPOP_REPLY: _owal_trace("REPLY");
          owal_print_mac("\tARP reply from ", arp_packet->arp_sha, "");
          printf("/%s", owal_find_vendor(arp_packet->arp_sha));
          owal_print_ip(" (",  arp_packet->arp_spa, ")\n");

        break;
        case ARPOP_REVREQUEST: _owal_trace("REVREQUEST");
        break;
        case ARPOP_REVREPLY: _owal_trace("REVREPLY");
        break;
        case ARPOP_INVREQUEST:  _owal_trace("INVREQUEST");
        break;
        case ARPOP_INVREPLY:  _owal_trace("INVREPLY");
        break;
       default:  _owal_trace("%u", arp_packet->ea_hdr.ar_op);
      }
      _owal_trace(")\n");

      //This is an arp reply directed to us...
      if(arp_packet->ea_hdr.ar_op == ARPOP_REPLY){
        //The message is a reply...
      }
      if(owal_find(lists->probed, (u_int8_t*)arp_packet->arp_spa) != -1){
        //We've probed this host, and it responded to our ARP probe
        owal_print_ip("Warning:  host ", (u_int8_t*)arp_packet->arp_spa, "");
        owal_print_mac("(", (u_int8_t*)arp_packet->arp_sha, "/");
        printf("%s) appears to be in promiscuous mode!\n", owal_find_vendor(arp_packet->arp_sha), arp_packet->ea_hdr.ar_op);
        owal_remove(lists->probed, (u_int8_t*)arp_packet->arp_spa);
        owal_remove(lists->gray, (u_int8_t*)arp_packet->arp_spa);
        owal_add(lists->black, (u_int8_t*)arp_packet->arp_spa);
      }
    }
  }
  _owal_trace("done with arp\n");
}

char* protocol_from_i(u_char c){
  switch(c){
    case IPPROTO_UDP: return "UDP";
    case IPPROTO_TCP: return "TCP";
    case IPPROTO_ICMP: return "ICMP";
  }
  return "";
}

void print_ip_packet(struct ip* ip_header, int linesz){
  u_char * data = (u_char *)ip_header + ip_header->ip_hl;
  char line[linesz+1];
  int i;
  for(i=0; i<ip_header->ip_len-linesz; i+=linesz){
    memcpy(&line, data+i, linesz);
    line[linesz]=0;
    printf("%s\n", line);
  }
}

void process_ip(owal_colors_p lists, struct ip* ip_header, owal_if_info_p this_info){
   u_int32_t source_ip = ip_header->ip_src.s_addr;
   u_int32_t dest_ip = ip_header->ip_dst.s_addr;

   if(memcmp(&this_info->ip, &ip_header->ip_dst.s_addr, 4)==0){
     //The destination address is this host
     //If traffic is coming from another host on the network, 
     //it might be suspect.
     if(is_peer((bpf_u_int32*)&source_ip, this_info)){
       owal_offer_ip(lists, (u_int8_t*)&source_ip);
       int header_len = ip_header->ip_hl << 2;
       u_int16_t *src_port = (u_int16_t*)(((u_char*)ip_header) + header_len);
       u_int16_t *dest_port = (u_int16_t*)src_port + 1;//sizeof(u_int16_t);

       printf("Warning:  ip packet (%s) from lan peer (%s:%u ->", protocol_from_i(ip_header->ip_p), inet_ntoa(ip_header->ip_src), ntohs(*src_port));
       printf(" %s:%u)\n", inet_ntoa(ip_header->ip_dst), ntohs(*dest_port));
     }
   }else if(memcmp(&this_info->ip, &ip_header->ip_src.s_addr, 4) == 0){
     //The source is this host, this is okay traffic to ignore
   }else{
     //This host is neither the source nor the dest, must be in promiscous mode!
     //offer both ips
     
     if(is_peer((bpf_u_int32*)&source_ip, this_info)){
        _owal_trace_ip("offering ip", (u_int8_t*)&source_ip, "\n");
        owal_offer_ip(lists, (u_int8_t*)&source_ip);
     }
     if(is_peer((bpf_u_int32*)&dest_ip, this_info)){
        _owal_trace_ip("offering ip", (u_int8_t*)&dest_ip, "\n");
        owal_offer_ip(lists, (u_int8_t*)&dest_ip);
     }
   }
}

void packet_callback(u_char* user, const struct pcap_pkthdr* header, const u_char* packet){
  _owal_trace("in packet callback...");
  loop_args_p loop_args = (loop_args_p)user;
  owal_if_info_p this_info = loop_args->device_info;
  struct ether_header* eth_header;
  struct ether_arp* arp_packet;
  struct ip* ip_header;

  eth_header = (struct ether_header *) packet;
  arp_packet = (struct ether_arp * ) (packet + ETH_HEADER_SIZE);
  ip_header = (struct ip *)(packet + ETH_HEADER_SIZE);

  _owal_trace_mac("Source: ", eth_header->ether_shost, " (");
  _owal_trace("%s), ", owal_find_vendor(eth_header->ether_shost));
  _owal_trace_mac("Dest: ", eth_header->ether_dhost, " ("); 
  _owal_trace("%s)\n", owal_find_vendor(eth_header->ether_dhost));

  u_int16_t ether_type = ntohs(eth_header->ether_type);
  switch(ether_type){
    case ETHERTYPE_REVARP:
    case ETHERTYPE_ARP: 
      _owal_trace("Going into arp...\n");
      process_arp(loop_args->lists, this_info, arp_packet);
      _owal_trace("done with arp...\n");
      break;
   case ETHERTYPE_IP: 
      _owal_trace("Going into ip...");
     process_ip(loop_args->lists, ip_header, this_info);
      _owal_trace("done with ip...\n");
     break;
     case ETHERTYPE_PUP:
      _owal_trace("Got packet type ETHERTYPE_PUP...\n");
     break;
     case ETHERTYPE_VLAN:
      _owal_trace("Got packet type ETHERTYPE_VLAN...\n");
     break;
     case ETHERTYPE_IPV6:
      _owal_trace("Got packet type ETHERTYPE_IPV6...\n");
     break;
     case ETHERTYPE_LOOPBACK:
      _owal_trace("Got packet type ETHERTYPE_LOOPBACK...\n");
     break;
     case ETHERTYPE_TRAIL:
      _owal_trace("Got packet type ETHERTYPE_TRAIL...\n");
     break;
   default: 
     if(is_spanning_tree(packet)){
       //For STP packets
       _owal_trace("Got BPDU packet\n");
     }else{
       if(memcmp(arp_packet->arp_tha, &this_info->mac, 6) == 0){
        printf("Received packet of unsupported type (0x%04x) ", ether_type);
        owal_print_mac("from ", eth_header->ether_shost, " (");
        printf("%s)\n", owal_find_vendor(eth_header->ether_shost));

       }

       //print_packet(header, packet);
     }
  }
  _owal_trace("Black: \n");
  trace_list(loop_args->lists->black);
  _owal_trace("Gray: \n");
  trace_list(loop_args->lists->gray);
  _owal_trace("White: \n");
  trace_list(loop_args->lists->white);
  _owal_trace("Probed: \n");
  trace_list(loop_args->lists->probed);
  _owal_trace("done with callaback...\n");
}
