#include <stdio.h>
#include <libnet.h>

#include "owal_info.h"
#include "ip_lists.h"


struct arp_probe_args{
  unsigned timer;
  owal_colors_p ip_lists;
  char* device;
};

int probe_run_flag;
pthread_mutex_t probe_run_mutex = PTHREAD_MUTEX_INITIALIZER;

int auto_probe_arp(char* device, u_int8_t* dst_mac, u_int8_t *tgt_mac, u_int8_t *tgt_ip){
  u_int32_t src_ip, dst_ip;
  struct libnet_ether_addr* src_mac;
  int i;
  char errbuf[LIBNET_ERRBUF_SIZE];
  libnet_t *l;

  //Open libnet context
  l = libnet_init(LIBNET_LINK_ADV, device, errbuf);
  if(l == NULL){
    fprintf(stderr, "libnet_init failed: %s\n", errbuf);
    return -1;
  }

  printf("Probing for promiscuous devices using ARP on %s\n", device);
  if((src_ip = libnet_get_ipaddr4(l)) == -1){
    fprintf(stderr, "Can't find ip address for this machine %s\n", libnet_geterror(l));
    return -1;
  }

  //Get the hardware address
  if((src_mac = libnet_get_hwaddr(l)) == NULL){
    fprintf(stderr, "Can't find MAC address %s\n", libnet_geterror(l));
    return -1;
  }
  print_mac("Source MAC is ", src_mac->ether_addr_octet, "\n");

  //Print the destination mac
  print_mac("Destination MAC is ", dst_mac, "\n");

  return probe_arp(l, dst_mac, src_mac->ether_addr_octet, (u_int8_t *)&src_ip, tgt_mac, tgt_ip);
}

/*
 * Uses libnet to build and send an ARP packet.
 * @param l       the libnet context
 * @param src_mac the ARP hardware source
 * @param src_ip  the ARP protocol source
 * @param dst_mac the ethernet destination
 */
int probe_arp(libnet_t *l, u_int8_t *dst_mac, u_int8_t *src_mac, u_int8_t *src_ip, u_int8_t *tgt_mac, u_int8_t *tgt_ip){

  libnet_ptag_t arp_ptag = libnet_autobuild_arp(ARPOP_REQUEST, src_mac, src_ip, tgt_mac, tgt_ip, l);

  if(arp_ptag == -1){
    fprintf(stderr, "Problems building arp packet:  %s\n", libnet_geterror(l));
    return -1;
  }

  libnet_ptag_t eth_ptag = libnet_build_ethernet(
    dst_mac,
    src_mac,
    0x0806,
    NULL,
    0,
    l,
    0
  );
  if(eth_ptag == -1){
    fprintf(stderr, "Problems building ethernet packet:  %s\n", libnet_geterror(l));
    return -1;
  }
  if(libnet_write(l) == -1){
    fprintf(stderr, "Write error:  %s\n", libnet_geterror(l));
    return -1;
  }

  return 0;
}


void probe_ip(libnet_t *l, libnet_ptag_t *arp_ptag, libnet_ptag_t *eth_ptag, u_short hrd, u_int8_t *src_mac, u_int8_t* src_ip, u_int8_t *tgt_mac, u_int8_t *tgt_ip, u_int8_t *dst_mac){

    int i;
    _owal_trace_ip("Starting probes against ", tgt_ip, "\n");
    owal_print_ip("Probing ", tgt_ip, "...\n");
    for(i=0; i<NUM_FAKE_MACS; i++){
      if(!probe_run_flag){
        return;
      }
       dst_mac = (u_int8_t*)(fake_macs[i]);
       owal_print_mac("\twith ", dst_mac, "...\n");
       //Print the destination mac
       //print_mac("Probing ", dst_mac, "...\n");

       *arp_ptag = libnet_build_arp(
         hrd,
         ETHERTYPE_IP,
         6,
         4,
         ARPOP_REQUEST, 
         src_mac,
         src_ip, 
         tgt_mac, 
         tgt_ip, 
         NULL,
         0,
         l,
         *arp_ptag);

        if(*arp_ptag == -1){
          fprintf(stderr, "Problems building arp packet:  %s\n", libnet_geterror(l));
          break;
        }
        *eth_ptag = libnet_build_ethernet(
          dst_mac,
          src_mac,
          0x0806,
          NULL,
          0,
          l,
          *eth_ptag
        );
        if(*eth_ptag == -1){
          fprintf(stderr, "Problems building ethernet packet:  %s\n", libnet_geterror(l));
          break;
        }

        if(libnet_write(l) == -1){
          fprintf(stderr, "Write error:  %s\n", libnet_geterror(l));
          break;
        }
        sleep(2);
    }
}


void *run_arp_probe(void* void_args){
  struct arp_probe_args *probe_args = (struct arp_probe_args *)void_args;
  int i;
  u_int8_t tgt_mac[6];
  u_int8_t* dst_mac;
  memset(tgt_mac, 0, 6);

  u_int32_t src_ip, dst_ip;
  struct libnet_ether_addr* src_mac;
  char errbuf[LIBNET_ERRBUF_SIZE];
  libnet_t *l;
  char* device = probe_args->device;
  owal_colors_p ip_lists = probe_args->ip_lists;

  //Open libnet context
  l = libnet_init(LIBNET_LINK_ADV, device, errbuf);
  if(l == NULL){
    fprintf(stderr, "libnet_init failed: %s\n", errbuf);
    return;
  }

  _owal_trace("Probing for promiscuous devices using ARP on %s\n", device);
  if((src_ip = libnet_get_ipaddr4(l)) == -1){
    fprintf(stderr, "Can't find ip address for this machine %s\n", libnet_geterror(l));
    return;
  }

  //Get the hardware address
  if((src_mac = libnet_get_hwaddr(l)) == NULL){
    fprintf(stderr, "Can't find MAC address %s\n", libnet_geterror(l));
    return;
  }
  //print_mac("Source MAC is ", src_mac->ether_addr_octet, "\n");

  libnet_ptag_t arp_ptag, eth_ptag;
  arp_ptag=0;
  eth_ptag=0;
  u_short hrd;
    
        switch (l->link_type)
        {
        case 1: /* DLT_EN10MB */
            hrd = ARPHRD_ETHER;
            break;
        case 6: /* DLT_IEEE802 */
            hrd = ARPHRD_IEEE802; 
            break;
        default:
            hrd = 0;
            snprintf(l->err_buf, LIBNET_ERRBUF_SIZE,
                    "%s(): unsupported link type\n", __func__);
            return;
        /* add other link-layers */
       }

  int loop_var;
  pthread_mutex_lock(&probe_run_mutex);
  loop_var = probe_run_flag;
  pthread_mutex_unlock(&probe_run_mutex);
  while(loop_var){
    _owal_trace("starting-loop...\n");
    if(ip_lists->gray->num > 0){
      _owal_trace("someing in gray...\n");
      i=0;
      //owal_print_list(ip_lists->gray);
      while(ip_lists->gray->num > 0){
        u_int8_t *cur_ip = ip_lists->gray->plist[0];

        //Need to add first, in case the callback gets hit before probes finish
        owal_remove(ip_lists->gray, cur_ip);
        owal_add(ip_lists->probed, cur_ip);

        probe_ip(l, &arp_ptag, &eth_ptag, hrd, src_mac->ether_addr_octet, (u_int8_t*)&src_ip, tgt_mac, cur_ip, dst_mac);

        if(!probe_run_flag){
          break;
        }
        sleep(probe_args->timer);
      }
    }
    _owal_trace("Done with all probes\n");
    pthread_mutex_lock(&probe_run_mutex);
    loop_var = probe_run_flag;
    pthread_mutex_unlock(&probe_run_mutex);
    _owal_trace("Re-looping...\n");
  }
}
