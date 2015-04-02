#include <stdio.h>
#include <string.h>
#include <libnet.h>
#include <pcap.h>

int main(int argc, char** argv){

  u_int32_t src_ip, dst_ip;
  struct libnet_ether_addr* src_mac, dst_mac, tgt_mac;

  char errbuf[LIBNET_ERRBUF_SIZE];
  int i;
  char*device = "en1";
  libnet_t *l = NULL;
  l = libnet_init(LIBNET_LINK_ADV, device, errbuf);
  if(l == NULL){
    fprintf(stderr, "libnet_init failed: %s\n", errbuf);
    return -1;
  }

  if((src_ip = libnet_get_ipaddr4(l)) == -1){
    fprintf(stderr, "Can't find ip address for this machine %s\n", libnet_geterror(l));
    return -1;
  }
  u_int8_t dst_ip_8[4] = {0, 0, 0, 0};
  dst_ip = *((u_int32_t*)dst_ip_8);
  dst_ip = src_ip+1;

  struct in_addr src_ip_addr;
  src_ip_addr.s_addr = src_ip;
  printf("Source ip is %s\n", inet_ntoa(src_ip_addr));

  if((src_mac = libnet_get_hwaddr(l)) == NULL){
    fprintf(stderr, "Can't find MAC address %s\n", libnet_geterror(l));
    return -1;
  }

  struct in_addr dst_ip_addr;
  dst_ip_addr.s_addr = dst_ip;
  printf("Target ip is %s\n", inet_ntoa(dst_ip_addr));

  printf("Source MAC is ");
  for(i=0; i<6; i++){
    printf("%02x%s", src_mac->ether_addr_octet[i], i<5 ? ":" : "");
  }
  printf("\n");

  for(i=0; i<5; i++){
    dst_mac.ether_addr_octet[i]=0xff;
  }
  dst_mac.ether_addr_octet[5]=0xfe;
  memset(tgt_mac.ether_addr_octet, 0, 6);

  printf("Target MAC is ");
  for(i=0; i<6; i++){
    printf("%02x%s", dst_mac.ether_addr_octet[i], i<5 ? ":" : "");
  }
  printf("\n");

  libnet_ptag_t arp_ptag = libnet_autobuild_arp(
  ARPOP_REQUEST,/* ARP operation type u_int16_t */
  src_mac->ether_addr_octet, /* sender's hardware address (u_int8_t *) */
  (u_int8_t *)&src_ip, /* sender's protocol address (u_int8_t *) */
  tgt_mac.ether_addr_octet, /* target hardware address (u_int8_t *) */
  (u_int8_t *)&dst_ip, /* target protocol address (u_int8_t *) */
  l  /* libnet context (libnet_t *) */
  );
  if(arp_ptag == -1){
    fprintf(stderr, "Problems building arp packet:  %s\n", libnet_geterror(l));
    return -1;
  }


  libnet_ptag_t eth_ptag = libnet_build_ethernet(
    dst_mac.ether_addr_octet,
    src_mac->ether_addr_octet,
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
  printf("Writing packet...\n");
  if(libnet_write(l) == -1){
    fprintf(stderr, "Write error:  %s\n", libnet_geterror(l));
  }
  printf("Cleaning up...\n");

  libnet_destroy(l);

return 0;
}
