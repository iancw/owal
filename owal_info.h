
#include <stdarg.h>
#ifndef _OWAL_INFO_H_
#define _OWAL_INFO_H_

#define NUM_FAKE_MACS 6
#define ETHER_ADDR_LEN 6
const u_char fake_macs[NUM_FAKE_MACS][ETHER_ADDR_LEN] = {
 {0xff, 0xff, 0xff, 0xff, 0xff, 0xfe},
 {0xff, 0xff, 0x00, 0x00, 0x00, 0x00},
 {0xff, 0x00, 0x00, 0x00, 0x00, 0x00},
 {0x01, 0x00, 0x00, 0x00, 0x00, 0x00},
 {0x01, 0x00, 0x5e, 0x00, 0x00, 0x00},
 {0x01, 0x00, 0x5e, 0x00, 0x00, 0x01}
 };

/*
 * Stores information about the interface that the program
 * will listen on.  This is used to pass data to the packet
 * callback method.
 */
struct owal_if_info {
  bpf_u_int32 net;
  bpf_u_int32 mask;
  bpf_u_int32 broadcast;
  bpf_u_int32 gateway;
  bpf_u_int32 ip;
  u_int8_t mac[6];
  char* name;
  int link_type;
};

typedef struct owal_if_info * owal_if_info_p;

/*
 * pulled from  
 * http://www.linuxquestions.org/questions/linux-networking-3/howto-find-gateway-address-through-code-397078/ 
 */
bpf_u_int32 find_gateway(char* if_name){
  char line[255];
  char *p, *q, *z;
  FILE *fp;
  bpf_u_int32 result=0;
  u_int8_t *octet=(u_int8_t*)&result;

  system("netstat -rn > tmp-gateway.txt");
  fp = fopen("tmp-gateway.txt", "rb");
  if (!fp)
    return -1;
  while (fgets(line, 255, fp))
  if ((p = strstr(line, "default")) && (z = strstr(line, if_name)))
    break;
  int i = 0;
  while (!isdigit(p[i]))
    i++;
  q = p + i;
  z=q;
  p = strstr(q, ".");
  *p=0;
  octet[0] = atoi(z);
  *p='.';
  p++;
  z=p;
  p = strstr(p, ".");
  *p=0;
  octet[1] = atoi(z);
  *p='.';
  p++;
  z=p;
  p = strstr(p, ".");
  *p=0;
  octet[2] = atoi(z);
  *p='.';
  p++;
  z=p;
  i = 0;
  while (isdigit(p[i]))
    i++;
  p[i]=0;
  octet[3] = atoi(z);
  q[strlen(q) - strlen(p) + i] = 0;
  fclose(fp);
  return result;
}

/*
 * Prints the first n bytes of a packet as hexidecimal to
 * standard out
 *
 */
void print_packet_hex(const int n, const u_char* packet, const int line_size){
  int i;
  for(i = 0; i<n; i++){
    printf("%02x", packet[i]);
    if(((i+1)%line_size)==0) {printf("\n");}
  }
  printf("\n");
}

void print_mac(char* prefix, u_int8_t *mac, char* suffix){
  int i;
  printf("%s", prefix);
  for(i=0; i<6; i++){
    printf("%02x%s", mac[i], i<5 ? ":" : "");
  }
  printf("%s", suffix);
}

void _owal_trace(char * str_arg, ...){
#ifdef _OWAL_TRACE_
  va_list args;
  va_start(args, str_arg);
  vprintf(str_arg, args);
  va_end(args);
#endif
}

void owal_print_mac(char* prefix, u_int8_t *mac, char* suffix){
  int i;
  printf("%s", prefix);
  for(i=0; i<6; i++){
    printf("%02x%s", mac[i], i<5 ? ":" : "");
  }
  printf("%s", suffix);
}


void owal_print_ip(char* prefix, u_int8_t *ip, char* suffix){
  int i;
  printf("%s", prefix);
  for(i=0; i<4; i++){
    printf("%d%s", ip[i], i<3 ? "." : "");
  }
  printf("%s", suffix);
}

void _owal_trace_ip(char * prefix, u_int8_t* ip, char* suffix){
#ifdef _OWAL_TRACE_
  owal_print_ip(prefix, ip, suffix);
#endif
}

void _owal_trace_mac(char * prefix, u_int8_t* ip, char* suffix){
#ifdef _OWAL_TRACE_
  owal_print_mac(prefix, ip, suffix);
#endif
}

void print_device_info(owal_if_info_p info){
  struct in_addr tmp_addr;

  owal_print_ip("Network address:\t", (u_int8_t*)&info->net, "\n");
  owal_print_ip("Network mask:\t\t", (u_int8_t*)&info->mask, "\n");
  owal_print_ip("Gateway:\t\t", (u_int8_t*)&info->gateway, "\n");
  printf("Interface name:\t\t%s\n", info->name);
  owal_print_mac("MAC address:\t\t", (u_int8_t*)&info->mac, "\n");
  owal_print_ip("IP address:\t\t", (u_int8_t*)&info->ip, "\n");
}

int select_datalink_type(pcap_t* session, const char* pref){

 //Choose a data link
  int *dlt_buf;
  int num = pcap_list_datalinks(session, &dlt_buf);
  int i;
  printf("Available data link types are...\n");
  int sel_type = -1;
  for(i=0; i<num; i++){
    const char* dl_name=pcap_datalink_val_to_name(dlt_buf[i]); 
    printf("%x - %s - %s\n", 
	   dlt_buf[i], 
	   dl_name, 
	   pcap_datalink_val_to_description(dlt_buf[i]));
    if(strcmp(dl_name, pref) == 0){
      sel_type = dlt_buf[i];
    }
  }
  if(sel_type == -1){
    sel_type = dlt_buf[0];
  }
  const char* selected_name = pcap_datalink_val_to_name(sel_type);
  const char* selected_desc = pcap_datalink_val_to_description(sel_type);
  int dl_result = pcap_set_datalink(session, sel_type);
  if(dl_result < 0) {
    fprintf(stderr, "Failed to set data link to type %s: %s, select another\n",  selected_name, selected_desc);
  }else{
    printf("Set data link to  %s: %s.\n",  selected_name, selected_desc);
  }
  return sel_type;
}


void lookup_device_info(owal_if_info_p this_info, char* if_name, char* errbuf){
  pcap_if_t *alldevs, *dev_ptr, *this_dev;
  pcap_addr_t *list;
  
  this_info->name=if_name;

  this_info->gateway=find_gateway(if_name);

  //Lookup network and network mask
  pcap_lookupnet(if_name, &this_info->net, &this_info->mask, errbuf);

  //Loop through all returned devices and try
  //to match if_name with the device name
  pcap_findalldevs(&alldevs, errbuf);
  dev_ptr = alldevs;
  while(dev_ptr != NULL){
    if(dev_ptr->name != NULL){
      if(strcmp(dev_ptr->name, if_name) == 0){
        this_dev = dev_ptr;
        _owal_trace("Debug: found pcap_if_t for %s\n", dev_ptr->name);
        break;
      }
    }
    dev_ptr = dev_ptr->next;
  }
  if(this_dev!=NULL){
  list=this_dev->addresses;
  //lookup interface address
  //Devices can have multiple addresses, find the one that matches the most of
  //the network address.  Example, I get three addresses for my wireless card:
  // 6.3.6.0, 0.0.0.0, and 192.168.1.178.
  while(list != NULL){
    if(list->addr != NULL){
      switch(list->addr->sa_family){
        case AF_INET:{
          struct sockaddr_in *addr = (struct sockaddr_in *)list->addr;
          this_info->ip=addr->sin_addr.s_addr;
          addr = (struct sockaddr_in *)list->broadaddr;
          this_info->broadcast=addr->sin_addr.s_addr;
          addr = (struct sockaddr_in *)list->netmask;
          this_info->mask=addr->sin_addr.s_addr;
          break;
        }
        case AF_LINK:{
          //This doesn't actually appear to be the hardware MAC
          //device_hardware_addr = (struct sockaddr*)list->addr;
          break;
        }
        case AF_INET6:{
          //No support for inet 6 addresses
          break;
        }
        default: printf("Unsupported address family: %u will be ignored.\n", list->addr->sa_family);
      }
    }
    list=list->next;
  }
  }
}

#endif
