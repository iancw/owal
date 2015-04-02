#include <unistd.h>
#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>
#include <stdlib.h>

#include <arpa/inet.h>
#include <net/if.h>

//#define _OWAL_TRACE_
#include "owal_info.h"
#include "owal_callback.h"
#include "probe_arp.h"
#include "ip_lists.h"

#define _PROG_ERR -1
#define NUM_LIST_IPS 100

void print_usage(char* name){
  printf("%s - Open Wireless Access Listening\n", name);
  printf("Usage:\t%s [-p] [-f filter] [-d device] [-t timeout] [-b probe sleep] [-l link type]\n", name);
  printf("\t-p\tlisten in promiscuous mode\n");
  printf("\t-h\tprint help and exit\n");
  printf("\t-f\tpcap filter expression\n");
  printf("\t-d\tspecify the device to listen on\n");
  printf("\t-t\tspecify the packet capture timeout in ms, value is 1000 if unspecified\n");
  printf("\t-b\tspecify the sleep time between ARP probes in seconds, value is 3 if unspecified\n");
  printf("\t-l\tspecify the data link type, typicall one of EN10MB, IEEE802_11_RADIO, IEEE802_11, or IEEE802_11_RADIO_AVS\n");
}
//Global so the session can be closed from the interrupt callback
pcap_t* session;

void ctrl_c_callback(){
  pthread_mutex_lock(&probe_run_mutex);
  probe_run_flag = 0;
  pthread_mutex_unlock(&probe_run_mutex);

  pcap_breakloop(session);
  pcap_close(session);
  printf("\nCapture stopped.\n");
}

int main (int argc, char** argv) {

  if(argc == 1){
    print_usage(argv[0]);
    return 0;
  }
  
  char errbuf[PCAP_ERRBUF_SIZE];
  char* filter_exp="";
  char* if_name=pcap_lookupdev(errbuf);
  int promisc_flag=0;
  char* getopt_arg_filter = "hpf::d::t::l::b::";
  int timeout = 1000;
  int optimize_filter = 0;
  int num_packets = -1;
  int probe_timer = 3;
  char *pref_link_type="";
  pthread_t loop_thread, probe_thread;
  struct arp_probe_args probe_args;
  struct pcap_loop_args *loop_args;

  signal(SIGINT, ctrl_c_callback);

  int c = getopt(argc, argv, getopt_arg_filter);
  while(c != -1){
    switch(c){
      case 'h':
       print_usage(argv[0]);
       return 0;
       break;
      case 'p':
        promisc_flag=1;
        break;
      case 'f':
        filter_exp=optarg;       
        break;
      case 'd':
        if_name=optarg;
        break;
      case 't':
        timeout=atoi(optarg);
        break;
      case 'l':
        pref_link_type=optarg;
        break;
      case 'b':
        probe_timer=atoi(optarg);
        break;
      default:
        print_usage(argv[0]);
        return _PROG_ERR;
    }
    c = getopt(argc, argv, getopt_arg_filter);
  }
  _owal_trace("Filter expression is \"%s\"\nPromiscuous flag is %d\nListening interface is %s\n", filter_exp, promisc_flag, if_name);
  _owal_trace("Timeout is %d\nNumber of packets is %d\nOptimize filter is %d\n", timeout, num_packets, optimize_filter);

  //Look up device information
  struct owal_if_info *device_info;
  device_info = (struct owal_if_info *)malloc(sizeof(struct owal_if_info));
  device_info->ip=0;
  memset(device_info->mac, 0x00, 6);
  device_info->broadcast=0;
  device_info->mask=0;
  lookup_device_info(device_info, if_name, errbuf);

  //Check device_info for errors...
  if(device_info->ip == 0 || device_info->mac == 0 || device_info->mask == 0){
    fprintf(stderr, "Error looking up device %s\n", if_name);
    fprintf(stderr, "%s\n", errbuf);
    return _PROG_ERR;
  }

  //Init libnet (requires sudo privs here)
  errbuf[0]=0;
  libnet_t *l = libnet_init(LIBNET_LINK_ADV, if_name, errbuf);
  if(l == NULL){
    fprintf(stderr, "Can't open libnet %s, (must be run as root).\n", errbuf);
    fprintf(stderr, "Continuing with ids without promiscuous detection\n");
  }
  if(strlen(errbuf) > 0){
    fprintf(stderr, "Warning: (post libnet_init) %s\n", errbuf);
    errbuf[0]=0;
  }
  struct libnet_ether_addr *src_mac;

  //Get the hardware address from libnet, doesn't seem to be a way
  // to get it from pcap
  if((src_mac = libnet_get_hwaddr(l)) == NULL){
    fprintf(stderr, "Can't find MAC address %s\n", libnet_geterror(l));
    return _PROG_ERR;
  }
  memcpy(device_info->mac, src_mac->ether_addr_octet, 6);

  //Begin pcap setup...
  //Open session
  session = pcap_open_live(device_info->name, BUFSIZ, promisc_flag, timeout, errbuf);
  if(session == NULL){
    fprintf(stderr, "%s\n", errbuf);
    return _PROG_ERR;
  }
  if(strlen(errbuf) > 0){
    fprintf(stderr, "Warning: (post pcap_open_live) %s\n", errbuf);
    errbuf[0]=0;
  }

  //Create BPF filter for packets
  struct bpf_program filter_program;
  if(pcap_compile(session, &filter_program, filter_exp, optimize_filter, device_info->mask) == -1){
    fprintf(stderr, "%s", pcap_geterr(session));
    return _PROG_ERR;
  }
  if(pcap_setfilter(session, &filter_program) == -1){
    fprintf(stderr, "%s", pcap_geterr(session));
    return _PROG_ERR;
  }
  pcap_freecode(&filter_program);

  //Set data link type
  device_info->link_type = select_datalink_type(session, pref_link_type);

  //Create shared lists of ips (black list, white list, gray list, probing list)
  _owal_trace("mallocing color_lists\n");
  owal_colors_p color_lists = (owal_colors_p)malloc(sizeof(struct owal_color_list));
  _owal_trace("mallocing black\n");
  color_lists->black = (owal_ip_list_p)malloc(sizeof(struct owal_ip_list));
  _owal_trace("mallocing plist\n");
  color_lists->black->plist = (u_int8_t**)malloc(sizeof(u_int8_t*) * NUM_LIST_IPS);
  color_lists->black->num=0;
  color_lists->black->bufsz=NUM_LIST_IPS;
  color_lists->black->list_mutex = (pthread_mutex_t*)malloc(sizeof(pthread_mutex_t));
  pthread_mutex_init(color_lists->black->list_mutex, NULL);

  _owal_trace("mallocing white\n");
  color_lists->white = (owal_ip_list_p)malloc(sizeof(struct owal_ip_list));
  _owal_trace("mallocing plist\n");
  color_lists->white->plist = (u_int8_t**)malloc(sizeof(u_int8_t*) * NUM_LIST_IPS);
  color_lists->white->num=0;
  color_lists->white->bufsz=NUM_LIST_IPS;
  color_lists->white->list_mutex = (pthread_mutex_t*)malloc(sizeof(pthread_mutex_t));
  pthread_mutex_init(color_lists->white->list_mutex, NULL);

  _owal_trace("mallocing gray\n");
  color_lists->gray = (owal_ip_list_p)malloc(sizeof(struct owal_ip_list));
  _owal_trace("mallocing plist\n");
  color_lists->gray->plist = (u_int8_t**)malloc(sizeof(u_int8_t*) * NUM_LIST_IPS);
  color_lists->gray->num=0;
  color_lists->gray->bufsz=NUM_LIST_IPS;
  color_lists->gray->list_mutex = (pthread_mutex_t*)malloc(sizeof(pthread_mutex_t));
  pthread_mutex_init(color_lists->gray->list_mutex, NULL);

  _owal_trace("mallocing probed\n");
  color_lists->probed = (owal_ip_list_p)malloc(sizeof(struct owal_ip_list));
  _owal_trace("mallocing plist\n");
  color_lists->probed->plist = (u_int8_t**)malloc(sizeof(u_int8_t*) * NUM_LIST_IPS);
  color_lists->probed->num=0;
  color_lists->probed->bufsz=NUM_LIST_IPS;
  color_lists->probed->list_mutex = (pthread_mutex_t*)malloc(sizeof(pthread_mutex_t));
  pthread_mutex_init(color_lists->probed->list_mutex, NULL);

  _owal_trace("Done mallocing\n");

  //Print lists
  trace_list(color_lists->gray);
  trace_list(color_lists->white);
  trace_list(color_lists->black);
  trace_list(color_lists->probed);

  //Initialize structures that pass arguments to the two threads
  //pcap loop thread...
  _owal_trace("mallocing loop_args\n");
  loop_args = (struct pcap_loop_args *)malloc(sizeof(struct pcap_loop_args));
  loop_args->session = session;
  loop_args->num_packets = num_packets;
  loop_args->packet_callback = packet_callback;
  loop_args->device_info = device_info;
  loop_args->lists = color_lists;
  _owal_trace("done initilizing loop_args\n");

  //libnet ARP generator thread...
  probe_args.timer = probe_timer;
  probe_args.device = device_info->name;
  probe_args.ip_lists = color_lists;

  //Flag that tells the ARP generator to stop
  probe_run_flag=1;

  printf("...done with initialization\n");
  printf("---------------------------------------------\n");
  print_device_info(device_info);
  printf("Beginning monitoring...(Ctrl-C to quit)\n");
  printf("---------------------------------------------\n");

  //Create both threads
  _owal_trace("starting the loop thread\n");
  pthread_create(&loop_thread, NULL, run_pcap_loop, (void*)loop_args);
  pthread_create(&probe_thread, NULL, run_arp_probe, (void*)&probe_args);

  //Wait for both to finish before exiting.
  pthread_join(loop_thread, NULL);
  pthread_join(probe_thread, NULL);
  return 0;
}
