#ifndef _OWAL_IP_LISTS_H_
#define _OWAL_IP_LISTS_H_
#include <pthread.h>
#include <stdlib.h>
#include "owal_info.h"//for the print statements
/*
 * ips in the black list are known to be in promiscuous mode
 * ips in the white list are known to not be in promiscuous mode
 * ips in the grey list are unknown
 */

struct owal_ip_list{
  int bufsz;
  int num;
  pthread_mutex_t* list_mutex;
  u_int8_t **plist;
};
typedef struct owal_ip_list * owal_ip_list_p;

struct owal_color_list {
  /*
  * ips that have been determined to be in promiscuous mode
  */
  owal_ip_list_p black;
  /*
  * ips that have been determined to not be in promiscuous mode
  */
  owal_ip_list_p white;
  /* ips that have been identified, 
   * are typically on the local net,
   * but have not yet been classified as
   * black or white
   */
  owal_ip_list_p gray;
  /*
   * ips that have been probed, but are still
   * awaiting probe responses
   */
  owal_ip_list_p probed;
};
typedef struct owal_color_list * owal_colors_p;


void trace_list(owal_ip_list_p list){
  _owal_trace("num: %d\n", list->num);
  _owal_trace("bufsz: %d\n", list->bufsz);
  _owal_trace("plist: %d\n", list->plist);
  _owal_trace("data: \n");
  int i;
  for(i=0; i<list->num; i++){
    _owal_trace("[%d]", i);
    _owal_trace_ip("", list->plist[i], i<list->num-1 ? "\n" : "");
  }
  _owal_trace("\n");
}

void owal_print_list(owal_ip_list_p lists){
  int i;
  for(i=0; i<lists->num; i++){
    owal_print_ip("", lists->plist[i], i<lists->num-1 ? "," : "");
  }
  printf("\n");
}

int owal_find(owal_ip_list_p list, u_int8_t *ip){
  int i;
  int ret=-1;
  pthread_mutex_lock(list->list_mutex);
  for(i=0; i<list->num; i++){
    if(memcmp(ip, list->plist[i], 4) == 0){
      _owal_trace_ip("Found ", ip, " in gray");
      _owal_trace(" (at %d).\n", i);
      ret= i;
      break;
    }
  }
  pthread_mutex_unlock(list->list_mutex);
  return ret;
}
int owal_add(owal_ip_list_p list, u_int8_t* ip){
  int i;
  if(list->num < list->bufsz){
    _owal_trace("Inserting at %d\n", list->num);
    pthread_mutex_lock(list->list_mutex);
    list->plist[list->num] = (u_int8_t*)malloc(sizeof(u_int8_t) * 4);
    memcpy(list->plist[list->num], ip, sizeof(u_int8_t) * 4);
    list->num++;
    pthread_mutex_unlock(list->list_mutex);
    _owal_trace("New list size is %d\n", list->num);
    return 1;
  }else{
    fprintf(stderr, "List is full (%d of %d)\n", list->num, list->bufsz);
    return -1;
  }
  _owal_trace("Done adding\n");
  return -1;
}

int owal_remove(owal_ip_list_p list, u_int8_t* ip){
  int idx = owal_find(list, ip);
  if(idx > -1){
    _owal_trace_ip("Removing ", ip, " from list");
    _owal_trace("[%d]\n", idx);
    int i;
    pthread_mutex_lock(list->list_mutex);
    u_int8_t *old_ptr = list->plist[idx];
    free(old_ptr);
    for(i=idx; i<list->num-1; i++){
      list->plist[i]=list->plist[i+1];
    }
    list->num--;
    pthread_mutex_unlock(list->list_mutex);
    _owal_trace("New list size is %d\n", list->num);
  }else{
    _owal_trace_ip("Could not find ip to remove ", ip, "\n");
    return -1;
  }
  return 0;
}

/*
 * If the ip isn't in black or white, add it to gray
 */
int owal_offer_ip(owal_colors_p lists, u_int8_t* ip){
  _owal_trace("In offer...");
  int pos_b = owal_find(lists->black, ip);
  int pos_w = owal_find(lists->white, ip);
  int pos_g = owal_find(lists->gray, ip);
  int pos_probed = owal_find(lists->probed, ip);
  _owal_trace("black: %d, white: %d, gray: %d, probed: %d\n", pos_b, pos_w, pos_g, pos_probed);
  if(pos_b == -1 && pos_w == -1 && pos_g == -1 && pos_probed == -1){
      _owal_trace("tracing gray...\n");
      trace_list(lists->gray);
      _owal_trace_ip("Adding ", ip, " to gray list...\n");
      owal_add(lists->gray, ip);
      _owal_trace("tracing gray...\n");
      trace_list(lists->gray);
  }
}
#endif
