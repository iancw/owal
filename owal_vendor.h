#ifndef __OWAL_VENDOR_LOOKUP_H
#define __OWAL_VENDOR_LOOKUP_H

#include <stdio.h>
#include <stdlib.h>

char *_owal_vendor_buf;

char *owal_find_vendor(unsigned char *mac){
  FILE *fp;
  char *line_ptr;
  char mac_ascii[12];
  int n;
  int l_mac;
  char mac_arg_ascii[12];
  char *m_ptr;
  int i;
  unsigned char* m_arg_p = mac;

  free(_owal_vendor_buf);
  _owal_vendor_buf=(char *)malloc(255);
  _owal_vendor_buf[0]=0;

  char linebuf[512];
  line_ptr = linebuf;

  m_ptr = mac_arg_ascii;
  for(i=0; i<3; i++){
    sprintf(m_ptr, "%02hX", *m_arg_p);
    m_ptr+=2;
    m_arg_p+=1;
  }

  fp = fopen("ether-manufacturers.txt", "r");
  strcpy(_owal_vendor_buf, "unknown");
  if(!fp){
    return "(unknown)";
  }
  while (fgets(linebuf, 255, fp)){
    line_ptr=linebuf;
    sscanf(line_ptr, "%12[^\t\n]%n", mac_ascii, &n);
    if(strcmp(mac_ascii, mac_arg_ascii) == 0){
      line_ptr += n + 1;
      sscanf(line_ptr, "%12[^\t\n]%n", _owal_vendor_buf, &n);
      break;
    }
  }
  fclose(fp);
  return _owal_vendor_buf;
}

#endif
