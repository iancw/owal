all: owal

owal : wireless-listener.c owal_info.h owal_callback.h probe_arp.h ip_lists.h owal_vendor.h
	gcc -g wireless-listener.c -o owal -I../libpcap -L../libpcap -lpcap -lnet
