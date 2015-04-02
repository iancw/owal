How to compile the Open Wireless Access Listener (owal) project:

Requirements:  
 - Mac OS X, may work with other UNIXes
 - libnet 

Owal requires two libraries:  libpcap and libnet.  The source for both is included, the libpcap binaries for OS X are also included.  I was unable to compile the libnet source on OS X as downloaded, but the homebrew package manager (http://mxcl.github.com/homebrew/) for OS X included prebuild binaries of version 1.1.4, which I used.  Macports or fink may also contain libnet, and are the easiest way of building owal.

Step 1: Unzip the owal deliverable
 - tar -xzvf owal-cs232-project.tgz
Step 1:  Install libnet
 - brew install libnet
Step 2:  Build pcap
 - cd into the libpcap sub directory
 - ./configure
 - make
Step 2:  Build owal
 - cd into the owal directory
 - make
Step 3:  Run the owal executable
 - ./owal



Open Wireless Access Listener (owal) is a program that monitors traffic between nodes in the local network, identifying potentially risky behavior like local-network-peer to local-network-peer communication and promiscuous hosts.  Owal is written in C and relies on the pcap library for packet capture and libnet for packet construction and transmission.  It has three main components of functionality, corresponding to three header files:  owal_info.h, owal_callback.h, and probe_arp.h.   

The first phase is gathering information about the local host and network configuration for use interpreting later intercepts of network traffice.  This requires identifying the ip address, hardware address, network address, network mask, and default gateway.  All this information is stored in a C structure named owal_if_info (defined in owal_info.h) for use by the latter two stages.  

The second and third phases are packet capture, and probing for promiscuous hosts via ARP.  Both phases are performed simultaneously and continuously for the duration of the program.  As it runs, it prints status messages to the console and warnings about potentially nefarious behavior.  Owal runs until terminated by Ctrl-C.  The simultaneous execution if performed using POSIX threads.  The two entry points for the threads are run_pcap_loop in owal_callback.h and run_arp_probe in probe_arph.h.  The two threads communicate with each other using a group of shared lists of ip addresses, which are defined in ip_lists.h.  The lists are arrainged into color groups based on the observed behavior of the ips.  When the callback loop first identifies a new ip, it adds it to the gray list, which the ARP probe thread monitors.  As new ips are added to the gray list, the ARP probe thread generates ARP probes for promiscuous configurations.  This is done by addressing the packets to hardware addresses which should be rejected by interfaces, unless they are in promiscous mode.  Just before probing, those addresses are added to a probed list, which the callback thread monitors.  When the callback thread encounters an ARP response, it checks to see if the source is in the probed thread.  If it is, we know the host is in promiscous mode, because otherwise its network interface should have filtered out the ARP request.  When a promiscous host is found, its ip is moved into the black list and a warning is printed to the console. 

The callback thread also listens for packets originating from hosts within the local network.  In open wireless acess situations, it's undesirable for local-network-peers to interact with your host, as none of them are known to be secure and none have valid reasons to interact with other peers.  When these packets are encountered, the callback function prints warnings to the console with the source ip and source and destination ports.  This allows for identification of the type of traffic being sent, which is important context.  Although theoretically peers have no need to communicate, practically many operating systems are configured to share printers and files, and have no way of knowing that the host is operating in an environment where that type of sharing is undesirable.  It's frequenty to observe traffic over TCP port 139 and UDP port 137, which NetBIOS uses to coordinate printer, file sharing, and name resolution.

