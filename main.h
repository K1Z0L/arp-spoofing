#include <stdio.h>
#include <pcap/pcap.h>
#include <libnet.h>
#include <sys/ioctl.h>
#include <net/if.h> 
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <net/if_dl.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include "ip.h"
#include "mac.h"

#define SUCCESS 1
#define FAIL -1

struct arp_addr{
    uint8_t smac_addr[6];
    uint8_t sip_addr[4];
    uint8_t tmac_addr[6];
    uint8_t tip_addr[4];
};

typedef struct _ARP_PK{
    struct libnet_ethernet_hdr eth;
    struct libnet_arp_hdr arp;
    struct arp_addr arp_;
}ARP_PK;
