#include "ip.h"


void Ip(uint8_t *ip_addr, std::string s){
    unsigned int addr[IP_SIZE] = { 0 };
    sscanf(s.c_str(),  "%u.%u.%u.%u", &addr[0], &addr[1], &addr[2], &addr[3]);
    for(int i=0;i<IP_SIZE;i++){
        ip_addr[i] = (uint8_t)addr[i];
    }
}

bool ip_eq(uint8_t *ip1, uint8_t *ip2){
    for(int i=0;i<IP_SIZE;i++){
        if(ip1[i] != ip2[i])
            return false;
    }
    return true;
}