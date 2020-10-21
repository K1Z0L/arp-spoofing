#include "mac.h"

void Mac(uint8_t *mac_addr, std::string s){
    unsigned int addr[MAC_SIZE] = { 0 };
    sscanf(s.c_str(), "%02x:%02x:%02x:%02x:%02x:%02x", &addr[0], &addr[1], &addr[2], &addr[3], &addr[4], &addr[5]);
    for(int i=0;i<MAC_SIZE;i++){
        mac_addr[i] = (uint8_t)addr[i];
    }
}

bool mac_eq(uint8_t *mac1, uint8_t *mac2){
    for(int i=0;i<MAC_SIZE;i++){
        if(mac1[i] != mac2[i])
            return false;
    }
    return true;
}