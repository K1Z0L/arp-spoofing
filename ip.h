#pragma once

#include <string>
#include <stdint.h>

#define PROTO_IPv4  0x0800
#define IP_SIZE     4

void Ip(uint8_t *ip_addr, std::string s);
bool ip_eq(uint8_t *ip1, uint8_t *ip2);