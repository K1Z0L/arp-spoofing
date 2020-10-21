#pragma once

#include <string>
#include <stdint.h>

#define MAC_SIZE    6

void Mac(uint8_t *mac_addr, std::string s);
bool mac_eq(uint8_t *mac1, uint8_t *mac2);