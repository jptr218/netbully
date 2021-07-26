#pragma once
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <iostream>
#include <vector>
#include <string>

#include <pcap/pcap.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include "packet.h"

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

using namespace std;

uint16_t checksum(uint16_t* buf, int sz);
void strToIp(const char* s, uint8_t* ip);
vector<string> getDevices();

bool kill(pcap_t* handle, uint8_t* tmac, uint8_t* tip, uint8_t* smac, uint8_t* sip);
