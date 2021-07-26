#pragma once
#include "netbully.h"

struct ether_header
{
	uint8_t  dest[6];
	uint8_t  src[6];
	uint16_t type;
};

struct ip_hdr
{
	uint8_t ihl : 4;
	uint8_t ver : 4;
	uint8_t ecn : 2;
	uint8_t dscp : 6;
	uint16_t len;
	uint16_t id;
	uint16_t fOff : 13;
	uint16_t flags : 3;
	uint8_t ttl;
	uint8_t proto;
	uint16_t csum;
	uint8_t src[4];
	uint8_t dest[4];
};

struct icmp_hdr
{
	uint8_t type;
	uint8_t code;
	uint16_t csum;
	uint16_t id;
	uint16_t seq;
};