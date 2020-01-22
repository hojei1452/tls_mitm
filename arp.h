#pragma once

#ifndef _ARP_H_
#define _ARP_H_

#include "main.h"

#pragma pack(push, 1)
struct arp_header
{
	uint16_t	hw_type;				// (16Bit)		Hardware Type
	uint16_t	protocol_type;			// (16Bit)		Protocol Type
	uint8_t		hw_size;				// (8Bit)		Hardware Size
	uint8_t		protocol_size;			// (8Bit)		Protocol Size
	uint16_t	opcode;					// (16Bit)		Opcode[1-4]
	uint8_t		sender_host[ETH_LEN];	// (8Bit x 6)	Sender MAC Address
	uint8_t		sender_ip[IP_LEN];		// (8Bit x 4)	Sender IP Address
	uint8_t		target_host[ETH_LEN];	// (8Bit x 6)	Target MAC Address
	uint8_t		target_ip[IP_LEN];		// (8Bit x 4)	Target IP Address
};
#pragma pack(pop)

#pragma pack(push, 1)
struct ip_header
{
	uint8_t		header_len : 4;			// (4Bit)		IP Header Length
	uint8_t		version : 4;			// (4Bit)		IP Hedaer Version
	uint8_t		ds_filed;				// (8Bit)		Type of Service
	uint16_t	total_len;				// (16Bit)		Total Length
	uint16_t	id;						// (16Bit)		Identification
	uint16_t	flags;					// (16Bit)		IP Flags(4Bit) + Fragment Offset(12Bit)
	uint8_t		ttl;					// (8Bit)		Time To Live
	uint8_t		protocol;				// (8Bit)		Next Protocol
	uint16_t	checksum;				// (16Bit)		IP Header Checksum
	uint8_t		src_ip[IP_LEN];			// (8Bit x 4)	Source IP Address
	uint8_t		dst_ip[IP_LEN];			// (8Bit x 4)	Destination IP Address
};
#pragma pack(pop)

class Arp : public Basic
{
public:
	Arp();
	~Arp();

	void arp_thread();
	bool arp_init();

protected:
	bool is_equal(uint8_t* _com1, uint8_t* _com2, int _len);
	bool find_macaddr(uint8_t _src_ip[], uint8_t _dst_mac[]);
	void print_info(uint8_t _addr[], int _len);
	bool arpspoof();
	bool forwarding();

private:
	pcap_pkthdr header;
	uint8_t* data;
	
};

#endif