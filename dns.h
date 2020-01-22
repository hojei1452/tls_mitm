#pragma once

#ifndef _DNS_H_
#define _DNS_H_

#include "main.h"
#include "arp.h"

#define UDP_PORT_DNS	53

#pragma pack(push, 1)
struct udp_header
{
	uint16_t	src_port;				// (16Bit)		Source Port
	uint16_t	dst_port;				// (16Bit)		Destination Port
	uint16_t	udp_len;				// (16Bit)		UDP + Data Length
	uint16_t	checksum;				// (16Bit)		UDP Header Checksum
};
#pragma pack(pop)

#pragma pack(push, 1)
struct dns_header
{
	uint16_t	trans_id;				// (16Bit)
	uint16_t	flags;					// (16Bit)
	uint16_t	questions;				// (16Bit)
	uint16_t	answer;					// (16Bit)
	uint16_t	auth;					// (16Bit)
	uint16_t	add;					// (16Bit)
};
#pragma pack(pop)

#pragma pack(push, 1)
struct dns_questions
{
	//uint8_t*	name;
	uint16_t	type;
	uint16_t	q_class;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct dns_answer
{
	uint16_t	name;
	uint16_t	type;
	uint16_t	q_class;
	uint32_t	ttl;
	uint16_t	data_len;
	uint8_t		addr[IP_LEN];
};
#pragma pack(pop)

class Dns : public Arp
{
public:
	Dns();
	~Dns();

	void dns_thread();
	bool dns_spoof();

protected:
	void ip_checksum(_Inout_ struct ip_header* _pIp);

private:
	pcap_pkthdr header;
	uint8_t* data;

};

#endif