#pragma once

#ifndef _MAIN_H_
#define _MAIN_H_

#include <iostream>
#include <thread>
#include <WinSock2.h>
#include <pcap.h>
#include <iphlpapi.h>
#include <conio.h>

#pragma warning(disable:4996)

using namespace std;

#define ETH_LEN	6
#define IP_LEN	4

#define ETHERTYPE_ARP	0x0806
#define ETHERTYPE_IP	0x0800

#define ARPCODE_REQ		0x0001
#define ARPCODE_RLY		0x0002

#define PROTOCOL_ICMP	1
#define PROTOCOL_TCP	6
#define PROTOCOL_UDP	17

#define PORT_ATTACK		4433
#define PORT_SSL		443

typedef struct _Info
{
	uint8_t		attacker_ip[IP_LEN];
	uint8_t		attacker_mac[ETH_LEN];
	uint8_t		victim_ip[IP_LEN];
	uint8_t		victim_mac[ETH_LEN];
	uint8_t		gateway_ip[IP_LEN];
	uint8_t		gateway_mac[ETH_LEN];
	pcap_t*		arp_handle;
	pcap_t*		dns_handle;
} Info, *pInfo;

typedef struct _Adapter_list
{
	int			number;
	PCHAR		interfaceName;
	PWCHAR		FriendlyName;
	PWCHAR		adapterName;
	uint8_t		mac_addr[ETH_LEN];
	ULONG		ip_addr;
	ULONG		gate_addr;
	struct _Adapter_list* next;
} Adapter_list, * pAdapter_list;

#pragma pack(push, 1)
struct ether_header
{
	uint8_t		dst_host[ETH_LEN];		// (8Bit x 6)	Destination MAC Address
	uint8_t		src_host[ETH_LEN];		// (8Bit x 6)	Source MAC Address
	uint16_t	ether_type;				// (16Bit)		Ethernet Type
};
#pragma pack(pop)

class Basic
{
public:
	Basic();
	Basic(const char* _vaddr, const char* host);
	~Basic();

	Info info;
	bool _init();
	void set_ip(_In_ const char* _src, _Inout_ uint8_t* _dst);

protected:
	bool get_adapters();
	bool print_adapters(PIP_ADAPTER_ADDRESSES tmp);
	bool insert_adapters_iist(PIP_ADAPTER_ADDRESSES tmp);
	bool open_adapter(int _inum);

private:
	char* _victim_addr;
	char* _attack_host;
	pAdapter_list head_list, tail_list, work_list;
};

#endif