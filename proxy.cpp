#include "proxy.h"

CSERVER::CSERVER() {	}

CSERVER::CSERVER(_In_ int _port)
{
	//std::thread thread_exit(&CSERVER::Thread_exit, this);
	//thread_exit.detach();
	port = _port;
}

CSERVER::~CSERVER() {	}

void CSERVER::Thread_exit()
{
	fprintf(stdout, "Shutdown, press the [esc] key..\n");

	while (1)
	{
		if (getch() == 27)
		{
			fprintf(stdout, "\n");
			for (UINT j = 0; total > 0 && j < TotalSockets; j++)
				FreeSocketInformation(i);
			WSACleanup();
			exit(0);
		}
	}
}

void CSERVER::proxy_thread()
{
	thread porxyThread(&CSERVER::do_start, this);
	porxyThread.detach();
}

void CSERVER::do_start()
{
	SockWSAStartup();
	Sockup(SOCK_STREAM, IPPROTO_TCP);
	SockInfo();
	SockSetInfo();
	SockListen();

	while (TRUE)
	{
		SockAccept();
		Sock_SSLecho();
	}
}

bool CSERVER::SockWSAStartup()
{
	if (WSAStartup(MAKEWORD(2, 2), &wsaData))
	{
		fprintf(stderr, "[!] WSAStartup()\n");
		return false;
	}
	return true;
}

bool CSERVER::Sockup(_In_ int type, _In_ int protocol)
{
	hservSock = WSASocket(AF_INET, type, protocol, NULL, 0, WSA_FLAG_OVERLAPPED);
	if (hservSock == INVALID_SOCKET)
	{
		fprintf(stderr, "[!] WSASocket()\n");
		return false;
	}
	return true;
}

void CSERVER::SockInfo()
{
	memset(&serverInfo, 0, sizeof(serverInfo));
	serverInfo.sin_family = AF_INET;
	serverInfo.sin_addr.s_addr = INADDR_ANY;
	serverInfo.sin_port = htons(port);
}

bool CSERVER::SockSetInfo()
{
	if (bind(hservSock, (PSOCKADDR)&serverInfo, sizeof(serverInfo)) == SOCKET_ERROR)
	{
		fprintf(stderr, "[!] bind()\n");
		return false;
	}
	return true;
}

bool CSERVER::SockListen()
{
	if(listen(hservSock, 5))
	{
		fprintf(stderr, "[!] listen()\n");
		return false;
	}
	return true;
}

bool CSERVER::SetNon_block(_In_ SOCKET socket, _In_ ULONG mods)
{
	non_block = mods;
	if (ioctlsocket(socket, FIONBIO, &non_block) == SOCKET_ERROR)
	{
		fprintf(stderr, "[!] ioctlsocket()\n");
		return false;
	}
	return true;
}

bool CSERVER::SelectIO()
{
	total = select(0, &ReadSet, &WriteSet, NULL, NULL);
	if (total == SOCKET_ERROR)
	{

		fprintf(stderr, "[!] ioctlsocket()\n");
		return false;
	}
	return true;
}

bool CSERVER::CreateSocketInformation(_In_ SOCKET socket)
{
	LPSOCKET_INFORMATION SI;

	fprintf(stdout, "[+] Accepted socket number %d\n", socket);

	SI = (LPSOCKET_INFORMATION)GlobalAlloc(GPTR, sizeof(SOCKET_INFORMATION));
	if ((int)SI == NULL)
	{
		fprintf(stderr, "[!] GlobalAlloc()\n");
		return false;
	}

	SI->Socket = socket;
	SI->BytesSEND = 0;
	SI->BytesRECV = 0;

	SSL_init();
	SSL_Setinfo(SI);
	if (!SSL_server(SI))
	{
		closesocket(socket);
		fprintf(stdout, "[-] Closing socket number %d\n", socket);
		GlobalFree(SI);
		return false;
	}

	int size;
	struct sockaddr_in sock;
	size = sizeof(sock);
	memset(&sock, 0x00, sizeof(sock));
	getpeername(socket, (struct sockaddr*) & sock, &size);
	SSL_client(inet_ntoa(sock.sin_addr), SI);
	fprintf(stdout, "[+] Accepted socket number %d\n", SI->Client);

	SetNon_block(socket, 1);
	SetNon_block(SI->Client, 1);

	SocketArray[TotalSockets] = SI;
	TotalSockets++;

	return true;
}

void CSERVER::FreeSocketInformation(_In_ DWORD index)
{
	LPSOCKET_INFORMATION SI = SocketArray[index];
	DWORD i;

	closesocket(SI->Socket);
	closesocket(SI->Client);
	fprintf(stdout, "[-] Closing socket number %d\n", SI->Socket);
	fprintf(stdout, "[-] Closing socket number %d\n", SI->Client);
	GlobalFree(SI);

	for (i = index; i < TotalSockets; i++)
		SocketArray[i] = SocketArray[i + 1];

	TotalSockets--;
}

bool CSERVER::SockAccept()
{
	FD_ZERO(&ReadSet);
	FD_ZERO(&WriteSet);

	FD_SET(hservSock, &ReadSet);

	for (i = 0; i < TotalSockets; i++)
	{
		if (SocketArray[i]->BytesRECV > SocketArray[i]->BytesSEND)
			FD_SET(SocketArray[i]->Socket, &WriteSet);
		else
			FD_SET(SocketArray[i]->Socket, &ReadSet);
	}

	SelectIO();

	if (FD_ISSET(hservSock, &ReadSet))
	{
		total--;
		hclntSock = accept(hservSock, NULL, NULL);
		if (hclntSock == INVALID_SOCKET)
		{
			fprintf(stderr, "[!] accept()\n");
			return false;
		}
		CreateSocketInformation(hclntSock);
	}
	return true;
}

bool CSERVER::SSL_init()
{
	if (SSL_library_init() == -1)
	{
		fprintf(stderr, "[!] SSL_library_init()\n");
		return false;
	}
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	return true;
}

//void CSERVER::load_file(_Inout_ BIO* bio, _In_ char* filename)
//{
//	fprintf(stdout, "[!]File name : %s\n", filename);
//	LOG(_ETC, "BIO_read_filename()", BIO_read_filename(bio, filename), 0);
//}

bool CSERVER::SSL_Setinfo(_Inout_ LPSOCKET_INFORMATION socket)
{
	socket->ctx = SSL_CTX_new(SSLv23_server_method());
	if ((int)socket->ctx == NULL)
	{
		fprintf(stderr, "[!] SSL_CTX_new()\n");
		return false;
	}

	if (SSL_CTX_use_certificate_file(socket->ctx, "server.crt", SSL_FILETYPE_PEM) <= 0)
	{
		fprintf(stderr, "[!] SSL_CTX_use_certificate_file()\n");
		return false;
	}

	if (SSL_CTX_use_PrivateKey_file(socket->ctx, "server.key", SSL_FILETYPE_PEM) <= 0)
	{
		fprintf(stderr, "[!] SSL_CTX_use_PrivateKey_file()\n");
		return false;
	}

	if (!SSL_CTX_check_private_key(socket->ctx))
	{
		fprintf(stderr, "[!] SSL_CTX_check_private_key()\n");
		return false;
	}
	return true;
}

bool CSERVER::SSL_server(_Inout_ LPSOCKET_INFORMATION socket)
{
	if (FD_ISSET(hservSock, &ReadSet))
	{
		socket->ssl = SSL_new(socket->ctx);
		if ((int)socket->ssl == 0)
		{
			fprintf(stderr, "[!] SSL_CTX_new()\n");
			return false;
		}

		if (SSL_use_certificate_file(socket->ssl, "server.crt", SSL_FILETYPE_PEM) <= 0)
		{
			fprintf(stderr, "[!] SSL_CTX_use_certificate_file()\n");
			return false;
		}

		if (SSL_use_PrivateKey_file(socket->ssl, "server.key", SSL_FILETYPE_PEM) <= 0)
		{
			fprintf(stderr, "[!] SSL_CTX_use_certificate_file()\n");
			return false;
		}

		if (!SSL_check_private_key(socket->ssl))
		{
			fprintf(stderr, "[!] SSL_CTX_check_private_key()\n");
			return false;
		}

		SSL_set_accept_state(socket->ssl);

		if (SSL_set_fd(socket->ssl, socket->Socket) == 0)
		{
			fprintf(stderr, "[!] SSL_set_fd()\n");
			return false;
		}

		SSL_set_ex_data(socket->ssl, 0, this);

		if (SSL_is_init_finished(socket->ssl))
		{
			fprintf(stderr, "[!] SSL_is_init_finished()\n");
			return false;
		}

		fprintf(stdout, "[*] SSL_accept()...");
		res = SSL_accept(socket->ssl);
		if (res <= 0) {
			fprintf(stderr, "[!] SSL_accept()\n");
			return false;
		}
		fprintf(stdout, "ok\n");
		fprintf(stdout, "[*] SSL Connected!\n");

		certInfo(socket->ssl, _server);
	}
	return true;
}

bool CSERVER::SSL_client(_In_ const char* _host, _Inout_ LPSOCKET_INFORMATION Client)
{
	c_hSocket = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
	if (c_hSocket == INVALID_SOCKET)
	{
		fprintf(stderr, "[!] WSASocket()\n");
		return false;
	}

	// test
	hostent* test = gethostbyname("naver.com");
	struct in_addr add_temp;
	u_long* temp;
	temp = (u_long*)*test->h_addr_list;
	add_temp.s_addr = *temp;
	printf("[*] Server IP Address : %s\n", inet_ntoa(add_temp));

	memset(&c_serverInfo, 0, sizeof(c_serverInfo));
	c_serverInfo.sin_family = AF_INET;
	c_serverInfo.sin_addr.S_un.S_addr = *temp;
	c_serverInfo.sin_port = htons(sslPort);

	if (connect(c_hSocket, (SOCKADDR*)&c_serverInfo, sizeof(c_serverInfo)) == SOCKET_ERROR)
	{
		fprintf(stderr, "[!] connect()\n");
		return false;
	}

	SSL_init();
	c_ctx = SSL_CTX_new(SSLv23_client_method());
	if ((int)c_ctx == NULL)
	{
		fprintf(stderr, "[!] SSL_CTX_new()\n");
		return false;
	}

	c_ssl = SSL_new(c_ctx);
	if ((int)c_ssl == 0)
	{
		fprintf(stderr, "[!] SSL_new()\n");
		return false;
	}

	if (SSL_set_fd(c_ssl, c_hSocket) == 0)
	{
		fprintf(stderr, "[!] SSL_set_fd()\n");
		return false;
	}

	fprintf(stdout, "[*] SSL_connect()...");
	res = SSL_connect(c_ssl);
	if (res <= 0) {
		fprintf(stderr, "[!] SSL_connect()\n");
		return false;
	}
	fprintf(stdout, "ok\n");
	fprintf(stdout, "[*] SSL Connected!\n");

	certInfo(c_ssl, _client);

	Client->ssl_Client = c_ssl;
	Client->Client = c_hSocket;

	return true;
}

bool CSERVER::certInfo(_In_ SSL* ssl, _In_ int socket)
{
	fprintf(stdout, "encryption : %s\n", SSL_get_cipher(ssl));

	if (socket == _server)
		cert = SSL_get_certificate(ssl);
	else if (socket == _client)
		cert = SSL_get_peer_certificate(ssl);
	if ((int)cert == NULL)
	{
		fprintf(stderr, "[!] SSL_get_certificate()\n");
		return false;
	}

	info = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
	fprintf(stdout, "[!] Server Certificate : %s ", info);
	info = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
	fprintf(stdout, "%s\n", info);
	X509_free(cert);
	return true;
}

bool CSERVER::Sock_SSLecho()
{
	for (i = 0; total > 0 && i < TotalSockets; i++)
	{
		LPSOCKET_INFORMATION SocketInfo = SocketArray[i];

		if (FD_ISSET(SocketInfo->Socket, &ReadSet))
		{
			total--;
			memset(&echo, 0, sizeof(echo));
			fprintf(stdout, "[*] SSL_read()...");
			if (SSL_read(
				SocketInfo->ssl,
				echo,
				sizeof(echo)) == SOCKET_ERROR)
			{
				if (WSAGetLastError() != WSAEWOULDBLOCK)
				{
					FreeSocketInformation(i);
					fprintf(stderr, "[!] SSL_read()\n");
					return false;
				}
				else
					fprintf(stdout, "ok\n");
				continue;
			}
			else
			{
				fprintf(stdout, "ok\n");
				SocketInfo->BytesRECV = strlen(echo);
				if (SocketInfo->BytesRECV == 0)
				{
					FreeSocketInformation(i);
					continue;
				}
				fprintf(stdout, "[!] Clinet : \n%s\n", echo);

				// Host: °Ë»ö
				strncpy(search, echo, strlen(echo));
				server_addr = strtok(search, "\r\n");
				if (strcmp(server_addr, "GET / HTTP/1.1"))
					continue;
				server_addr = strtok(NULL, ": \r\n");
				server_addr = strtok(NULL, ": \r\n");
				printf("[!] ServerIP : %s\n", server_addr);
			}
		}
		if (FD_ISSET(SocketInfo->Socket, &WriteSet))
		{
			total--;

			fprintf(stdout, "[*] SSL_write()...");
			if (SSL_write(
				SocketInfo->ssl_Client,
				echo,
				strlen(echo)) == SOCKET_ERROR)
			{
				if (WSAGetLastError() != WSAEWOULDBLOCK)
				{
					FreeSocketInformation(i);
					fprintf(stderr, "[!] SSL_write()\n");
					return false;
				}
				else
					fprintf(stdout, "ok\n");
				continue;
			}
			else
			{
				fprintf(stdout, "ok\n");
				SocketInfo->BytesSEND += strlen(echo);
				if (SocketInfo->BytesSEND == SocketInfo->BytesRECV)
				{
					SocketInfo->BytesSEND = 0;
					SocketInfo->BytesRECV = 0;
				}
			}
			fprintf(stdout, "[!] Server : \n%s\n", echo);
		}
	}
	return true;
}