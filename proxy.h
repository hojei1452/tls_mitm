#pragma once 

#ifndef __DEFAULT_H_
#define __DEFAULT_H_

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>

#include "main.h"

typedef struct _SOCKET_INFORMATION {
#define DATA_BUFSIZE 8192
	CHAR Buffer[DATA_BUFSIZE];
	WSABUF DataBuf;
	SOCKET Socket;
	SOCKET Client;
	OVERLAPPED Overlapped;
	DWORD BytesSEND;
	DWORD BytesRECV;
	SSL_CTX* ctx;
	SSL* ssl;
	SSL* ssl_Client;
	EVP_PKEY* get_key;
	X509* get_crt;
} SOCKET_INFORMATION, * LPSOCKET_INFORMATION;

class CSERVER
{
public:
	CSERVER();
	CSERVER(_In_ int _port);
	~CSERVER();

	void	proxy_thread();
	void	do_start();
private:
	//* Variable *//
	// Using WSAStartup() funtion
	WSADATA		wsaData;

	// nonblock option 1
	ULONG		non_block;

	// Using WSARecv() funtion
	DWORD		Flags;

	//ssl
	BIO* bio;
	long		res;
	int			err;
	X509* cert;
	char* info;
	int			read_size;
	char		echo[DATA_BUFSIZE];
	char* server_addr;
	char		search[DATA_BUFSIZE];

	// Server/Client socket infomation
	UINT			port;
	SOCKET			hclntSock;
	SOCKADDR_IN		serverInfo;
	SOCKET			hservSock;

	// Loop variable
	DWORD		i;

	// total work list number
	DWORD		total;
	DWORD		TotalSockets = 0;

	// connected socket infomation
	LPSOCKET_INFORMATION	SocketArray[FD_SETSIZE];

	// Data read/recv variables
	FD_SET		ReadSet;
	DWORD		RecvBytes;

	// Data write/send variables
	FD_SET		WriteSet;
	DWORD		SendBytes;

protected:
	// Basic function
	bool	SockWSAStartup();
	bool	Sockup(_In_ int type, _In_ int protocol);
	void	SockInfo();
	bool	SockSetInfo();
	bool	SockListen();

	bool	CreateSocketInformation(_In_ SOCKET socket);
	void	FreeSocketInformation(_In_ DWORD index);

	// LOOP
	bool	SockAccept();
	void	Sock_TCPecho();

	// Using Thread exit
	void	Thread_exit();

	bool	SetNon_block(_In_ SOCKET socket, _In_ ULONG mods);
	bool	SelectIO();

	// ssl function
	bool SSL_init();
	//void load_file(_Inout_ BIO* bio, _In_ char* filename);
	bool SSL_Setinfo(_Inout_ LPSOCKET_INFORMATION socket);
	bool SSL_server(_Inout_ LPSOCKET_INFORMATION socket);

	bool certInfo(_In_ SSL* ssl, _In_ int socket);
#define _server 1
#define _client 0
	bool Sock_SSLecho();


	bool SSL_client(_In_ const char* _host, _Inout_ LPSOCKET_INFORMATION Client);
#define sslPort 443
	SOCKADDR_IN	c_serverInfo;
	SOCKET c_hSocket;
	SSL_CTX* c_ctx;
	SSL* c_ssl;
};

#endif