#pragma once
#include <winsock2.h>
#include <iostream>

class WSAControl
{
public:
	WSAControl();
	SOCKET CreateSocketTCP();
	~WSAControl();
private:
	WSADATA wsadata;
};

