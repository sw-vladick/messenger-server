#include "WSAControl.h"

WSAControl::WSAControl() {
	if (WSAStartup(MAKEWORD(2, 2), &wsadata) != 0) {
		std::cerr << "error create WSAS!\n";
		std::exit(0);
	}
}

SOCKET WSAControl::CreateSocketTCP()
{
	return socket(AF_INET, SOCK_STREAM, 0);
}

WSAControl::~WSAControl()
{
	WSACleanup();
}

