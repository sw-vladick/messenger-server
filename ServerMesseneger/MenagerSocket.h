#pragma once
#include "WSAControl.h"
#include "Constant.h"
#include <string>
#include <thread>
#include <mutex>
#include "MyCommandProcessor.h"
#pragma comment(lib,"ws2_32.lib")

struct Client {
	SOCKET clientSocket;
	std::string nickname;
	Client();
	~Client();
	Client& operator=(Client&& other) noexcept;
	void DoEmptyClient();
};

class MenagerSocket
{
public:
	MenagerSocket(const std::string& db_master_key);
	void FromBindToListen();
	void AcceptClient();
	void HandleSocket(Client& currentClient, int index);
	~MenagerSocket();
private:
	SOCKET serverSocket;
	WSAControl wsadata;
	Client** clients;
	int currentCountClient;
	std::mutex acceptMTX;
	int maxClients;
	MyCommandProcessor RouteMap;
};

