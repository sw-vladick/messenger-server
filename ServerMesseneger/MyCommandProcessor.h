#pragma once
#include <unordered_map>
#include <functional>
#include <string>
#include <WinSock2.h>
#include <iostream>
#include "json.hpp"
#include <fstream>
#include <WS2tcpip.h>
#include "DatabaseManager.h"

using json = nlohmann::json;

class MyCommandProcessor
{
public:
	MyCommandProcessor();
	void Execute(std::string command, SOCKET currentSocket, const json& data);
	void HandleLogin(SOCKET currentSocket, const json& data);
	void HandlRegistration(SOCKET currentSocket, const json& data);
	
private:
	std::string GetIp(SOCKET currentSocket);
	std::unordered_map<std::string, std::function<void(SOCKET, const json&)>> commands;
	DatabaseManager dbManager;
};

