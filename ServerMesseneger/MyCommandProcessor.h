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
#include "CryptoManager.h"

using json = nlohmann::json;

class MyCommandProcessor
{
public:
	MyCommandProcessor(const std::string& db_master_key);
	void Execute(std::string command, SOCKET currentSocket, const json& data);
	void HandleLogin(SOCKET currentSocket, const json& data);
	void HandlRegistration(SOCKET currentSocket, const json& data);
	void HandleHandshake(SOCKET currentSocket, const json& data);
	void HandleGetChatHistory(SOCKET currentSocket, const json& data);
	void HandleSendMessage(SOCKET currentSocket, const json& data);
	void HandleGetRecentChats(SOCKET currentSocket, const json& data);
	void HandleEditMessage(SOCKET currentSocket, const json& data);
	void HandleFileStart(SOCKET currentSocket, const json& data);
	void HandleFileChunk(SOCKET currentSocket, const json& data);
	void HandleFileEnd(SOCKET currentSocket, const json& data);
	void HandleLogout(SOCKET currentSocket, const json& data);
	void HandleDownloadFile(SOCKET currentSocket, const json& data);
	bool DecryptRequest(SOCKET currentSocket, const json& data, json& outRequest);
	void SendEncryptedResponse(SOCKET currentSocket, const std::string& commandName, const json& innerPayload);
	void RemoveClient(SOCKET currentSocket);
private:
	std::string GetIp(SOCKET currentSocket);
	std::unordered_map<std::string, std::function<void(SOCKET, const json&)>> commands;
	std::unordered_map<SOCKET, std::string> clientAesKeys;
	std::unordered_map<SOCKET, std::string> loggedInUsers;
	DatabaseManager dbManager;
	CryptoManager cryptoManager;
	void HandleSearchUser(SOCKET currentSocket, const json& data);
	std::string masterKey;
	struct FileTransferSession {
		std::string fileName;
		std::string targetUser;
		std::vector<unsigned char> buffer;
	};
	std::unordered_map<std::string, FileTransferSession> memoryForFile;
};

