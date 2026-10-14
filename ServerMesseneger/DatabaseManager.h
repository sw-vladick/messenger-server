#pragma once
#include <iostream>
#include <string>
#include <mysql_connection.h>
#include <cppconn/driver.h>
#include <cppconn/prepared_statement.h>
#include <cppconn/exception.h>
#include <mysql_driver.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <sstream>
#include <mutex>
#include <iomanip>
#include <unordered_map>
#include <chrono>
#include <vector>
#include "Models.h"


struct ipAttempts {
	int failedCount = 0;
	std::chrono::steady_clock::time_point lockTime;
};

using mapIp = std::unordered_map<std::string, ipAttempts>;

class DatabaseManager
{
public:
	DatabaseManager(const std::string& db_master_key);
	bool Connect(const std::string& host, const std::string& user, const std::string& password, const std::string& database);
	~DatabaseManager();

	int RegisterUser(const std::string& username, const std::string& password, const std::string& ipAddress);
	int LoginUser(const std::string& username, const std::string& password, const std::string& ipAddress);

	bool StartAttempts(const std::string& ipAddress, std::mutex& mtx, mapIp& u_map);
	void EndAttempts(const std::string& ipAddress, std::mutex& mtx, mapIp& u_map,const int status);

	bool UserExists(const std::string& username);
	std::vector<std::string> SearchUsers(const std::string& searchQuery);

	std::vector<ChatMessage> GetChatHistory(const std::string& user1, const std::string& user2);
	bool SaveMessage(const std::string& sender, const std::string& receiver, const std::string text);

	std::vector<std::string> GetRecentChats(const std::string& username);

	bool EditMessage(int messageId, const std::string& senderUsername, const std::string& newText);

	void MarkMessagesAsRead(const std::string& sender, const std::string& receiver);

	bool IsUserVerified(const std::string& username);
	void SetUserEmailVerified(const std::string& username, const std::string& email);
private:
	sql::Connection* con;
	std::mutex dbMutex;
	std::string generateSalt(int length = 16);
	std::string hashPassword(const std::string& password, const std::string& salt);
	mapIp loginAttempts;
	mapIp registerAttempts;
	std::mutex attemptsLoginMutex;
	std::mutex attemptsRegMutex;
	std::string masterKey;
};

