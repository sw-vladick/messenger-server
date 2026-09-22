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


struct ipAttempts {
	int failedCount = 0;
	std::chrono::steady_clock::time_point lockTime;
};

using mapIp = std::unordered_map<std::string, ipAttempts>;

class DatabaseManager
{
public:
	DatabaseManager();
	bool Connect(const std::string& host, const std::string& user, const std::string& password, const std::string& database);
	~DatabaseManager();

	int RegisterUser(const std::string& username, const std::string& password, const std::string& ipAddress);
	int LoginUser(const std::string& username, const std::string& password, const std::string& ipAddress);

	bool StartAttempts(const std::string& ipAddress, std::mutex& mtx, mapIp& u_map);
	void EndAttempts(const std::string& ipAddress, std::mutex& mtx, mapIp& u_map,const int status);
private:
	sql::Connection* con;
	std::mutex dbMutex;
	std::string generateSalt(int length = 16);
	std::string hashPassword(const std::string& password, const std::string& salt);
	mapIp loginAttempts;
	mapIp registerAttempts;
	std::mutex attemptsLoginMutex;
	std::mutex attemptsRegMutex;
};

