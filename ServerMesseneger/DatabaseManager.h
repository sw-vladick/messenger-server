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
#include <iomanip>

class DatabaseManager
{
public:
	DatabaseManager();
	bool Connect(const std::string& host, const std::string& user, const std::string& password, const std::string& database);
	~DatabaseManager();

	bool RegisterUser(const std::string& username, const std::string& password);
	bool LoginUser(const std::string& username, const std::string& password);
private:
	sql::Connection* con;

	std::string generateSalt(int length = 16);
	std::string hashPassword(const std::string& password, const std::string& salt);
};

