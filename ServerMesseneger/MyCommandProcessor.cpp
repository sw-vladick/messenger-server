#include "MyCommandProcessor.h"

MyCommandProcessor::MyCommandProcessor()
{
	commands.emplace("LOGIN", [this](SOCKET currentSocket, const json& data) {
		HandleLogin(currentSocket, data);
		});
	commands.emplace("REGISTER", [this](SOCKET currentSocket, const json& data) {
		HandlRegistration(currentSocket, data);
		});

	std::ifstream configFile("config.json");
	if (!configFile.is_open()) {
		std::cout << "[КРИТИЧНА ПОМИЛКА] Не знайдено файл config.json!" << std::endl;
		return;
	}

	json config;
	configFile >> config;

	std::string host = config["host"];
	std::string user = config["user"];
	std::string password = config["password"];
	std::string database = config["database"];

	if (dbManager.Connect(host, user, password, database)) {
		std::cout << "[СЕРВЕР] Успішно підключено до БД через config.json!" << std::endl;
	}
	else {
		std::cout << "[СЕРВЕР] ПОМИЛКА підключення до БД!" << std::endl;
	}
}

void MyCommandProcessor::Execute(std::string command, SOCKET currentSocket, const json& data)
{
	if (commands.count(command)) {
		commands[command](currentSocket, data);
	}
	else {
		std::cout << "[СЕРВЕР] Невідома команда: " << command << std::endl;
	}
}

void MyCommandProcessor::HandleLogin(SOCKET currentSocket, const json& data)
{
	std::string username = data.value("Username", "");
	std::string password = data.value("Password", "");

	json response;
	response["command"] = "LOGIN_RESPONSE";

	try {
		int loginResult = dbManager.LoginUser(username, password, GetIp(currentSocket));

		if (loginResult == 1) {
			response["status"] = "success";
			std::cout << "[СЕРВЕР] Успішна авторизація: " << username << std::endl;
		}
		else if (loginResult == -1) {
			response["status"] = "locked";
			std::cout << "[СЕРВЕР] Блокування (перевищено ліміт): " << username << std::endl;
		}
		else {
			response["status"] = "error";
			std::cout << "[СЕРВЕР] Помилка авторизації (невірний пароль або логін): " << username << std::endl;
		}
	}
	catch (const std::exception& e) {
		std::cout << "!!! [КРАШ В БАЗІ ДАНИХ]: " << e.what() << std::endl;
		response["status"] = "error";
	}
	catch (...) {
		std::cout << "!!! [ТИХИЙ КРАШ В БАЗІ ДАНИХ] !!!" << std::endl;
		response["status"] = "error";
	}

	std::string responseString = response.dump();
	int messageSize = responseString.length();

	send(currentSocket, reinterpret_cast<const char*>(&messageSize), sizeof(int), 0);
	send(currentSocket, responseString.c_str(), messageSize, 0);
}

void MyCommandProcessor::HandlRegistration(SOCKET currentSocket, const json& data)
{
	std::string username = data.value("Username", "");
	std::string password = data.value("Password", "");

	json response;
	response["command"] = "REGISTER_RESPONSE";

	try {
		int registerResult = dbManager.RegisterUser(username, password, GetIp(currentSocket));

		if (registerResult == 1) {
			response["status"] = "success";
			std::cout << "[СЕРВЕР] Успішна реєстрація: " << username << std::endl;
		}
		else if (registerResult == -1) {
			response["status"] = "locked";
			std::cout << "[СЕРВЕР] Блокування (перевищено ліміт): " << username << std::endl;
		}
		else {
			response["status"] = "error";
			std::cout << "[СЕРВЕР] Помилка реєстрації (можливо, логін зайнятий): " << username << std::endl;
		}
	}
	catch (const std::exception& e) {
		std::cout << "!!! [КРАШ В БАЗІ ДАНИХ]: " << e.what() << std::endl;
		response["status"] = "error";
	}
	catch (...) {
		std::cout << "!!! [ТИХИЙ КРАШ В БАЗІ ДАНИХ] !!!" << std::endl;
		response["status"] = "error";
	}

	std::string responseString = response.dump();
	int messageSize = responseString.length();

	send(currentSocket, reinterpret_cast<const char*>(&messageSize), sizeof(int), 0);
	send(currentSocket, responseString.c_str(), messageSize, 0);
}

std::string MyCommandProcessor::GetIp(SOCKET currentSocket)
{
	sockaddr_in addr;
	int sizeAddr = sizeof(addr);

	getpeername(currentSocket, (sockaddr*)&addr, &sizeAddr);
	char ipStr[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, &addr.sin_addr, ipStr, INET_ADDRSTRLEN);

	std::string clientIP(ipStr);
	return clientIP;
}
