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
		if (dbManager.LoginUser(username, password)) {
			response["status"] = "success";
			std::cout << "[СЕРВЕР] Успішна авторизація: " << username << std::endl;
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

	if (dbManager.RegisterUser(username, password)) {
		response["status"] = "success";
		std::cout << "[СЕРВЕР] Успішна реєстрація: " << username << std::endl;
	}
	else {
		response["status"] = "error";
		std::cout << "[СЕРВЕР] Помилка реєстрації (можливо, логін зайнятий): " << username << std::endl;
	}

	std::string responseString = response.dump();

	int messageSize = responseString.length();
	send(currentSocket, reinterpret_cast<const char*>(&messageSize), sizeof(int), 0);

	send(currentSocket, responseString.c_str(), messageSize, 0);
}
