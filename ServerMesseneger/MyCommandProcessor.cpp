#include "MyCommandProcessor.h"

MyCommandProcessor::MyCommandProcessor()
{
	if (cryptoManager.LoadPrivateKey("private_key.pem")) {
		std::cout << "[СЕРВЕР] RSA ключ завантажено успішно!" << std::endl;
	}
	else {
		std::cout << "[СЕРВЕР] ПОМИЛКА: Не вдалося завантажити RSA ключ!" << std::endl;
	}
	commands.emplace("LOGIN", [this](SOCKET currentSocket, const json& data) {
		HandleLogin(currentSocket, data);
		});
	commands.emplace("REGISTER", [this](SOCKET currentSocket, const json& data) {
		HandlRegistration(currentSocket, data);
		});
	commands.emplace("HANDSHAKE", [this](SOCKET currentSocket, const json& data) {
		HandleHandshake(currentSocket, data);
		});
	commands.emplace("SEARCH_USER", [this](SOCKET currentSocket, const json& data) {
		HandleSearchUser(currentSocket, data);
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
	if (clientAesKeys.find(currentSocket) == clientAesKeys.end()) { return; }

	std::string payload = data.value("payload", "");

	std::string decryptedPayload = cryptoManager.Base64Decode(payload);

	std::string strJson = cryptoManager.DecryptAES(decryptedPayload, clientAesKeys[currentSocket]);

	json encryptedJson = json::parse(strJson);

	std::string username = encryptedJson.value("Username", "");
	std::string password = encryptedJson.value("Password", "");

	json response;
	response["command"] = "LOGIN_RESPONSE";

	try {
		int loginResult = dbManager.LoginUser(username, password, GetIp(currentSocket));

		if (loginResult == 1) {
			response["status"] = "success";
			loggedInUsers[currentSocket] = username;
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

	std::string resultEnc = cryptoManager.EncryptAES(responseString, clientAesKeys[currentSocket]);
	std::string finaleEncJson = cryptoManager.Base64Encode(resultEnc);

	json finalResponse;

	finalResponse["command"] = "LOGIN_RESPONSE";
	finalResponse["payload"] = finaleEncJson;

	std::string finaleResponseStr = finalResponse.dump();
	int messageSize = finaleResponseStr.length();

	send(currentSocket, reinterpret_cast<const char*>(&messageSize), sizeof(int), 0);
	send(currentSocket, finaleResponseStr.c_str(), messageSize, 0);
}

void MyCommandProcessor::HandlRegistration(SOCKET currentSocket, const json& data)
{
	if (clientAesKeys.find(currentSocket) == clientAesKeys.end()) { return; }

	std::string payload = data.value("payload", "");

	std::string decryptedPayload = cryptoManager.Base64Decode(payload);

	std::string strJson = cryptoManager.DecryptAES(decryptedPayload, clientAesKeys[currentSocket]);

	json encryptedJson = json::parse(strJson);

	std::string username = encryptedJson.value("Username", "");
	std::string password = encryptedJson.value("Password", "");

	json response;
	response["command"] = "REGISTER_RESPONSE";

	try {
		int registerResult = dbManager.RegisterUser(username, password, GetIp(currentSocket));

		if (registerResult == 1) {
			response["status"] = "success";
			loggedInUsers[currentSocket] = username;
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

	std::string resultEnc = cryptoManager.EncryptAES(responseString, clientAesKeys[currentSocket]);
	std::string finaleEncJson = cryptoManager.Base64Encode(resultEnc);

	json finalResponse;

	finalResponse["command"] = "REGISTER_RESPONSE";
	finalResponse["payload"] = finaleEncJson;

	std::string finaleResponseStr = finalResponse.dump();
	int messageSize = finaleResponseStr.length();

	send(currentSocket, reinterpret_cast<const char*>(&messageSize), sizeof(int), 0);
	send(currentSocket, finaleResponseStr.c_str(), messageSize, 0);
}

void MyCommandProcessor::HandleHandshake(SOCKET currentSocket, const json& data)
{
	std::string key = data.value("key", "");

	json response;
	response["command"] = "HANDSHAKE_RESPONSE";

	std::string result_key = cryptoManager.DecryptRSA(key);
	if (result_key.empty()) {
		response["status"] = "error";
		std::cout << "[СЕРВЕР] Помилка розшифрування хендшейку!" << std::endl;
	}
	else {
		clientAesKeys[currentSocket] = result_key;
		response["status"] = "ready";
		std::cout << "[СЕРВЕР] Хендшейк успішний, AES ключ збережено!" << std::endl;
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

void MyCommandProcessor::HandleSearchUser(SOCKET currentSocket, const json& data)
{
	if (clientAesKeys.find(currentSocket) == clientAesKeys.end()) return;

	std::string payload = data.value("payload", "");
	std::string decryptedPayload = cryptoManager.Base64Decode(payload);
	std::string strJson = cryptoManager.DecryptAES(decryptedPayload, clientAesKeys[currentSocket]);

	try {
		json requestJson = json::parse(strJson);
		std::string targetQuery = requestJson.value("username", "");

		std::string currentUsername = loggedInUsers[currentSocket];

		std::vector<std::string> foundUsers = dbManager.SearchUsers(targetQuery);

		std::vector<std::string> filteredUsers;
		for (const std::string& u : foundUsers) {
			if (u != currentUsername) {
				filteredUsers.push_back(u);
			}
		}

		json responseInner;
		responseInner["query"] = targetQuery;
		responseInner["status"] = filteredUsers.empty() ? "not_found" : "found";

		responseInner["users"] = filteredUsers;

		std::string innerString = responseInner.dump();
		std::string encryptedInner = cryptoManager.EncryptAES(innerString, clientAesKeys[currentSocket]);
		std::string encodedPayload = cryptoManager.Base64Encode(encryptedInner);

		json finalResponse;
		finalResponse["Command"] = "SEARCH_RESPONSE";
		finalResponse["payload"] = encodedPayload;

		std::string responseStr = finalResponse.dump();
		int messageSize = responseStr.length();

		send(currentSocket, reinterpret_cast<const char*>(&messageSize), sizeof(int), 0);
		send(currentSocket, responseStr.c_str(), messageSize, 0);

		std::cout << "[СЕРВЕР] Пошук по запиту: " << targetQuery
			<< " | Знайдено: " << filteredUsers.size() << " користувачів." << std::endl;
	}
	catch (const json::exception& e) {
		std::cout << "[СЕРВЕР] JSON Помилка в SEARCH_USER: " << e.what() << std::endl;
		std::cout << "[СЕРВЕР] Рядок, який намагалися спарсити: " << strJson << std::endl;
	}
	catch (const std::exception& e) {
		std::cout << "[СЕРВЕР] Стандартна помилка в SEARCH_USER: " << e.what() << std::endl;
	}
	catch (...) {
		std::cout << "[СЕРВЕР] Невідома помилка обробки SEARCH_USER" << std::endl;
	}
}