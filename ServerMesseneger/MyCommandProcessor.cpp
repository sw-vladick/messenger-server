#include "MyCommandProcessor.h"

struct EmailData {
	std::string text;
	size_t bytes_read;
};

static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
	((std::string*)userp)->append((char*)contents, size * nmemb);
	return size * nmemb;
}

static size_t payload_source(char* ptr, size_t size, size_t nmemb, void* userp) {
	EmailData* emailData = (EmailData*)userp;
	size_t room = size * nmemb;

	if (room < 1 || emailData->bytes_read >= emailData->text.size()) {
		return 0;
	}

	size_t bytes_left = emailData->text.size() - emailData->bytes_read;
	size_t bytes_to_copy = (bytes_left < room) ? bytes_left : room;

	memcpy(ptr, emailData->text.data() + emailData->bytes_read, bytes_to_copy);
	emailData->bytes_read += bytes_to_copy;

	return bytes_to_copy;
}

MyCommandProcessor::MyCommandProcessor(const std::string& db_master_key) : masterKey(db_master_key), dbManager(db_master_key)
{
	if (cryptoManager.LoadPrivateKey("private_key.pem")) {
		std::cout << "[СЕРВЕР] RSA ключ завантажено успішно!" << std::endl;
	}
	else {
		std::cout << "[СЕРВЕР] ПОМИЛКА: Не вдалося завантажити RSA ключ!" << std::endl;
	}

	commands.emplace("LOGIN", [this](SOCKET currentSocket, const json& data) { HandleLogin(currentSocket, data); });
	commands.emplace("REGISTER", [this](SOCKET currentSocket, const json& data) { HandlRegistration(currentSocket, data); });
	commands.emplace("HANDSHAKE", [this](SOCKET currentSocket, const json& data) { HandleHandshake(currentSocket, data); });
	commands.emplace("SEARCH_USER", [this](SOCKET currentSocket, const json& data) { HandleSearchUser(currentSocket, data); });
	commands.emplace("GET_CHAT_HISTORY", [this](SOCKET currentSocket, const json& data) { HandleGetChatHistory(currentSocket, data); });
	commands.emplace("SEND_MESSAGE", [this](SOCKET currentSocket, const json& data) { HandleSendMessage(currentSocket, data); });
	commands.emplace("GET_RECENT_CHATS", [this](SOCKET currentSocket, const json& data) { HandleGetRecentChats(currentSocket, data); });
	commands.emplace("EDIT_MESSAGE", [this](SOCKET currentSocket, const json& data) { HandleEditMessage(currentSocket, data); });
	commands.emplace("LOGOUT", [this](SOCKET currentSocket, const json& data) { HandleLogout(currentSocket, data); });
	commands.emplace("FILE_START", [this](SOCKET currentSocket, const json& data) { HandleFileStart(currentSocket, data); });
	commands.emplace("FILE_CHUNK", [this](SOCKET currentSocket, const json& data) { HandleFileChunk(currentSocket, data); });
	commands.emplace("FILE_END", [this](SOCKET currentSocket, const json& data) { HandleFileEnd(currentSocket, data); });
	commands.emplace("DOWNLOAD_FILE", [this](SOCKET currentSocket, const json& data) { HandleDownloadFile(currentSocket, data); });
	commands.emplace("SEND_VERIFICATION_CODE", [this](SOCKET currentSocket, const json& data) { HandleSendVerificationCode(currentSocket, data); });
	commands.emplace("VERIFY_CODE", [this](SOCKET currentSocket, const json& data) { HandleVerifyCode(currentSocket, data); });
	commands.emplace("GOOGLE_LOGIN", [this](SOCKET currentSocket, const json& data) { HandleGoogleLogin(currentSocket, data); });

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
	senderEmail = config.value("email_sender", "");
	senderPassword = config.value("email_password", "");
	client_id = config.value("google_client_id", "");
	client_secret = config.value("google_client_secret", "");

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

bool MyCommandProcessor::DecryptRequest(SOCKET currentSocket, const json& data, json& outRequest)
{
	std::string aesKey;
	{
		std::lock_guard<std::mutex> lock(processorMutex);
		if (clientAesKeys.find(currentSocket) == clientAesKeys.end()) return false;
		aesKey = clientAesKeys[currentSocket];
	}

	std::string payload = data.value("payload", "");
	std::string decryptedPayload = cryptoManager.Base64Decode(payload);
	std::string strJson = cryptoManager.DecryptAES(decryptedPayload, aesKey);

	if (strJson.empty()) {
		std::cout << "[СЕРВЕР] Отримано битий пакет, ігноруємо." << std::endl;
		dbManager.LogActivity(GetIp(currentSocket), "MALFORMED_PAYLOAD", GetIp(currentSocket));
		return false;
	}

	try {
		outRequest = json::parse(strJson);
		return true;
	}
	catch (const std::exception& e) {
		std::cout << "[СЕРВЕР] Помилка парсингу JSON: " << e.what() << std::endl;
		return false;
	}
}

void MyCommandProcessor::SendEncryptedResponse(SOCKET currentSocket, const std::string& commandName, const json& innerPayload)
{
	std::string aesKey;
	{
		std::lock_guard<std::mutex> lock(processorMutex);
		if (clientAesKeys.find(currentSocket) == clientAesKeys.end()) return;
		aesKey = clientAesKeys[currentSocket];
	}

	std::string innerString = innerPayload.dump();
	std::string encryptedInner = cryptoManager.EncryptAES(innerString, aesKey);
	std::string encodedPayload = cryptoManager.Base64Encode(encryptedInner);

	json finalResponse;
	finalResponse["command"] = commandName;
	finalResponse["payload"] = encodedPayload;

	std::string responseStr = finalResponse.dump();
	int messageSize = responseStr.length();

	send(currentSocket, reinterpret_cast<const char*>(&messageSize), sizeof(int), 0);
	send(currentSocket, responseStr.c_str(), messageSize, 0);
}

void MyCommandProcessor::HandleLogin(SOCKET currentSocket, const json& data)
{
	json requestJson;
	if (!DecryptRequest(currentSocket, data, requestJson)) return;

	std::string username = requestJson.value("Username", "");
	std::string password = requestJson.value("Password", "");
	json response;

	try {
		int loginResult = dbManager.LoginUser(username, password, GetIp(currentSocket));

		if (loginResult == 1) {
			response["status"] = "success";
			{
				std::lock_guard<std::mutex> lock(processorMutex);
				loggedInUsers[currentSocket] = username;
			}
			response["is_verified"] = dbManager.IsUserVerified(username);
			std::cout << "[СЕРВЕР] Успішна авторизація: " << username << std::endl;
			dbManager.LogActivity(username, "LOGIN_SUCCESS", GetIp(currentSocket));
		}
		else if (loginResult == -1) {
			response["status"] = "locked";
			std::cout << "[СЕРВЕР] Блокування (перевищено ліміт): " << username << std::endl;
			dbManager.LogActivity(username, "LOGIN_LOCKED", GetIp(currentSocket));
		}
		else {
			response["status"] = "error";
			std::cout << "[СЕРВЕР] Помилка авторизації: " << username << std::endl;
			dbManager.LogActivity(username, "LOGIN_FAILED", GetIp(currentSocket));
		}
	}
	catch (const std::exception& e) {
		std::cout << "!!! [КРАШ В БД]: " << e.what() << std::endl;
		response["status"] = "error";
	}

	SendEncryptedResponse(currentSocket, "LOGIN_RESPONSE", response);
}

void MyCommandProcessor::HandlRegistration(SOCKET currentSocket, const json& data)
{
	json requestJson;
	if (!DecryptRequest(currentSocket, data, requestJson)) return;

	std::string username = requestJson.value("Username", "");
	std::string password = requestJson.value("Password", "");
	json response;

	try {
		int registerResult = dbManager.RegisterUser(username, password, GetIp(currentSocket));

		if (registerResult == 1) {
			response["status"] = "success";
			{
				std::lock_guard<std::mutex> lock(processorMutex);
				loggedInUsers[currentSocket] = username;
			}
			response["is_verified"] = false;
			std::cout << "[СЕРВЕР] Успішна реєстрація: " << username << std::endl;
			dbManager.LogActivity(username, "REGISTER_SUCCESS", GetIp(currentSocket));
		}
		else if (registerResult == -1) {
			response["status"] = "locked";
			std::cout << "[СЕРВЕР] Блокування (перевищено ліміт): " << username << std::endl;
			dbManager.LogActivity(username, "REGISTER_LOCKED", GetIp(currentSocket));
		}
		else {
			response["status"] = "error";
			std::cout << "[СЕРВЕР] Помилка реєстрації (логін зайнятий): " << username << std::endl;
			dbManager.LogActivity(username, "REGISTER_FAILED", GetIp(currentSocket));
		}
	}
	catch (const std::exception& e) {
		std::cout << "!!! [КРАШ В БД]: " << e.what() << std::endl;
		response["status"] = "error";
	}

	SendEncryptedResponse(currentSocket, "REGISTER_RESPONSE", response);
}

void MyCommandProcessor::HandleHandshake(SOCKET currentSocket, const json& data)
{
	std::string key = data.value("key", "");
	json response;

	std::string result_key = cryptoManager.DecryptRSA(key);
	if (result_key.empty()) {
		response["status"] = "error";
		std::cout << "[СЕРВЕР] Помилка розшифрування хендшейку!" << std::endl;
	}
	else {
    {
        std::lock_guard<std::mutex> lock(processorMutex);
        clientAesKeys[currentSocket] = result_key;
    }
		response["status"] = "ready";
		std::cout << "[СЕРВЕР] Хендшейк успішний, AES ключ збережено!" << std::endl;
	}

	json finalResponse;
	finalResponse["command"] = "HANDSHAKE_RESPONSE";

	for (auto& el : response.items()) {
		finalResponse[el.key()] = el.value();
	}

	std::string responseString = finalResponse.dump();
	int messageSize = responseString.length();

	send(currentSocket, reinterpret_cast<const char*>(&messageSize), sizeof(int), 0);
	send(currentSocket, responseString.c_str(), messageSize, 0);
}

void MyCommandProcessor::HandleGetChatHistory(SOCKET currentSocket, const json& data)
{
	json requestJson;
	if (!DecryptRequest(currentSocket, data, requestJson)) return;

	try {
		std::string targetUser = requestJson.value("target_user", "");
		std::string currentUser;
		if (!GetLoggedUser(currentSocket, currentUser)) return;

		dbManager.MarkMessagesAsRead(targetUser, currentUser);
		std::vector<ChatMessage> messages = dbManager.GetChatHistory(currentUser, targetUser);

		json response;
		json messagesArray = json::array();
		response["target_user"] = targetUser;
		response["status"] = "success";

		for (const ChatMessage& msg : messages) {
			std::string rawEncrypted = cryptoManager.Base64Decode(msg.text);
			std::string decryptedText = cryptoManager.DecryptAES(rawEncrypted, masterKey);

			messagesArray.push_back({
				{"id", msg.id},
				{"sender", msg.sender},
				{"text", decryptedText},
				{"timestamp", msg.timestamp},
				{"is_edited", msg.is_edited},
				{"is_read", msg.is_read}
				});
		}
		response["messages"] = messagesArray;
		SendEncryptedResponse(currentSocket, "CHAT_HISTORY_RESPONSE", response);
	}
	catch (const std::exception& e) {
		std::cout << "[СЕРВЕР] Помилка в GET_CHAT_HISTORY: " << e.what() << std::endl;
	}
}

void MyCommandProcessor::HandleSendMessage(SOCKET currentSocket, const json& data)
{
	json requestJson;
	if (!DecryptRequest(currentSocket, data, requestJson)) return;

	try {
		std::string targetUser = requestJson.value("target_user", "");
		std::string currentUser;
		if (!GetLoggedUser(currentSocket, currentUser)) return;
		std::string text = requestJson.value("text", "");

		std::string encryptedTextForDB = cryptoManager.EncryptAES(text, masterKey);
		std::string base64ForDB = cryptoManager.Base64Encode(encryptedTextForDB);

		if (dbManager.SaveMessage(currentUser, targetUser, base64ForDB)) {
			json response;
			response["status"] = "success";

			SendEncryptedResponse(currentSocket, "UPDATE_CHAT", response);

			SOCKET targetSocket = INVALID_SOCKET;
			{
				std::lock_guard<std::mutex> lock(processorMutex);
				for (const auto& a : loggedInUsers) {
					if (a.second == targetUser) {
						targetSocket = a.first;
						break;
					}
				}
			}
			if (targetSocket != INVALID_SOCKET) {
				SendEncryptedResponse(targetSocket, "UPDATE_CHAT", response);
			}
		}
	}
	catch (const std::exception& e) {
		std::cout << "[СЕРВЕР] Помилка в SEND_MESSAGE: " << e.what() << std::endl;
	}
}

void MyCommandProcessor::HandleGetRecentChats(SOCKET currentSocket, const json& data)
{
	if (clientAesKeys.find(currentSocket) == clientAesKeys.end()) return;

	try {
		std::string currentUser;
		if (!GetLoggedUser(currentSocket, currentUser)) return;
		std::vector<std::string> chats = dbManager.GetRecentChats(currentUser);

		json response;
		json usersArray = json::array();
		for (const auto& a : chats) {
			usersArray.push_back(a);
		}
		response["users"] = usersArray;

		SendEncryptedResponse(currentSocket, "RECENT_CHATS_RESPONSE", response);
	}
	catch (const std::exception& e) {
		std::cout << "[СЕРВЕР] Помилка в GET_RECENT_CHATS: " << e.what() << std::endl;
	}
}

void MyCommandProcessor::HandleEditMessage(SOCKET currentSocket, const json& data)
{
	json requestJson;
	if (!DecryptRequest(currentSocket, data, requestJson)) return;

	try {
		int messageId = requestJson.value("message_id", -1);
		std::string targetUser = requestJson.value("target_user", "");
		std::string currentUser;
		if (!GetLoggedUser(currentSocket, currentUser)) return;
		std::string text = requestJson.value("text", "");

		if (messageId == -1 || text.empty()) return;

		std::string encryptedTextForDB = cryptoManager.EncryptAES(text, masterKey);
		std::string base64ForDB = cryptoManager.Base64Encode(encryptedTextForDB);

		if (dbManager.EditMessage(messageId, currentUser, base64ForDB)) {
			json response;
			response["status"] = "success";

			SendEncryptedResponse(currentSocket, "UPDATE_CHAT", response);

			SOCKET targetSocket = INVALID_SOCKET;
			{
				std::lock_guard<std::mutex> lock(processorMutex);
				for (const auto& a : loggedInUsers) {
					if (a.second == targetUser) {
						targetSocket = a.first;
						break;
					}
				}
			}
			if (targetSocket != INVALID_SOCKET) {
				SendEncryptedResponse(targetSocket, "UPDATE_CHAT", response);
			}
		}
	}
	catch (const std::exception& e) {
		std::cout << "[СЕРВЕР] Помилка в EDIT_MESSAGE: " << e.what() << std::endl;
	}
}

void MyCommandProcessor::HandleFileStart(SOCKET currentSocket, const json& data)
{
	json requestJson;
	if (!DecryptRequest(currentSocket, data, requestJson)) return;

	std::string currentUser;
	if (!GetLoggedUser(currentSocket, currentUser)) return;

	try {
		std::string transferId = requestJson.value("transfer_id", "");
		std::string targetUser = requestJson.value("target_user", "");
		std::string rawFileName = requestJson.value("file_name", "");

		std::string safeFileName = std::filesystem::path(rawFileName).filename().string();
		if (safeFileName.empty() || transferId.empty()) return;

		FileTransferSession currentSession;
		currentSession.fileName = safeFileName;
		currentSession.targetUser = targetUser;

		std::lock_guard<std::mutex> lock(processorMutex);
		memoryForFile[transferId] = currentSession;
	}
	catch (const std::exception& e) {
		std::cout << "[СЕРВЕР] Помилка в FileStart: " << e.what() << std::endl;
	}
}

void MyCommandProcessor::HandleFileChunk(SOCKET currentSocket, const json& data)
{
	json requestJson;
	if (!DecryptRequest(currentSocket, data, requestJson)) return;

	try {
		std::string transferId = requestJson.value("transfer_id", "");
		std::string dataFile = requestJson.value("data", "");
		std::string decodeDataFile = cryptoManager.Base64Decode(dataFile);

		std::lock_guard<std::mutex> lock(processorMutex);
		auto it = memoryForFile.find(transferId);
		if (it == memoryForFile.end()) return;

		const size_t MAX_FILE_SIZE = 50 * 1024 * 1024;
		if (it->second.buffer.size() + decodeDataFile.size() > MAX_FILE_SIZE) {
			std::cout << "[СЕРВЕР] Перевищено ліміт розміру файлу (50 МБ)! Сесію скасовано." << std::endl;
			memoryForFile.erase(it);
			return;
		}

		it->second.buffer.insert(it->second.buffer.end(), decodeDataFile.begin(), decodeDataFile.end());
	}
	catch (const std::exception& e) {
		std::cout << "[СЕРВЕР] Помилка в FileChunk: " << e.what() << std::endl;
	}
}

void MyCommandProcessor::HandleFileEnd(SOCKET currentSocket, const json& data)
{
	json requestJson;
	if (!DecryptRequest(currentSocket, data, requestJson)) return;

	std::string currentUser;
	if (!GetLoggedUser(currentSocket, currentUser)) return;

	try {
		std::string transferId = requestJson.value("transfer_id", "");
		std::string targetUser = requestJson.value("target_user", "");

		FileTransferSession session;
		{
			std::lock_guard<std::mutex> lock(processorMutex);
			auto it = memoryForFile.find(transferId);
			if (it == memoryForFile.end()) return;
			session = std::move(it->second);
			memoryForFile.erase(it);
		}

		std::filesystem::create_directories("uploads");
		std::string safePath = "uploads/" + session.fileName;

		std::ofstream fout(safePath, std::ios::binary);
		if (fout.is_open()) {
			fout.write(reinterpret_cast<const char*>(session.buffer.data()), session.buffer.size());
			fout.close();
			std::cout << "[СЕРВЕР] Файл успішно збережено: " << safePath << std::endl;

			std::string fileMessageText = "[FILE] " + session.fileName;
			std::string encryptedTextForDB = cryptoManager.EncryptAES(fileMessageText, masterKey);
			std::string base64ForDB = cryptoManager.Base64Encode(encryptedTextForDB);

			if (dbManager.SaveMessage(currentUser, targetUser, base64ForDB)) {
				json response;
				response["status"] = "success";

				SendEncryptedResponse(currentSocket, "UPDATE_CHAT", response);

				SOCKET targetSocket = INVALID_SOCKET;
				{
					std::lock_guard<std::mutex> lock(processorMutex);
					for (const auto& a : loggedInUsers) {
						if (a.second == targetUser) {
							targetSocket = a.first;
							break;
						}
					}
				}
				if (targetSocket != INVALID_SOCKET) {
					SendEncryptedResponse(targetSocket, "UPDATE_CHAT", response);
				}
			}
		}
		else {
			std::cout << "[СЕРВЕР] ПОМИЛКА: Не вдалося створити файл " << safePath << std::endl;
		}
	}
	catch (const std::exception& e) {
		std::cout << "[СЕРВЕР] Помилка в FileEnd: " << e.what() << std::endl;
	}
}

void MyCommandProcessor::HandleDownloadFile(SOCKET currentSocket, const json& data)
{
	json requestJson;
	if (!DecryptRequest(currentSocket, data, requestJson)) return;

	std::string currentUser;
	if (!GetLoggedUser(currentSocket, currentUser)) return;

	try {
		std::string rawFileName = requestJson.value("file_name", "");
		std::string safeFileName = std::filesystem::path(rawFileName).filename().string();
		if (safeFileName.empty()) return;

		std::string safePath = "uploads/" + safeFileName;
		std::ifstream file(safePath, std::ios::binary);

		if (file.is_open()) {
			file.seekg(0, std::ios::end);
			int fileSize = static_cast<int>(file.tellg());
			file.seekg(0, std::ios::beg);

			unsigned int randomId = 0;
			RAND_bytes(reinterpret_cast<unsigned char*>(&randomId), sizeof(randomId));
			std::string transferId = std::to_string(randomId) + "_" + safeFileName;

			json responseStart;
			responseStart["transfer_id"] = transferId;
			responseStart["file_name"] = safeFileName;
			responseStart["file_size"] = fileSize;
			SendEncryptedResponse(currentSocket, "FILE_RECEIVE_START", responseStart);

			std::vector<unsigned char> buffer(16 * 1024);
			int chunkIndex = 0;

			while (!file.eof()) {
				file.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
				int bytesRead = static_cast<int>(file.gcount());
				if (bytesRead == 0) break;

				std::string rawData(reinterpret_cast<char*>(buffer.data()), bytesRead);
				std::string temporaryStr = cryptoManager.Base64Encode(rawData);

				json responseChunk;
				responseChunk["transfer_id"] = transferId;
				responseChunk["chunk_index"] = chunkIndex;
				responseChunk["data"] = temporaryStr;
				SendEncryptedResponse(currentSocket, "FILE_RECEIVE_CHUNK", responseChunk);

				chunkIndex++;
			}
			file.close();

			json responseEnd;
			responseEnd["transfer_id"] = transferId;
			SendEncryptedResponse(currentSocket, "FILE_RECEIVE_END", responseEnd);

			std::cout << "[СЕРВЕР] Відправлено файл: " << safeFileName << " (" << chunkIndex << " шматків)" << std::endl;
		}
		else {
			std::cout << "[СЕРВЕР] Помилка: не знайдено файл " << safePath << std::endl;
		}
	}
	catch (const std::exception& e) {
		std::cout << "[СЕРВЕР] Помилка в DownloadFile: " << e.what() << std::endl;
	}
}

void MyCommandProcessor::HandleSearchUser(SOCKET currentSocket, const json& data)
{
	json requestJson;
	if (!DecryptRequest(currentSocket, data, requestJson)) return;

	try {
		std::string targetQuery = requestJson.value("username", "");
		std::string currentUser;
		if (!GetLoggedUser(currentSocket, currentUser)) return;

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

		SendEncryptedResponse(currentSocket, "SEARCH_RESPONSE", responseInner);
	}
	catch (const std::exception& e) {
		std::cout << "[СЕРВЕР] Стандартна помилка в SEARCH_USER: " << e.what() << std::endl;
	}
}

void MyCommandProcessor::HandleLogout(SOCKET currentSocket, const json& data)
{
	std::string user;
	{
		std::lock_guard<std::mutex> lock(processorMutex);
		if (loggedInUsers.find(currentSocket) != loggedInUsers.end()) {
			user = loggedInUsers[currentSocket];
			loggedInUsers.erase(currentSocket);
		}
	}
	if (!user.empty()) {
		std::cout << "[СЕРВЕР] Користувач " << user << " безпечно вийшов з акаунту." << std::endl;
		dbManager.LogActivity(user, "LOGOUT", GetIp(currentSocket));
	}
}

std::string MyCommandProcessor::GetIp(SOCKET currentSocket)
{
	sockaddr_in addr;
	int sizeAddr = sizeof(addr);

	getpeername(currentSocket, (sockaddr*)&addr, &sizeAddr);
	char ipStr[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, &addr.sin_addr, ipStr, INET_ADDRSTRLEN);

	return std::string(ipStr);
}

void MyCommandProcessor::RemoveClient(SOCKET currentSocket)
{
	std::string user;
	{
		std::lock_guard<std::mutex> lock(processorMutex);
		if (loggedInUsers.find(currentSocket) != loggedInUsers.end()) {
			user = loggedInUsers[currentSocket];
		}
		loggedInUsers.erase(currentSocket);
		clientAesKeys.erase(currentSocket);
	}
	if (!user.empty()) {
		dbManager.LogActivity(user, "DISCONNECTED", GetIp(currentSocket));
	}
	std::cout << "[СЕРВЕР] Дані сокета очищено з пам'яті." << std::endl;
}


bool MyCommandProcessor::SendEmail(const std::string& toAddress, const std::string& verificationCode)
{
	CURL* curl;
	CURLcode res = CURLE_OK;

	curl = curl_easy_init();
	if (!curl) return false;

	std::string emailPayload =
		"To: " + toAddress + "\r\n"
		"From: Messenger Security <" + senderEmail + ">\r\n"
		"Subject: Verification Code for Messenger\r\n"
		"\r\n"
		"Your verification code is: " + verificationCode + "\r\n"
		"This code is valid for 5 minutes.\r\n";

	EmailData emailData;
	emailData.text = emailPayload;
	emailData.bytes_read = 0;

	curl_easy_setopt(curl, CURLOPT_URL, "smtps://smtp.gmail.com:465");
	curl_easy_setopt(curl, CURLOPT_USERNAME, senderEmail.c_str());
	curl_easy_setopt(curl, CURLOPT_PASSWORD, senderPassword.c_str());
	curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);

	curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
	curl_easy_setopt(curl, CURLOPT_READFUNCTION, payload_source);
	curl_easy_setopt(curl, CURLOPT_READDATA, &emailData);

	curl_easy_setopt(curl, CURLOPT_MAIL_FROM, senderEmail.c_str());

	struct curl_slist* recipients = NULL;
	recipients = curl_slist_append(recipients, toAddress.c_str());
	curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);

	res = curl_easy_perform(curl);

	curl_slist_free_all(recipients);
	curl_easy_cleanup(curl);

	if (res != CURLE_OK) {
		std::cout << "[СЕРВЕР] Помилка відправки листа: " << curl_easy_strerror(res) << std::endl;
		return false;
	}

	std::cout << "[СЕРВЕР] Лист успішно відправлено на " << toAddress << std::endl;
	return true;
}

void MyCommandProcessor::HandleSendVerificationCode(SOCKET currentSocket, const json& data)
{
	json requestJson;
	if (!DecryptRequest(currentSocket, data, requestJson)) return;

	try
	{
		std::unique_lock<std::mutex> lock(processorMutex);
		std::string email = requestJson.value("email", "");

		if (emailLockouts.find(email) != emailLockouts.end()) {
			if (std::chrono::steady_clock::now() < emailLockouts[email]) {
				json responseInner;
				responseInner["status"] = "locked";
				SendEncryptedResponse(currentSocket, "SEND_VERIFICATION_CODE_RESPONSE", responseInner);
				dbManager.LogActivity(email, "SEND_CODE_LOCKED", GetIp(currentSocket));
				return;
			}
			else {
				emailLockouts.erase(email);
			}
		}

		unsigned char randomBytes[4];
		if (RAND_bytes(randomBytes, sizeof(randomBytes)) != 1) {
			std::cout << "[СЕРВЕР] ПОМИЛКА генерації випадкового коду!" << std::endl;
			return;
		}

		unsigned int randomNum = 0;
		if (RAND_bytes(reinterpret_cast<unsigned char*>(&randomNum), sizeof(randomNum)) != 1) {
			std::cout << "[СЕРВЕР] ПОМИЛКА генерації випадкового коду!" << std::endl;
			return;
		}
		int secureCode = 100000 + (randomNum % 900000);
		std::string code = std::to_string(secureCode);

		EmailVerificationSession session;
		session.code = code;
		session.expiresAt = std::chrono::steady_clock::now() + std::chrono::minutes(5);
		verificationCodes[email] = session;
		lock.unlock();

		json responseInner;

		if (SendEmail(email, code)) {
			responseInner["status"] = "success";
			dbManager.LogActivity(email, "SEND_CODE_SUCCESS", GetIp(currentSocket));
		}
		else {
			responseInner["status"] = "error";
			dbManager.LogActivity(email, "SEND_CODE_FAILED", GetIp(currentSocket));
		}
		SendEncryptedResponse(currentSocket, "SEND_VERIFICATION_CODE_RESPONSE", responseInner);

	}
	catch (const std::exception& e) {
		std::cout << "[СЕРВЕР] Стандартна помилка в SendVerificationCode: " << e.what() << std::endl;
	}
}

void MyCommandProcessor::HandleVerifyCode(SOCKET currentSocket, const json& data)
{
	json requestJson;
	if (!DecryptRequest(currentSocket, data, requestJson)) return;

	try
	{
		std::lock_guard<std::mutex> lock(processorMutex);
		std::string email = requestJson.value("email", "");
		std::string code = requestJson.value("code", "");
		json responseInner;

		if (emailLockouts.find(email) != emailLockouts.end()) {
			if (std::chrono::steady_clock::now() < emailLockouts[email]) {
				responseInner["status"] = "locked";
				SendEncryptedResponse(currentSocket, "VERIFY_CODE_RESPONSE", responseInner);
				return;
			}
			else {
				emailLockouts.erase(email);
			}
		}

		if (verificationCodes.find(email) == verificationCodes.end()) {
			responseInner["status"] = "error";
			SendEncryptedResponse(currentSocket, "VERIFY_CODE_RESPONSE", responseInner);
			dbManager.LogActivity(email, "VERIFY_CODE_NOT_FOUND", GetIp(currentSocket));
			return;
		}

		if (std::chrono::steady_clock::now() > verificationCodes[email].expiresAt) {
			verificationCodes.erase(email);
			responseInner["status"] = "error";
			SendEncryptedResponse(currentSocket, "VERIFY_CODE_RESPONSE", responseInner);
			dbManager.LogActivity(email, "VERIFY_CODE_EXPIRED", GetIp(currentSocket));
			return;
		}

		if (verificationCodes[email].code == code) {
			std::string currentUser = loggedInUsers[currentSocket];
			dbManager.SetUserEmailVerified(currentUser, email);

			verificationCodes.erase(email);
			responseInner["status"] = "success";
			SendEncryptedResponse(currentSocket, "VERIFY_CODE_RESPONSE", responseInner);

			dbManager.LogActivity(currentUser, "EMAIL_VERIFIED", GetIp(currentSocket));
		}
		else {
			verificationCodes[email].failedAttempts++;

			if (verificationCodes[email].failedAttempts >= 5) {
				emailLockouts[email] = std::chrono::steady_clock::now() + std::chrono::minutes(5);
				verificationCodes.erase(email);
				responseInner["status"] = "locked";
				dbManager.LogActivity(email, "EMAIL_VERIFY_LOCKED", GetIp(currentSocket));
			}
			else {
				responseInner["status"] = "error";
				dbManager.LogActivity(email, "EMAIL_VERIFY_FAILED", GetIp(currentSocket));
			}

			SendEncryptedResponse(currentSocket, "VERIFY_CODE_RESPONSE", responseInner);
		}
	}
	catch (const std::exception& e) {
		std::cout << "[СЕРВЕР] Стандартна помилка в VERIFY_CODE_RESPONSE: " << e.what() << std::endl;
	}
}

void MyCommandProcessor::HandleGoogleLogin(SOCKET currentSocket, const json& data)
{
	json requestJson;
	if (!DecryptRequest(currentSocket, data, requestJson)) return;

	try
	{
		std::string code = requestJson.value("code", "");

		std::string token = ExchangeGoogleCodeForToken(code);

		json responseInner;
		if (token.empty()) {
			responseInner["status"] = "error";
			SendEncryptedResponse(currentSocket, "GOOGLE_LOGIN_RESPONSE", responseInner);
			dbManager.LogActivity("Unknown", "GOOGLE_TOKEN_ERROR", GetIp(currentSocket));
			return;
		}

		json userInfo = GetGoogleUserInfo(token);

		std::string email = userInfo.value("email", "");
		std::string id = userInfo.value("id", "");
		std::string username;

		if (email.empty() || id.empty()) {
			responseInner["status"] = "error";
			SendEncryptedResponse(currentSocket, "GOOGLE_LOGIN_RESPONSE", responseInner);
			dbManager.LogActivity("Unknown", "GOOGLE_DATA_MISSING", GetIp(currentSocket));
			return;
		}

		if (dbManager.LoginOrRegisterGoogleUser(email, id, username)) {
			{
				std::lock_guard<std::mutex> lock(processorMutex);
				loggedInUsers[currentSocket] = username;
			}

			responseInner["status"] = "success";
			SendEncryptedResponse(currentSocket, "GOOGLE_LOGIN_RESPONSE", responseInner);
			dbManager.LogActivity(username, "GOOGLE_LOGIN_SUCCESS", GetIp(currentSocket));
		}
		else {
			responseInner["status"] = "error";
			SendEncryptedResponse(currentSocket, "GOOGLE_LOGIN_RESPONSE", responseInner);
			dbManager.LogActivity(email, "GOOGLE_LOGIN_FAILED", GetIp(currentSocket));
		}
	}
	catch (const std::exception& e) {
		std::cout << "[СЕРВЕР] Стандартна помилка в HandleGoogleLogin: " << e.what() << std::endl;
	}
}

bool MyCommandProcessor::GetLoggedUser(SOCKET currentSocket, std::string& outUsername)
{
	std::lock_guard<std::mutex> lock(processorMutex);
	auto it = loggedInUsers.find(currentSocket);
	if (it == loggedInUsers.end() || it->second.empty()) {
		return false;
	}
	outUsername = it->second;
	return true;
}

std::string MyCommandProcessor::ExchangeGoogleCodeForToken(const std::string& code) {
	CURL* curl = curl_easy_init();
	if (!curl) return "";

	std::string response_string;

	std::string post_fields = "code=" + code +
		"&client_id=" + client_id +
		"&client_secret=" + client_secret +
		"&redirect_uri=http://127.0.0.1" +
		"&grant_type=authorization_code";

	curl_easy_setopt(curl, CURLOPT_URL, "https://oauth2.googleapis.com/token");
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_fields.c_str());
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_string);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);

	CURLcode res = curl_easy_perform(curl);
	curl_easy_cleanup(curl);

	if (res != CURLE_OK) {
		std::cout << "[OAUTH] Помилка запиту токена: " << curl_easy_strerror(res) << std::endl;
		return "";
	}

	try {
		json jsonResponse = json::parse(response_string);
		return jsonResponse.value("access_token", "");
	}
	catch (...) {
		return "";
	}
}

json MyCommandProcessor::GetGoogleUserInfo(const std::string& accessToken) {
	CURL* curl = curl_easy_init();
	if (!curl) return json();

	std::string response_string;
	struct curl_slist* headers = NULL;
	headers = curl_slist_append(headers, ("Authorization: Bearer " + accessToken).c_str());

	curl_easy_setopt(curl, CURLOPT_URL, "https://www.googleapis.com/oauth2/v2/userinfo");
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_string);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);

	CURLcode res = curl_easy_perform(curl);
	curl_slist_free_all(headers);
	curl_easy_cleanup(curl);

	if (res != CURLE_OK) return json();

	try {
		return json::parse(response_string);
	}
	catch (...) {
		return json();
	}
}