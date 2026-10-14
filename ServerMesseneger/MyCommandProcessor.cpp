#include "MyCommandProcessor.h"

struct EmailData {
	std::string text;
	size_t bytes_read;
};

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
	if (clientAesKeys.find(currentSocket) == clientAesKeys.end()) return false;

	std::string payload = data.value("payload", "");
	std::string decryptedPayload = cryptoManager.Base64Decode(payload);
	std::string strJson = cryptoManager.DecryptAES(decryptedPayload, clientAesKeys[currentSocket]);

	if (strJson.empty()) {
		std::cout << "[СЕРВЕР] Отримано битий пакет, ігноруємо." << std::endl;
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
	if (clientAesKeys.find(currentSocket) == clientAesKeys.end()) return;

	std::string innerString = innerPayload.dump();
	std::string encryptedInner = cryptoManager.EncryptAES(innerString, clientAesKeys[currentSocket]);
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
			loggedInUsers[currentSocket] = username;
			response["is_verified"] = dbManager.IsUserVerified(username);
			std::cout << "[СЕРВЕР] Успішна авторизація: " << username << std::endl;
		}
		else if (loginResult == -1) {
			response["status"] = "locked";
			std::cout << "[СЕРВЕР] Блокування (перевищено ліміт): " << username << std::endl;
		}
		else {
			response["status"] = "error";
			std::cout << "[СЕРВЕР] Помилка авторизації: " << username << std::endl;
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
			loggedInUsers[currentSocket] = username;
			response["is_verified"] = false;
			std::cout << "[СЕРВЕР] Успішна реєстрація: " << username << std::endl;
		}
		else if (registerResult == -1) {
			response["status"] = "locked";
			std::cout << "[СЕРВЕР] Блокування (перевищено ліміт): " << username << std::endl;
		}
		else {
			response["status"] = "error";
			std::cout << "[СЕРВЕР] Помилка реєстрації (логін зайнятий): " << username << std::endl;
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
		clientAesKeys[currentSocket] = result_key;
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
		std::string currentUser = loggedInUsers[currentSocket];

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
		std::string currentUser = loggedInUsers[currentSocket];
		std::string text = requestJson.value("text", "");

		std::string encryptedTextForDB = cryptoManager.EncryptAES(text, masterKey);
		std::string base64ForDB = cryptoManager.Base64Encode(encryptedTextForDB);

		if (dbManager.SaveMessage(currentUser, targetUser, base64ForDB)) {
			json response;
			response["status"] = "success";

			SendEncryptedResponse(currentSocket, "UPDATE_CHAT", response);

			for (const auto& a : loggedInUsers) {
				if (a.second == targetUser) {
					SendEncryptedResponse(a.first, "UPDATE_CHAT", response);
					break;
				}
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
		std::string currentUser = loggedInUsers[currentSocket];
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
		std::string currentUser = loggedInUsers[currentSocket];
		std::string text = requestJson.value("text", "");

		if (messageId == -1 || text.empty()) return;

		std::string encryptedTextForDB = cryptoManager.EncryptAES(text, masterKey);
		std::string base64ForDB = cryptoManager.Base64Encode(encryptedTextForDB);

		if (dbManager.EditMessage(messageId, currentUser, base64ForDB)) {
			json response;
			response["status"] = "success";

			SendEncryptedResponse(currentSocket, "UPDATE_CHAT", response);

			for (const auto& a : loggedInUsers) {
				if (a.second == targetUser) {
					SendEncryptedResponse(a.first, "UPDATE_CHAT", response);
					break;
				}
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

	try {
		std::string transferId = requestJson.value("transfer_id", "");
		std::string targetUser = requestJson.value("target_user", "");
		std::string fileName = requestJson.value("file_name", "");

		FileTransferSession currentSession;
		currentSession.fileName = fileName;
		currentSession.targetUser = targetUser;

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
		auto& sessionBuffer = memoryForFile[transferId].buffer;
		sessionBuffer.insert(sessionBuffer.end(), decodeDataFile.begin(), decodeDataFile.end());
	}
	catch (const std::exception& e) {
		std::cout << "[СЕРВЕР] Помилка в FileChunk: " << e.what() << std::endl;
	}
}

void MyCommandProcessor::HandleFileEnd(SOCKET currentSocket, const json& data)
{
	json requestJson;
	if (!DecryptRequest(currentSocket, data, requestJson)) return;

	try {
		std::string transferId = requestJson.value("transfer_id", "");
		std::string targetUser = requestJson.value("target_user", "");

		FileTransferSession& session = memoryForFile[transferId];

		std::ofstream fout(session.fileName, std::ios::binary);
		if (fout.is_open()) {
			fout.write(reinterpret_cast<const char*>(session.buffer.data()), session.buffer.size());
			fout.close();
			std::cout << "[СЕРВЕР] Файл успішно збережено: " << session.fileName << std::endl;

			std::string fileMessageText = "[FILE] " + session.fileName;
			std::string encryptedTextForDB = cryptoManager.EncryptAES(fileMessageText, masterKey);
			std::string base64ForDB = cryptoManager.Base64Encode(encryptedTextForDB);

			if (dbManager.SaveMessage(loggedInUsers[currentSocket], targetUser, base64ForDB)) {
				json response;
				response["status"] = "success";

				SendEncryptedResponse(currentSocket, "UPDATE_CHAT", response);

				for (const auto& a : loggedInUsers) {
					if (a.second == targetUser) {
						SendEncryptedResponse(a.first, "UPDATE_CHAT", response);
						break;
					}
				}
			}
		}
		else {
			std::cout << "[СЕРВЕР] ПОМИЛКА: Не вдалося створити файл " << session.fileName << std::endl;
		}

		memoryForFile.erase(transferId);
	}
	catch (const std::exception& e) {
		std::cout << "[СЕРВЕР] Помилка в FileEnd: " << e.what() << std::endl;
	}
}

void MyCommandProcessor::HandleDownloadFile(SOCKET currentSocket, const json& data)
{
	json requestJson;
	if (!DecryptRequest(currentSocket, data, requestJson)) return;

	try {
		std::string fileName = requestJson.value("file_name", "");
		std::ifstream file(fileName, std::ios::binary);

		if (file.is_open()) {
			file.seekg(0, std::ios::end);
			int fileSize = file.tellg();
			file.seekg(0, std::ios::beg);

			std::string transferId = std::to_string(rand()) + "_" + fileName;

			json responseStart;
			responseStart["transfer_id"] = transferId;
			responseStart["file_name"] = fileName;
			responseStart["file_size"] = fileSize;
			SendEncryptedResponse(currentSocket, "FILE_RECEIVE_START", responseStart);

			std::vector<unsigned char> buffer(16 * 1024);
			int chunkIndex = 0;

			while (!file.eof()) {
				file.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
				int bytesRead = file.gcount();
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

			std::cout << "[СЕРВЕР] Відправлено файл: " << fileName << " (" << chunkIndex << " шматків)" << std::endl;
		}
		else {
			std::cout << "[СЕРВЕР] Помилка: не знайдено файл " << fileName << std::endl;
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

		SendEncryptedResponse(currentSocket, "SEARCH_RESPONSE", responseInner);
	}
	catch (const std::exception& e) {
		std::cout << "[СЕРВЕР] Стандартна помилка в SEARCH_USER: " << e.what() << std::endl;
	}
}

void MyCommandProcessor::HandleLogout(SOCKET currentSocket, const json& data)
{
	if (loggedInUsers.find(currentSocket) != loggedInUsers.end()) {
		std::cout << "[СЕРВЕР] Користувач " << loggedInUsers[currentSocket] << " безпечно вийшов з акаунту." << std::endl;
		loggedInUsers.erase(currentSocket);
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
	loggedInUsers.erase(currentSocket);
	clientAesKeys.erase(currentSocket);
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
		std::string email = requestJson.value("email", "");

		if (emailLockouts.find(email) != emailLockouts.end()) {
			if (std::chrono::steady_clock::now() < emailLockouts[email]) {
				json responseInner;
				responseInner["status"] = "locked";
				SendEncryptedResponse(currentSocket, "SEND_VERIFICATION_CODE_RESPONSE", responseInner);
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

		unsigned int randomNum = *(unsigned int*)randomBytes;
		int secureCode = 100000 + (randomNum % 900000);
		std::string code = std::to_string(secureCode);

		EmailVerificationSession session;
		session.code = code;
		session.expiresAt = std::chrono::steady_clock::now() + std::chrono::minutes(5);
		verificationCodes[email] = session;

		json responseInner;

		if (SendEmail(email, code)) {
			responseInner["status"] = "success";
		}
		else {
			responseInner["status"] = "error";
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
			return;
		}

		if (std::chrono::steady_clock::now() > verificationCodes[email].expiresAt) {
			verificationCodes.erase(email);
			responseInner["status"] = "error";
			SendEncryptedResponse(currentSocket, "VERIFY_CODE_RESPONSE", responseInner);
			return;
		}

		if (verificationCodes[email].code == code) {
			std::string currentUser = loggedInUsers[currentSocket];
			dbManager.SetUserEmailVerified(currentUser, email);

			verificationCodes.erase(email);
			responseInner["status"] = "success";
			SendEncryptedResponse(currentSocket, "VERIFY_CODE_RESPONSE", responseInner);
		}
		else {
			verificationCodes[email].failedAttempts++;

			if (verificationCodes[email].failedAttempts >= 5) {
				emailLockouts[email] = std::chrono::steady_clock::now() + std::chrono::minutes(5);
				verificationCodes.erase(email);
				responseInner["status"] = "locked";
			}
			else {
				responseInner["status"] = "error";
			}

			SendEncryptedResponse(currentSocket, "VERIFY_CODE_RESPONSE", responseInner);
		}
	}
	catch (const std::exception& e) {
		std::cout << "[СЕРВЕР] Стандартна помилка в VERIFY_CODE_RESPONSE: " << e.what() << std::endl;
	}
}
