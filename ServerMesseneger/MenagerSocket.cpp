#include "MenagerSocket.h"

MenagerSocket::MenagerSocket(const std::string& db_master_key) : RouteMap(db_master_key)
{
	serverSocket = wsadata.CreateSocketTCP();
	if (serverSocket == INVALID_SOCKET) {
		std::cerr << "error create socket!\n";
		std::exit(0);
	}
	maxClients = 8;
	clients = new Client * [maxClients];
	for (int i = 0; i < maxClients; i++) {
		clients[i] = nullptr;
	}
	currentCountClient = 0;
}

void MenagerSocket::FromBindToListen()
{
	sockaddr_in addressServer;
	addressServer.sin_addr.s_addr = INADDR_ANY;
	addressServer.sin_port = htons(PORT);
	addressServer.sin_family = AF_INET;

	if (bind(serverSocket, (sockaddr*)&addressServer, sizeof(addressServer)) == SOCKET_ERROR) {
		std::cerr << "error bind!\n";
		std::exit(0);
	}

	if (listen(serverSocket, SOMAXCONN) == SOCKET_ERROR) {
		std::cerr << "error listen!\n";
		std::exit(0);
	}
	std::cout << "FromBindToListen success\n";
}

void MenagerSocket::AcceptClient()
{
	while (true)
	{
		sockaddr_in addressClient;
		int sizeClient = sizeof(addressClient);
		SOCKET clientSocket = accept(serverSocket, (sockaddr*)&addressClient, &sizeClient);

		if (clientSocket != INVALID_SOCKET) {
			std::lock_guard<std::mutex> lock(acceptMTX);

			if (currentCountClient >= maxClients - 1) {
				std::cout << "create new slots. New max: " << maxClients * 2 << "\n";
				int oldMax = maxClients;
				maxClients *= 2;

				Client** temporaryClients = new Client * [maxClients];

				for (int i = 0; i < oldMax; i++) {
					temporaryClients[i] = clients[i];
				}
				for (int i = oldMax; i < maxClients; i++) {
					temporaryClients[i] = nullptr;
				}

				delete[] clients;
				clients = temporaryClients;
			}

			for (int i = 0; i < maxClients; i++)
			{

				if (clients[i] == nullptr) {
					clients[i] = new Client();
					clients[i]->clientSocket = INVALID_SOCKET;
				}

				if (clients[i]->clientSocket == INVALID_SOCKET) {
					clients[i]->clientSocket = clientSocket;
					currentCountClient++;

					Client* targetClient = clients[i];

					std::thread t([=]() { HandleSocket(*targetClient, i); });
					t.detach();
					break;
				}
			}
		}
		else {
			std::cerr << "error accept!\n";
		}
	}
}

void MenagerSocket::HandleSocket(Client& currentClient, int index)
{
	while (true)
	{
		int expectedBytes = 0;

		int headerResult = recv(currentClient.clientSocket, reinterpret_cast<char*>(&expectedBytes), sizeof(int), 0);

		if (headerResult <= 0) {
			std::cout << "[СЕРВЕР] Клієнт відключився.\n";
			break;
		}

		if (expectedBytes <= 0 || expectedBytes > 5 * 1024 * 1024) {
			std::cout << "[СЕРВЕР] Критична помилка розміру пакета: " << expectedBytes << ". Відключаємо клієнта.\n";
			break;
		}

		std::vector<char> buf(expectedBytes);
		int totalReceived = 0;

		while (totalReceived < expectedBytes)
		{
			int bytes = recv(currentClient.clientSocket, buf.data() + totalReceived, expectedBytes - totalReceived, 0);

			if (bytes <= 0) {
				break;
			}
			totalReceived += bytes;
		}

		if (totalReceived < expectedBytes) {
			std::cout << "[СЕРВЕР] З'єднання розірвано під час читання пакета.\n";
			break;
		}

		std::string msg(buf.begin(), buf.end());

		try
		{
			json parsedData = json::parse(msg);

			if (parsedData.contains("Command")) {
				std::string command = parsedData["Command"];
				RouteMap.Execute(command, currentClient.clientSocket, parsedData);
			}
		}
		catch (json::parse_error& e) {
			std::cout << "[ПОМИЛКА] Прийшов битий JSON: " << e.what() << std::endl;
		}
	}
	RouteMap.RemoveClient(currentClient.clientSocket);

	closesocket(currentClient.clientSocket);
	currentClient.DoEmptyClient();
	--currentCountClient;
}

MenagerSocket::~MenagerSocket()
{
	closesocket(serverSocket);
}

Client::Client()
{
	clientSocket = INVALID_SOCKET;
}

Client::~Client()
{
	closesocket(clientSocket);
}

Client& Client::operator=(Client&& other) noexcept
{
	if (this != &other) {
		closesocket(clientSocket);
		clientSocket = other.clientSocket;
		nickname = std::move(other.nickname);
		other.clientSocket = INVALID_SOCKET;
	}
	return *this;
}

void Client::DoEmptyClient()
{
	clientSocket = INVALID_SOCKET;
	nickname = "";
}

