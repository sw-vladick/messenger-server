#include "MenagerSocket.h"

MenagerSocket::MenagerSocket()
{
	serverSocket = wsadata.CreateSocketTCP();
	if (serverSocket == INVALID_SOCKET) {
		std::cerr << "error create socket!\n";
		std::exit(0);
	}
	maxClients = 8;
	clients = new Client[maxClients];
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
		if  (clientSocket != INVALID_SOCKET) {
			std::lock_guard<std::mutex> lock(acceptMTX);
			if (currentCountClient < maxClients - 1) {
				for (int i = 0; i < maxClients; i++)
				{
					if (clients[i].clientSocket == INVALID_SOCKET) {
						clients[i].clientSocket = clientSocket;
						currentCountClient++;
						std::thread t([=]() {HandleSocket(clients[i],i);});
						t.detach();
						break;
					}
				}
			}
			else {
				std::cout << "create new slots\n";
				maxClients *= 2;
				Client* temporaryClients = new Client[maxClients];
				for (size_t i = 0; i < maxClients/2; i++)
				{
					temporaryClients[i] = std::move(clients[i]);
				}
				delete[] clients;
				clients = temporaryClients;

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
		char buf[BUFFER_SIZE];

		int expectedBytes = 0;

		recv(currentClient.clientSocket, (char*)&expectedBytes, 4, 0);
		if (expectedBytes <= 0 || expectedBytes > BUFFER_SIZE) {
			std::cerr << "Invalid message size or client left\n";
			break;
		}

		int resultRecv = recv(currentClient.clientSocket, buf, expectedBytes, 0);
		while (true)
		{
			if (resultRecv < expectedBytes) {
				resultRecv += recv(currentClient.clientSocket, buf, expectedBytes - resultRecv, resultRecv);
			}
			else {
				break;
			}
		}

		std::string msg(buf, expectedBytes);

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

