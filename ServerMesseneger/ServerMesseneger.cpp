#include <iostream>
#include "MenagerSocket.h"
#include <Windows.h>
#include <ctime>
#include <cstdlib>
#include "Config.h"

int main()
{
    srand((unsigned)time(NULL));
    SetConsoleCP(CP_UTF8);
    SetConsoleOutputCP(CP_UTF8);

    std::string masterKey = LoadConfig();

    MenagerSocket menager(masterKey);
    menager.FromBindToListen();
    menager.AcceptClient();
}

