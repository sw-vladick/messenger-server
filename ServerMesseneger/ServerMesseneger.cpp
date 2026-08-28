#include <iostream>
#include "MenagerSocket.h"
#include <Windows.h>

int main()
{
    SetConsoleCP(CP_UTF8);
    SetConsoleOutputCP(CP_UTF8);
    MenagerSocket menager;
    menager.FromBindToListen();
    menager.AcceptClient();
}

