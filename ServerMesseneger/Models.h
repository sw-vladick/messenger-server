#pragma once
#include <string>

struct ChatMessage {
	std::string sender;
	std::string text;
	std::string timestamp;
};