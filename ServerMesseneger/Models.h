#pragma once
#include <string>

struct ChatMessage {
	int id;
	bool is_edited;
	bool is_read;
	std::string sender;
	std::string text;
	std::string timestamp;
};