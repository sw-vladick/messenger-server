#include "Config.h"
#include <fstream>
#include <iostream>
#include "json.hpp"

using json = nlohmann::json;

std::string DB_MASTER_KEY = "";

std::string LoadConfig() {
    std::ifstream configFile("config.json");
    if (configFile.is_open()) {
        json configObj;
        configFile >> configObj;
        DB_MASTER_KEY = configObj.value("master_key", "");
        return DB_MASTER_KEY;
    }
    else {
        std::cerr << "[ÏÎÌÈËÊÀ] Ôàéë config.json íå çíàéäåíî!" << std::endl;
        exit(1);
    }
}