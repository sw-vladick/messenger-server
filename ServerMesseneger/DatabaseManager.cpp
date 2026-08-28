#include "DatabaseManager.h"


DatabaseManager::DatabaseManager() : con(nullptr)
{
}

DatabaseManager::~DatabaseManager() {
    if (con) {
        delete con;
        std::cout << "[БД] З'єднання з базою закрито." << std::endl;
    }
}

std::string DatabaseManager::generateSalt(int length) {
    unsigned char saltBytes[16];

    if (RAND_bytes(saltBytes, 16) != 1) {
        throw std::runtime_error("Помилка OpenSSL RAND_bytes");
    }

    std::stringstream ss;

    for (int i = 0; i < 16; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)saltBytes[i];
    }

    return ss.str();
}

std::string DatabaseManager::hashPassword(const std::string& password, const std::string& salt) {
    std::string combined = password + salt;

    unsigned char hashBuffer[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(combined.c_str()), combined.length(), hashBuffer);

    std::stringstream ss;
    
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hashBuffer[i];
    }
    return ss.str();
}

bool DatabaseManager::RegisterUser(const std::string& username, const std::string& password) {
    std::string salt = generateSalt();
    std::string password_hash = hashPassword(password, salt);
    try
    {
        sql::PreparedStatement* pstmt = con->prepareStatement("INSERT INTO Users(username,password_hash,salt) VALUES (?,?,?)");

        pstmt->setString(1, username);
        pstmt->setString(2, password_hash);
        pstmt->setString(3, salt);

        pstmt->executeUpdate();
        delete pstmt;
    }
    catch ( sql::SQLException& e)
    {
        std::cout << e.what() << std::endl;
        return false;
    }
   
    return true;
}

bool DatabaseManager::LoginUser(const std::string& username, const std::string& password)
{
    try
    {
        sql::PreparedStatement* pstmt = con->prepareStatement("SELECT salt, password_hash FROM Users WHERE username = ?");
        pstmt->setString(1, username);

        sql::ResultSet* res = pstmt->executeQuery();

        bool success = false;

        if (res->next()) {
            std::string db_salt = res->getString("salt");
            std::string db_hash = res->getString("password_hash");

            std::string pass_hash = hashPassword(password, db_salt);

            if (pass_hash == db_hash) {
                success = true;
            }
        }

        delete res;
        delete pstmt;
        return success;
    }
    catch (sql::SQLException& e)
    {
        std::cout << e.what() << std::endl;
        return false;
    }

}

bool DatabaseManager::Connect(const std::string& host, const std::string& user, const std::string& password, const std::string& database)
{
    try {
        sql::mysql::MySQL_Driver* driver = sql::mysql::get_mysql_driver_instance();

        con = driver->connect(host, user, password);
        con->setSchema(database);

        std::cout << "[БД] Успішно підключено до бази: " << database << std::endl;
        return true;
    }
    catch (sql::SQLException& e) {
        std::cout << "[MYSQL ERROR] " << e.what() << std::endl;
        return false;
    }
}