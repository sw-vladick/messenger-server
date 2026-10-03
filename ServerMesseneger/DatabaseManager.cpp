#include "DatabaseManager.h"


DatabaseManager::DatabaseManager(const std::string& db_master_key) : con(nullptr)
{
    masterKey = db_master_key;
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

int DatabaseManager::RegisterUser(const std::string& username, const std::string& password, const std::string& ipAddress) {
    if (!StartAttempts(ipAddress, attemptsRegMutex, registerAttempts)) {
        return -1;
    }
    int status = 0;
    {
        std::lock_guard<std::mutex> lock(dbMutex);
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
            status = 1;
        }
        catch (sql::SQLException& e)
        {
            std::cout << e.what() << std::endl;
            status = 0;
        }
    }
    EndAttempts(ipAddress, attemptsRegMutex, registerAttempts, status);
    return status;
}

int DatabaseManager::LoginUser(const std::string& username, const std::string& password, const std::string& ipAddress)
{
    if (!StartAttempts(ipAddress, attemptsLoginMutex, loginAttempts)) {
        return -1;
    }
    int status = 0;
    try
    {
        std::lock_guard<std::mutex> lock(dbMutex);
        sql::PreparedStatement* pstmt = con->prepareStatement("SELECT salt, password_hash FROM Users WHERE username = ?");
        pstmt->setString(1, username);
        sql::ResultSet* res = pstmt->executeQuery();

        if (res->next()) {
            std::string db_salt = res->getString("salt");
            std::string db_hash = res->getString("password_hash");
            std::string pass_hash = hashPassword(password, db_salt);

            if (pass_hash == db_hash) {
                status = 1;
            }
        }
        delete res;
        delete pstmt;
    }
    catch (sql::SQLException& e) {
        std::cout << e.what() << std::endl;
        status = 0;
    }

    EndAttempts(ipAddress, attemptsLoginMutex, loginAttempts, status);

    return status;
}

bool DatabaseManager::StartAttempts(const std::string& ipAddress, std::mutex& mtx, mapIp& u_map)
{
    {
        std::lock_guard<std::mutex> lock(mtx);
        auto& attempt = u_map[ipAddress];
        
        if (attempt.failedCount >= 5) {
            auto now = std::chrono::steady_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::minutes>(now - attempt.lockTime).count();

            if (duration < 1) {
                return false;
            }
            else {
                attempt.failedCount = 0;
            }
        }
        attempt.failedCount++;
    }
    return true;
}

void DatabaseManager::EndAttempts(const std::string& ipAddress, std::mutex& mtx, mapIp& u_map,const int status)
{
    {
        std::lock_guard<std::mutex> lock(mtx);
        auto& attempt = u_map[ipAddress];

        if (status == 1) {
            u_map.erase(ipAddress);
        }
        else if (attempt.failedCount == 5) {
            attempt.lockTime = std::chrono::steady_clock::now();
        }
    }
}

bool DatabaseManager::UserExists(const std::string& username)
{
    try {
        std::lock_guard<std::mutex> lock(dbMutex);
        sql::PreparedStatement* pstmt = con->prepareStatement("SELECT id FROM Users WHERE username = ?");
        pstmt->setString(1, username);

        sql::ResultSet* res = pstmt->executeQuery();
        bool exists = res->next();

        delete res;
        delete pstmt;
        return exists;
    }
    catch (sql::SQLException& e) {
        std::cout << "[DB ERROR] Помилка пошуку користувача: " << e.what() << std::endl;
        return false;
    }
}

bool DatabaseManager::Connect(const std::string& host, const std::string& user, const std::string& password, const std::string& database)
{
    try {
        sql::mysql::MySQL_Driver* driver = sql::mysql::get_mysql_driver_instance();

        con = driver->connect(host, user, password);
        con->setSchema(database);

        std::unique_ptr<sql::Statement> stmt(con->createStatement());
        stmt->execute("SET NAMES utf8mb4");

        std::cout << "[БД] Успішно підключено до бази: " << database << std::endl;
        return true;
    }
    catch (sql::SQLException& e) {
        std::cout << "[MYSQL ERROR] " << e.what() << std::endl;
        return false;
    }
}

std::vector<std::string> DatabaseManager::SearchUsers(const std::string& searchQuery)
{
    std::vector<std::string> foundUsers;

    try {
        std::lock_guard<std::mutex> lock(dbMutex);

        sql::PreparedStatement* pstmt = con->prepareStatement("SELECT username FROM Users WHERE username LIKE ? LIMIT 20");

        pstmt->setString(1, searchQuery + "%");

        sql::ResultSet* res = pstmt->executeQuery();

        while (res->next()) {
            foundUsers.push_back(res->getString("username"));
        }

        delete res;
        delete pstmt;
    }
    catch (sql::SQLException& e) {
        std::cout << "[DB ERROR] Помилка живого пошуку користувачів: " << e.what() << std::endl;
    }

    return foundUsers;
}

std::vector<ChatMessage> DatabaseManager::GetChatHistory(const std::string& user1, const std::string& user2)
{
    std::vector<ChatMessage> messages;

    try
    {
        std::lock_guard<std::mutex> lock(dbMutex);

       sql::PreparedStatement* pstmt = con->prepareStatement(
        "SELECT m.id, u.username AS sender_name, m.content, DATE_FORMAT(m.created_at, '%H:%i') as time, m.is_edited, m.is_read "
        "FROM messages m "
        "JOIN Users u ON m.sender_id = u.id "
        "WHERE (m.sender_id = (SELECT id FROM Users WHERE username = ?) AND m.receiver_id = (SELECT id FROM Users WHERE username = ?)) "
        "   OR (m.sender_id = (SELECT id FROM Users WHERE username = ?) AND m.receiver_id = (SELECT id FROM Users WHERE username = ?)) "
        "ORDER BY m.created_at ASC"
    );

        pstmt->setString(1, user1);
        pstmt->setString(2, user2);
        pstmt->setString(3, user2);
        pstmt->setString(4, user1);

        sql::ResultSet* res = pstmt->executeQuery();

        while (res->next()) {
            ChatMessage msg;
            msg.id = res->getInt("id");
            msg.is_edited = res->getBoolean("is_edited");
            msg.is_read = res->getBoolean("is_read");
            msg.sender = res->getString("sender_name");
            msg.text = res->getString("content");
            msg.timestamp = res->getString("time");

            messages.push_back(msg);
        }

        delete pstmt;
        delete res;
    }
    catch (sql::SQLException& e) {
        std::cout << "[DB ERROR] Помилка завантаження історії чату: " << e.what() << std::endl;
    }
    return messages;
}

bool DatabaseManager::SaveMessage(const std::string& sender, const std::string& receiver, const std::string text)
{
    try
    {
        std::lock_guard<std::mutex> lock(dbMutex);

        sql::PreparedStatement* pstmt = con->prepareStatement(
            "INSERT INTO messages (sender_id, receiver_id, content) "
            "VALUES ("
            "  (SELECT id FROM Users WHERE username = ?), "
            "  (SELECT id FROM Users WHERE username = ?), "
            "  ?"
            ")"
        );

        pstmt->setString(1, sender);
        pstmt->setString(2, receiver);
        pstmt->setString(3, text);

        pstmt->executeUpdate();
        delete pstmt;
        return true;
    }
    catch (sql::SQLException& e) {
        std::cout << "[DB ERROR] Помилка завантаження повідомлення: " << e.what() << std::endl;
        return false;
    }
}

std::vector<std::string> DatabaseManager::GetRecentChats(const std::string& username)
{
    std::vector<std::string> foundUsers;

    try {
        std::lock_guard<std::mutex> lock(dbMutex);

        sql::PreparedStatement* pstmt = con->prepareStatement(
            "SELECT DISTINCT u.username "
            "FROM messages m "
            "JOIN Users u ON(u.id = m.sender_id OR u.id = m.receiver_id) "
            "WHERE(m.sender_id = (SELECT id FROM Users WHERE username = ? ) "
            "OR m.receiver_id = (SELECT id FROM Users WHERE username = ? )) "
            "AND u.username != ?;"
        );

        pstmt->setString(1, username);
        pstmt->setString(2, username);
        pstmt->setString(3, username);

        sql::ResultSet* res = pstmt->executeQuery();

        while (res->next()) {
            foundUsers.push_back(res->getString("username"));
        }

        delete res;
        delete pstmt;
    }
    catch (sql::SQLException& e) {
        std::cout << "[DB ERROR] Помилка живого пошуку користувачів: " << e.what() << std::endl;
    }

    return foundUsers;
}

bool DatabaseManager::EditMessage(int messageId, const std::string& senderUsername, const std::string& newText)
{
    try {
        std::lock_guard<std::mutex> lock(dbMutex);

        sql::PreparedStatement* pstmt = con->prepareStatement(
            "UPDATE messages SET content = ?, is_edited = TRUE "
            "WHERE id = ? AND sender_id = (SELECT id FROM Users WHERE username = ?)"
        );

        pstmt->setString(1, newText);
        pstmt->setInt(2, messageId);
        pstmt->setString(3, senderUsername);

        int updatedRows = pstmt->executeUpdate();
        delete pstmt;

        return updatedRows > 0;
    }
    catch (sql::SQLException& e) {
        std::cout << "[DB ERROR] Помилка редагування повідомлення: " << e.what() << std::endl;
        return false;
    }
}

void DatabaseManager::MarkMessagesAsRead(const std::string& sender, const std::string& receiver)
{
    try {
        std::lock_guard<std::mutex> lock(dbMutex);
        sql::PreparedStatement* pstmt = con->prepareStatement(
            "UPDATE messages SET is_read = TRUE "
            "WHERE sender_id = (SELECT id FROM Users WHERE username = ?) "
            "AND receiver_id = (SELECT id FROM Users WHERE username = ?) "
            "AND is_read = FALSE"
        );
        pstmt->setString(1, sender);
        pstmt->setString(2, receiver);
        pstmt->executeUpdate();
        delete pstmt;
    }
    catch (sql::SQLException& e) {
        std::cout << "[DB ERROR] Помилка оновлення статусу прочитання: " << e.what() << std::endl;
    }
}
