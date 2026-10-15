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
            sql::PreparedStatement* pstmt1 = con->prepareStatement("INSERT INTO Users(username, is_verified) VALUES (?, 0)");
            pstmt1->setString(1, username);
            pstmt1->executeUpdate();
            delete pstmt1;

            sql::Statement* stmt = con->createStatement();
            sql::ResultSet* res = stmt->executeQuery("SELECT LAST_INSERT_ID() AS id");
            int newUserId = -1;
            if (res->next()) {
                newUserId = res->getInt("id");
            }
            delete res;
            delete stmt;

            if (newUserId != -1) {
                sql::PreparedStatement* pstmt2 = con->prepareStatement("INSERT INTO Auth_Local(user_id, password_hash, salt) VALUES (?, ?, ?)");
                pstmt2->setInt(1, newUserId);
                pstmt2->setString(2, password_hash);
                pstmt2->setString(3, salt);
                pstmt2->executeUpdate();
                delete pstmt2;
                status = 1;
            }
        }
        catch (sql::SQLException& e)
        {
            std::cout << "[DB ERROR RegisterUser]: " << e.what() << std::endl;
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

        sql::PreparedStatement* pstmt = con->prepareStatement(
            "SELECT u.id, a.password_hash, a.salt "
            "FROM Users u "
            "JOIN Auth_Local a ON u.id = a.user_id "
            "WHERE u.username = ?"
        );
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
        std::cout << "[DB ERROR LoginUser]: " << e.what() << std::endl;
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

bool DatabaseManager::IsUserVerified(const std::string& username)
{
    try {
        std::lock_guard<std::mutex> lock(dbMutex);

        sql::PreparedStatement* pstmt = con->prepareStatement(
            "SELECT is_verified FROM Users WHERE username = ?;"
        );

        pstmt->setString(1, username);

        sql::ResultSet* res = pstmt->executeQuery();

        bool verified = false;
        if (res->next()) {
            verified = res->getBoolean("is_verified");
        }

        delete pstmt;
        delete res;
        return verified;
    }
    catch (sql::SQLException& e) {
        std::cout << "[DB ERROR] Помилка IsUserVerified: " << e.what() << std::endl;
        return false;
    }
}

void DatabaseManager::SetUserEmailVerified(const std::string& username, const std::string& email)
{
    try {
        std::lock_guard<std::mutex> lock(dbMutex);

        sql::PreparedStatement* pstmt = con->prepareStatement(
            "UPDATE Users SET email = ?, is_verified = 1 WHERE username = ?;"
        );

        pstmt->setString(1, email);
        pstmt->setString(2, username);

        pstmt->executeUpdate();

        delete pstmt;
    }
    catch (sql::SQLException& e) {
        std::cout << "[DB ERROR] Помилка IsUserVerified: " << e.what() << std::endl;
    }
}

bool DatabaseManager::LoginOrRegisterGoogleUser(const std::string& email, const std::string& googleId, std::string& outUsername)
{
    try {
        std::lock_guard<std::mutex> lock(dbMutex);

        sql::PreparedStatement* pstmtCheck = con->prepareStatement(
            "SELECT u.username FROM Auth_Google ag "
            "JOIN Users u ON ag.user_id = u.id "
            "WHERE ag.google_id = ?"
        );
        pstmtCheck->setString(1, googleId);
        sql::ResultSet* resCheck = pstmtCheck->executeQuery();

        if (resCheck->next()) {
            outUsername = resCheck->getString("username");
            delete resCheck;
            delete pstmtCheck;
            return true;
        }
        delete resCheck;
        delete pstmtCheck;

        sql::PreparedStatement* pstmtEmailCheck = con->prepareStatement("SELECT id, username FROM Users WHERE email = ?");
        pstmtEmailCheck->setString(1, email);
        sql::ResultSet* resEmail = pstmtEmailCheck->executeQuery();

        int existingUserId = -1;
        if (resEmail->next()) {
            existingUserId = resEmail->getInt("id");
            outUsername = resEmail->getString("username");
        }
        delete resEmail;
        delete pstmtEmailCheck;

        if (existingUserId != -1) {
            sql::PreparedStatement* pstmtLink = con->prepareStatement("INSERT INTO Auth_Google (user_id, google_id) VALUES (?, ?)");
            pstmtLink->setInt(1, existingUserId);
            pstmtLink->setString(2, googleId);
            pstmtLink->executeUpdate();
            delete pstmtLink;

            sql::PreparedStatement* pstmtVerify = con->prepareStatement("UPDATE Users SET is_verified = 1 WHERE id = ?");
            pstmtVerify->setInt(1, existingUserId);
            pstmtVerify->executeUpdate();
            delete pstmtVerify;

            return true;
        }
        else {
            std::string baseUsername = email.substr(0, email.find('@'));
            unsigned int randomNum = 0;
            if (RAND_bytes(reinterpret_cast<unsigned char*>(&randomNum), sizeof(randomNum)) != 1) {
                std::cout << "[DB ERROR] Помилка RAND_bytes" << std::endl;
                return false;
            }
            int secureSuffix = 1000 + (randomNum % 9000);

            outUsername = baseUsername + "_" + std::to_string(secureSuffix);

            sql::PreparedStatement* pstmtCreate = con->prepareStatement(
                "INSERT INTO Users (username, email, is_verified) VALUES (?, ?, 1)"
            );
            pstmtCreate->setString(1, outUsername);
            pstmtCreate->setString(2, email);
            pstmtCreate->executeUpdate();
            delete pstmtCreate;

            sql::Statement* stmt = con->createStatement();
            sql::ResultSet* resId = stmt->executeQuery("SELECT LAST_INSERT_ID() AS id");
            int newUserId = -1;
            if (resId->next()) {
                newUserId = resId->getInt("id");
            }
            delete resId;
            delete stmt;

            if (newUserId != -1) {
                sql::PreparedStatement* pstmtAuthGoogle = con->prepareStatement(
                    "INSERT INTO Auth_Google (user_id, google_id) VALUES (?, ?)"
                );
                pstmtAuthGoogle->setInt(1, newUserId);
                pstmtAuthGoogle->setString(2, googleId);
                pstmtAuthGoogle->executeUpdate();
                delete pstmtAuthGoogle;
                return true;
            }
        }
    }
    catch (sql::SQLException& e) {
        std::cout << "[DB ERROR LoginOrRegisterGoogleUser]: " << e.what() << std::endl;
        return false;
    }

    return false;
}

void DatabaseManager::LogActivity(const std::string& username, const std::string& action, const std::string& ipAddress)
{
    try {
        std::lock_guard<std::mutex> lock(dbMutex);
        sql::PreparedStatement* pstmt = con->prepareStatement(
            "INSERT INTO ActivityLogs (username, action, ip_address) VALUES (?, ?, ?)"
        );
        pstmt->setString(1, username);
        pstmt->setString(2, action);
        pstmt->setString(3, ipAddress);

        pstmt->executeUpdate();
        delete pstmt;
    }
    catch (sql::SQLException& e) {
        std::cout << "[DB ERROR LogActivity]: " << e.what() << std::endl;
    }
}
