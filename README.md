# Secure C++ TCP Messenger Server

Багатопотоковий C++ TCP бекенд-сервер для десктопного месенджера реального часу (клієнтська частина розроблена на Unreal Engine 5). Сервер реалізує власний бінарний протокол поверх TCP з передачею JSON-пакетів, гібридним шифруванням трафіку (RSA + AES-256), авторизацією через Google OAuth 2.0, двофакторним підтвердженням пошти через SMTP та шифруванням повідомлень у базі даних.

## Основні можливості

* **Власний TCP-протокол та багатопотоковість:** Побудований на базі нативних сокетів Windows (`WinSock2`) із фреймінгом пакетів через 4-байтний заголовок довжини (`expectedBytes`) та динамічним масштабуванням слотів підключень.
* **Гібридна криптографія (OpenSSL):**
  * **RSA (PKCS#1 OAEP):** безпечний початковий Handshake та обмін сесійними ключами.
  * **AES-256-CBC:** симетричне шифрування всього мережевого трафіку між клієнтом і сервером.
  * **Encryption at Rest:** усі повідомлення чату шифруються серверним майстер-ключем (`AES-256`) перед збереженням у базу даних MySQL.
* **Багаторівнева автентифікація:**
  * **Локальна авторизація:** хешування паролів алгоритмом `SHA-256` з генерацією криптографічно стійкої випадкової солі (`Salt`, 16 байтів через OpenSSL `RAND_bytes`).
  * **Google OAuth 2.0:** серверний обмін коду авторизації на токен (`https://oauth2.googleapis.com/token`) та отримання профілю користувача через `libcurl` із підтримкою автоматичної прив'язки акаунтів (Account Linking).
  * **Підтвердження пошти (SMTP 2FA):** генерація 6-значних кодів підтвердження з часом життя 5 хвилин та відправка через захищене з'єднання `smtps://smtp.gmail.com:465`.
* **Безпека та захист від атак:**
  * Захист від Brute-force атак з обмеженням спроб входу та реєстрації по IP-адресі (`StartAttempts` / `EndAttempts`).
  * Блокування спаму та підбору кодів підтвердження електронної пошти.
  * Полноцінний **Журнал аудиту безпеки (`ActivityLogs`)**, який фіксує входи, помилки авторизації, блокування, спроби відправки пошкоджених пакетів (`MALFORMED_PAYLOAD`) та розриви з'єднань із прив'язкою до IP та часу.
  * Захист від SQL-ін'єкцій завдяки виключному використанню параметризованих запитів (`sql::PreparedStatement`).
  * Ізоляція завантажених файлів та захист від Path Traversal.
* **Чат та передача файлів:**
  * Обмін повідомленнями в реальному часі, редагування повідомлень (`is_edited`), статуси прочитання (`is_read`) та живий пошук користувачів.
  * Передача та завантаження файлів чанками по 16 КБ (кодування Base64 поверх зашифрованого AES-каналу).

## Технологічний стек

* **Мова:** C++17 (STL, `std::thread`, `std::mutex`, `std::atomic`, `std::filesystem`)
* **Мережа:** WinSock2 (`ws2_32.lib`), `libcurl` (SMTPS та HTTPS-запити)
* **Криптографія:** OpenSSL (`EVP`, `RSA`, `AES-256-CBC`, `SHA-256`, `RAND_bytes`, `BIO` Base64)
* **База даних:** MySQL (`MySQL Connector/C++`)
* **Серіалізація даних:** `nlohmann/json`

## Архітектура проєкту

* **`MenagerSocket` та `WSAControl`:** Ініціалізація сокетів, прослуховування порту `8000`, прийом клієнтів, контроль цілісності TCP-пакетів та керування потоками.
* **`MyCommandProcessor`:** Центральний диспетчер команд (патерн Command Router на базі `std::unordered_map`). Керує сесіями користувачів, OAuth 2.0, SMTP-верифікацією та потоковою передачею файлів.
* **`CryptoManager`:** Обгортка над низькорівневим API OpenSSL `EVP` для роботи з RSA, AES-256 та Base64.
* **`DatabaseManager`:** Потокобезпечний шар доступу до бази даних MySQL із системою Rate Limiting та логуванням активності.

## Структура бази даних (MySQL)

```sql
CREATE DATABASE messenger_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE messenger_db;

CREATE TABLE Users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    email VARCHAR(255) UNIQUE,
    is_verified TINYINT(1) DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE Auth_Local (
    user_id INT PRIMARY KEY,
    password_hash VARCHAR(64) NOT NULL,
    salt VARCHAR(32) NOT NULL,
    FOREIGN KEY (user_id) REFERENCES Users(id) ON DELETE CASCADE
);

CREATE TABLE Auth_Google (
    user_id INT PRIMARY KEY,
    google_id VARCHAR(255) NOT NULL UNIQUE,
    FOREIGN KEY (user_id) REFERENCES Users(id) ON DELETE CASCADE
);

CREATE TABLE messages (
    id INT AUTO_INCREMENT PRIMARY KEY,
    sender_id INT NOT NULL,
    receiver_id INT NOT NULL,
    content TEXT NOT NULL,
    is_edited BOOLEAN DEFAULT FALSE,
    is_read BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sender_id) REFERENCES Users(id) ON DELETE CASCADE,
    FOREIGN KEY (receiver_id) REFERENCES Users(id) ON DELETE CASCADE
);

CREATE TABLE ActivityLogs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    action VARCHAR(255) NOT NULL,
    ip_address VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```
Налаштування та запуск
Згенеруйте пару ключів RSA за допомогою OpenSSL та покладіть private_key.pem у робочу папку сервера (а public_key.pem — у папку клієнта Unreal Engine):

Bash
```
openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in private_key.pem -out public_key.pem
```
Створіть файл config.json у кореневій папці сервера:
```json
JSON
{
    "master_key": "ВАШ_32_БАЙТНИЙ_МАЙСТЕР_КЛЮЧ_ДЛЯ_БД",
    "host": "tcp://127.0.0.1:3306",
    "user": "root",
    "password": "ПАРОЛЬ_ВІД_БД",
    "database": "messenger_db",
    "email_sender": "ваша_пошта@gmail.com",
    "email_password": "ПАРОЛЬ_ДОДАТКУ_GMAIL",
    "google_client_id": "ВАШ_CLIENT_ID.apps.googleusercontent.com",
    "google_client_secret": "ВАШ_CLIENT_SECRET"
}
```
Скомпілюйте проєкт у Visual Studio (конфігурація x64) із підключеними бібліотеками OpenSSL, MySQL Connector/C++ та libcurl.
