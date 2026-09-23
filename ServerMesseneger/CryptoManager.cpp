#include "CryptoManager.h"

CryptoManager::~CryptoManager()
{
	if (privateKey != nullptr) {
		EVP_PKEY_free(privateKey);
	}

}

bool CryptoManager::LoadPrivateKey(const std::string& filename)
{
	BIO* bio = BIO_new_file(filename.c_str(), "rb");
	if (bio == nullptr) {
		return false;
	}

	privateKey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
	BIO_free(bio);

	return privateKey != nullptr;
}

std::string CryptoManager::DecryptRSA(const std::string& encryptedBase64)
{
	std::string rawBytes = Base64Decode(encryptedBase64);
	if (rawBytes.empty()) {
		return "";
	}

	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(privateKey, nullptr);
	if (!ctx) return "";

	if (EVP_PKEY_decrypt_init(ctx) <= 0) {
		EVP_PKEY_CTX_free(ctx);
		return "";
	}

	EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);

	size_t outLen = 0;
	if (EVP_PKEY_decrypt(ctx, nullptr, &outLen, reinterpret_cast<const unsigned char*>(rawBytes.data()), rawBytes.length()) <= 0) {
		EVP_PKEY_CTX_free(ctx);
		return "";
	}

	std::vector<unsigned char> finale_result(outLen);
	if (EVP_PKEY_decrypt(ctx, finale_result.data(), &outLen, reinterpret_cast<const unsigned char*>(rawBytes.data()), rawBytes.length()) <= 0) {
		EVP_PKEY_CTX_free(ctx);
		return "";
	}

	EVP_PKEY_CTX_free(ctx);
	return std::string(reinterpret_cast<char*>(finale_result.data()), outLen);
}

std::string CryptoManager::EncryptAES(const std::string& rawData, const std::string& aesKey)
{
	unsigned char iv[16] = { 0 };

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (ctx == nullptr) {
		EVP_CIPHER_CTX_free(ctx);
		return "";
	}

	if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, reinterpret_cast<const unsigned char*>(aesKey.data()), iv) <= 0) {
		EVP_CIPHER_CTX_free(ctx);
		return "";
	}

	std::vector<unsigned char> decryptedText(rawData.length() + 16);
	int len1 = 0;

	if (EVP_EncryptUpdate(ctx, decryptedText.data(), &len1, reinterpret_cast<const unsigned char*>(rawData.data()), rawData.length()) <= 0) {
		EVP_CIPHER_CTX_free(ctx);
		return "";
	}

	int len2 = 0;
	if (EVP_EncryptFinal_ex(ctx, decryptedText.data() + len1, &len2) <= 0) {
		EVP_CIPHER_CTX_free(ctx);
		return "";
	}

	EVP_CIPHER_CTX_free(ctx);
	return std::string(reinterpret_cast<char*>(decryptedText.data()), len1 + len2);
}

std::string CryptoManager::DecryptAES(const std::string& encryptedData, const std::string& aesKey)
{
	
	unsigned char iv[16] = { 0 };

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (ctx == nullptr) {
		EVP_CIPHER_CTX_free(ctx);
		return "";
	}

	if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, reinterpret_cast<const unsigned char*>(aesKey.data()), iv) <= 0) {
		EVP_CIPHER_CTX_free(ctx);
		return "";
	}

	std::vector<unsigned char> decryptedText(encryptedData.length() + 16);
	int len1 = 0;

	if (EVP_DecryptUpdate(ctx, decryptedText.data(), &len1, reinterpret_cast<const unsigned char*>(encryptedData.data()), encryptedData.length()) <= 0) {
		EVP_CIPHER_CTX_free(ctx);
		return "";
	}

	int len2 = 0;
	if (EVP_DecryptFinal_ex(ctx, decryptedText.data() + len1, &len2) <= 0) {
		EVP_CIPHER_CTX_free(ctx);
		return "";
	}

	EVP_CIPHER_CTX_free(ctx);
	return std::string(reinterpret_cast<char*>(decryptedText.data()), len1 + len2);
}

CryptoManager::CryptoManager() : privateKey(nullptr)
{
}

std::string CryptoManager::Base64Decode(const std::string& input)
{
	if (input.empty()) return "";

	std::vector<unsigned char> decoded(input.length());
	int len = EVP_DecodeBlock(decoded.data(), reinterpret_cast<const unsigned char*>(input.data()), input.length());

	if (len == -1) return "";

	if (input.length() >= 2) {
		if (input[input.length() - 1] == '=' && input[input.length() - 2] == '=') {
			len -= 2;
		}
		else if (input[input.length() - 1] == '=') {
			len -= 1;
		}
	}

	return std::string(reinterpret_cast<char*>(decoded.data()), len);
}

std::string CryptoManager::Base64Encode(const std::string& input)
{
	if (input.empty()) return "";

	std::vector<unsigned char> encoded(((input.length() + 2) / 3) * 4 + 1);

	int len = EVP_EncodeBlock(encoded.data(), reinterpret_cast<const unsigned char*>(input.data()), input.length());

	return std::string(reinterpret_cast<char*>(encoded.data()), len);
}