#pragma once
#include "openssl/rsa.h"
#include "openssl/pem.h"
#include <string>
#include <fstream>
#include <vector>
#include <openssl/evp.h>
#include <openssl/bio.h>

class CryptoManager
{
public:
	CryptoManager();
	~CryptoManager();

	bool LoadPrivateKey(const std::string& filename);

	std::string DecryptRSA(const std::string& encryptedBase64);

	std::string EncryptAES(const std::string& rawData, const std::string& aesKey);
	std::string DecryptAES(const std::string& encryptedData, const std::string& aesKey);

	std::string Base64Decode(const std::string& input);
	std::string Base64Encode(const std::string& input);
private:
	EVP_PKEY* privateKey;
};

