#pragma once
#include <string>
#include <aes.h>

class AESWrapper
{
public:
	static const unsigned int DEFAULT_KEY_LENGTH = 16; //In bytes
private:
	unsigned int m_keyLength = DEFAULT_KEY_LENGTH; //In bytes
	unsigned char m_key[DEFAULT_KEY_LENGTH];
	//The iv is a member variable so it will be easy to expand AES with a random iv generator if needed.
	CryptoPP::byte m_iv[CryptoPP::AES::BLOCKSIZE] = { 0 }; // for practical use iv should never be a fixed value!
	AESWrapper(const AESWrapper& AESWrapper);
	bool isValidKeyLength(unsigned int length) const;
public:
	AESWrapper();
	AESWrapper(unsigned int length);
	AESWrapper(const unsigned char* key, unsigned int size);
	~AESWrapper();
	const unsigned char* getKey() const;
	static unsigned char* GenerateKey(unsigned char* buffer, unsigned int length);
	std::string encrypt(const char* plain, unsigned int length) const;
	std::string decrypt(const char* cipher, unsigned int length) const;
};