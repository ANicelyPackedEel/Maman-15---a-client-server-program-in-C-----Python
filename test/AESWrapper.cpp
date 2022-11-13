#include "AESWrapper.h"

#include <modes.h>
#include <filters.h>

#include <stdexcept>
#include <immintrin.h>	// _rdrand32_step

bool AESWrapper::isValidKeyLength(unsigned int length) const
{
	if (length == 16 || length == 24 || length == 32) //If key length is valid for AES encryption - 128, 192 or 256 bits. //TODO מספרי קסם
		return true;
	return false;
}

unsigned char* AESWrapper::GenerateKey(unsigned char* buffer, unsigned int length)
{
	for (size_t i = 0; i < length; i += sizeof(unsigned int))
		_rdrand32_step(reinterpret_cast<unsigned int*>(&buffer[i]));
	return buffer;
}

const unsigned char* AESWrapper::getKey() const
{
	return m_key;
}

AESWrapper::AESWrapper()
{
	GenerateKey(m_key, DEFAULT_KEY_LENGTH);
}

AESWrapper::AESWrapper(unsigned int length)
{
	if (isValidKeyLength(length))
	{
		m_keyLength = length;
		GenerateKey(m_key, length);
	}
	else
		GenerateKey(m_key, DEFAULT_KEY_LENGTH);
}

AESWrapper::AESWrapper(const unsigned char* key, unsigned int length)
{
	if (!isValidKeyLength(length))
		throw std::length_error("key length must be 16, 24 or 32 bytses"); //TODO מספרי קסם
	m_keyLength = length;
	memcpy_s(m_key, m_keyLength, key, length);
}

AESWrapper::~AESWrapper()
{
}

std::string AESWrapper::encrypt(const char* plain, unsigned int length) const
{
	CryptoPP::AES::Encryption aesEncryption(m_key, m_keyLength);
	CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, m_iv);

	std::string cipher;
	CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink(cipher));
	stfEncryptor.Put(reinterpret_cast<const CryptoPP::byte*>(plain), length);
	stfEncryptor.MessageEnd();

	return cipher;
}


std::string AESWrapper::decrypt(const char* cipher, unsigned int length) const
{
	CryptoPP::AES::Decryption aesDecryption(m_key, m_keyLength);
	CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, m_iv);

	std::string decrypted;
	CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink(decrypted));
	stfDecryptor.Put(reinterpret_cast<const CryptoPP::byte*>(cipher), length);
	stfDecryptor.MessageEnd();

	return decrypted;
}