#include "Base64Wrapper.h"
#include "Util.h"

bool Base64Wrapper::isBase64Digit(const char c) {
	return isdigit(c) || isalpha(c) || c == '+' || c == '/' || c == '=';
}

size_t Base64Wrapper::lengthOfBytesInBase64(const size_t numOfBytes) {
	std::string s(numOfBytes, '0');
	return encode(s).length();
}

std::string Base64Wrapper::encode(const std::string& str)
{
	std::string encoded;
	CryptoPP::StringSource ss(str, true,
		new CryptoPP::Base64Encoder(
			new CryptoPP::StringSink(encoded)
		) // Base64Encoder
	); // StringSource

	return encoded;
}

std::string Base64Wrapper::decode(const std::string& str)
{
	std::string decoded;
	CryptoPP::StringSource ss(str, true,
		new CryptoPP::Base64Decoder(
			new CryptoPP::StringSink(decoded)
		) // Base64Decoder
	); // StringSource

	return decoded;
}
