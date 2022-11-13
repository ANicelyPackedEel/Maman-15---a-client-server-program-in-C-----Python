#pragma once

#include <string>
#include <base64.h>


class Base64Wrapper
{
public:
	static bool isBase64Digit(const char c);
	static size_t lengthOfBytesInBase64(const size_t numOfBytes);
	static std::string encode(const std::string& str);
	static std::string decode(const std::string& str);
};
