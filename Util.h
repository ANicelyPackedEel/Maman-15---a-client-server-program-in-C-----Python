#pragma once
#include <string>

const int RETRY_NUM = 3;
const int CLIENT_VERSION = 3;
const int MAX_NAME_LENGTH = 255; //In bytes
const int MAX_NAME_LENGTH_TRANSER_FILE = 100; //In bytes
const int MAX_CLIENT_ID_LENGTH_IN_HEX = 32; //Maximum possible length of a hex string that could be a number that's representable in 16 bytes.
const int RSA_KEYS_LENGTH = 160; //In bytes

struct FatalException {
    std::string msg;
    FatalException(std::string msg) :msg(msg) {}
};

enum RequestCode {
    Register = 1000,
    SendPubKey = 1001,
    SendFile = 1103,
    CRCValid = 1104,
    CRCInvalidResend = 1105,
    CRCInvalidError = 1106
};

enum ResponseCode {
    RegisterSuccess = 2100,
    RegisterError = 2101,
    SendEncAESKey = 2102,
    FileRecieved = 2103,
    RequestRecieved = 2104
};

//void DecimalToHex(std::string& hexVal, int& decimalVal);
//int hexToDecimal(char hexVal);
//bool isMultiplicationOverflow(size_t* result, size_t a, size_t b);
bool isAdditionOverflow(unsigned long long* result, unsigned long long a, unsigned long long b);
//bool isBigEndian();