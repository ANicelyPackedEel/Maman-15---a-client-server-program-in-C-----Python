#include "Util.h"

//bool isMultiplicationOverflow(size_t* result, size_t a, size_t b)
//{
//    // Check if either of them is zero
//    if (a == 0 || b == 0)
//        return false;
//
//    *result = a * b;
//    if (a == *result / b)
//        return false;
//    else
//        return true;
//}

bool isAdditionOverflow(unsigned long long* result, unsigned long long a, unsigned long long b)
{
    *result = a + b;
    if (a > 0 && b > 0 && *result < 0)
        return true;
    if (a < 0 && b < 0 && *result > 0)
        return true;
    return false;
}

//bool isBigEndian()
//{
//    union {
//        uint32_t i;
//        uint8_t c[4];
//    } bint = { 0x01020304 };
//
//    return bint.c[0] == 1;
//}

//void DecimalToHex(std::string& hexVal, int& decimalVal)
//{
//    std::stringstream ss;
//    ss << std::hex << decimalVal;
//    std::string res(ss.str());
//    hexVal = res;
//}
//
//int hexToDecimal(char hexVal)
//{
//    std::stringstream ss;
//    ss << hexVal;
//    int decimalVal;
//    ss >> std::hex >> decimalVal;
//    return decimalVal;
//}
