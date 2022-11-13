#pragma once
#include <cstdint>

const int HEADER_SIZE = 23; //In bytes.
const int MAX_CLIENT_ID_LENGTH_IN_BYTES = 16;

#pragma pack(push, 1)
class RequestHeader
{
	uint8_t _clientID[MAX_CLIENT_ID_LENGTH_IN_BYTES]; //16 bytes.
	uint8_t _version; //1 byte.
	uint16_t _code; //2 bytes.
	uint32_t _payloadSize; //4 bytes.
public:
	RequestHeader(uint8_t* clientID, uint8_t version, uint16_t code, uint32_t payloadSize);
	uint16_t getCode() const;
};

//
//union Serialize
//{
//	Request req;
//	uint8_t* serialized;
//	Serialize(const Request& r);
//	~Serialize();
//};
#pragma pack(pop)