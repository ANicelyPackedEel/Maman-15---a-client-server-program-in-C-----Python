#include "RequestHeader.h"

RequestHeader::RequestHeader(uint8_t* clientID, uint8_t version, uint16_t code, uint32_t payloadSize)
	: _version(version), _code(code), _payloadSize(payloadSize)
{
	for (int i = 0; i < MAX_CLIENT_ID_LENGTH_IN_BYTES; i++)
	{
		_clientID[i] = clientID[i];
	}
}

uint16_t RequestHeader::getCode() const
{
	return _code;
}