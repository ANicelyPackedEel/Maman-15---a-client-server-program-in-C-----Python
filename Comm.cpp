#include "Comm.h"

using boost::asio::ip::tcp;

void sendReq(tcp::socket& s, const RequestHeader& r, const std::vector<uint8_t>& payload) //TODO: check for integer addition overflows
{
	//serialize
	unsigned long long* res = new unsigned long long;
	if (isAdditionOverflow(res, HEADER_SIZE, payload.size()))
		throw FatalException("Unexpected integer overflow");
	uint8_t* serialized = new uint8_t[HEADER_SIZE + payload.size()];

	//TODO: keep and continue endianess?
	//if (isBigEndian())
	//{
	//	if (isAdditionOverflow(res, *res,  (unsigned long long)serialized))
	//		throw FatalException("Unexpected integer overflow");
	//	std::vector<uint8_t> temp1(serialized, serialized + HEADER_SIZE);
	//	std::reverse(temp1.begin(), temp1.begin() + MAX_CLIENT_ID_LENGTH_IN_BYTES);
	//	std::reverse(temp1.begin() + MAX_CLIENT_ID_LENGTH_IN_BYTES + (sizeof(uint8_t) * 2), temp1.begin() + MAX_CLIENT_ID_LENGTH_IN_BYTES + (sizeof(uint8_t) * 2) + 2);
	//	std::reverse(temp1.end() - sizeof(uint32_t), temp1.end());

	//	if (r.getCode() == RequestCode::SendFile)
	//	{
	//		std::vector<uint8_t> temp2(serialized + HEADER_SIZE + 1, serialized + HEADER_SIZE + payload.size());
	//		std::reverse(temp2.begin() + MAX_CLIENT_ID_LENGTH_IN_BYTES + 1, temp2.begin() + MAX_CLIENT_ID_LENGTH_IN_BYTES + 1 + sizeof(uint32_t));

	//		temp1.insert(temp1.end(), temp2.begin(), temp2.end());
	//	}
	//	serialized = temp1.data();
	//}

	memcpy(serialized, &r, HEADER_SIZE);
	memcpy(serialized + HEADER_SIZE, &(payload[0]), payload.size());
	try { boost::asio::write(s, boost::asio::buffer(serialized, sizeof(serialized))); } //TODO: write using chunks as only size_t-1 (which can be 16bit) is the max size of buffer
	catch (...) { throw; }
}

void recvRes(tcp::socket& s, uint16_t& code, std::vector<uint8_t>& payload) //TODO: REMEMBER TO CHECK AND SORT ENDIANESS!!
{
	uint8_t versionBuf[sizeof(uint8_t)];
	uint8_t codeBuf[sizeof(uint16_t)];
	uint8_t payloadSizeBuf[sizeof(uint32_t)];

	std::array<boost::asio::mutable_buffer, 3> bufs =
	{
		boost::asio::buffer(versionBuf),
		boost::asio::buffer(codeBuf),
		boost::asio::buffer(payloadSizeBuf)
	};

	try {
		boost::asio::read(s, bufs); //Maximum value 7 (maximum bytes read)

		uint32_t payloadSize = payloadSizeBuf[0] | (payloadSizeBuf[1] << sizeof(uint8_t) * 1) | (payloadSizeBuf[2] << (sizeof(uint8_t) * 2)) | (payloadSizeBuf[3] << (sizeof(uint8_t) * 3));
		std::vector<uint8_t> payloadBuf(payloadSize, 0);

		boost::asio::read(s, boost::asio::buffer(payloadBuf));

		payload.assign(begin(payloadBuf), end(payloadBuf));
	}
	catch (...) { throw; }

	code = codeBuf[0] | (codeBuf[1] << sizeof(uint8_t) * 1);
}