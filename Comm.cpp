#include "Comm.h"

using boost::asio::ip::tcp;

void sendReq(tcp::socket& s, const RequestHeader& r, const std::vector<uint8_t>& payload)
{
	//serialize
	unsigned long long* res = new unsigned long long;
	if (isAdditionOverflow(res, HEADER_SIZE, payload.size()))
		throw FatalException("Unexpected integer overflow");
	std::vector<char> serialized(HEADER_SIZE + payload.size(), 0);

	memcpy(serialized.data(), &r, HEADER_SIZE);
	memcpy(serialized.data() + HEADER_SIZE, &(payload[0]), payload.size());

	auto a = boost::asio::buffer(serialized.data(), serialized.size());
	try { boost::asio::write(s, a); }
	catch (...) { throw; }
}

void recvRes(tcp::socket& s, uint16_t& code, std::vector<uint8_t>& payload)
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

		uint32_t payloadSize = payloadSizeBuf[0] | (payloadSizeBuf[1] << 8 * 1) | (payloadSizeBuf[2] << 8 * 2) | (payloadSizeBuf[3] << 8 * 3);
		std::vector<uint8_t> payloadBuf(payloadSize, 0);

		boost::asio::read(s, boost::asio::buffer(payloadBuf));

		payload.assign(begin(payloadBuf), end(payloadBuf));
	}
	catch (...) { throw; }

	code = codeBuf[0] | (codeBuf[1] << 8 * 1);
}