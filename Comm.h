#pragma once
#include <boost/asio.hpp>
#include "RequestHeader.h"
#include "Util.h"

void sendReq(boost::asio::ip::tcp::socket& s, const RequestHeader& r, const std::vector<uint8_t>& payload);
void recvRes(boost::asio::ip::tcp::socket& s, uint16_t& code, std::vector<uint8_t>& payload);