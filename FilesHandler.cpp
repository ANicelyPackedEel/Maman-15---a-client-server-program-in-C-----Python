#include <fstream>
#include <boost/asio.hpp>
#include "FilesHandler.h"
#include "Util.h"
#include "Base64Wrapper.h"

std::string readFileIntoString(const std::string& filePath)
{
	std::string ret;
	std::ifstream inputFile(filePath, std::ios::binary);

	if (inputFile.fail())
		throw FatalException("Fatal error: Could'nt open file specified in transfer.info!");

	inputFile.seekg(0, std::ios::end);
	ret.reserve(inputFile.tellg());
	inputFile.seekg(0, std::ios::beg);

	ret.assign((std::istreambuf_iterator<char>(inputFile)),
		std::istreambuf_iterator<char>());
	return ret;
}

void createOrFixMeInfo(const std::string& userName, const std::vector<uint8_t> clientID, const std::string& privateKey)
{
	std::fstream meInfo;
	meInfo.open(ME_INFO_FILE_PATH, std::ios::out);

	meInfo << userName << std::endl;

	for (int i : clientID)
		meInfo << std::hex << std::setw(2) << std::setfill('0') << i;

	meInfo << std::endl << privateKey;
	meInfo.close();

	if (meInfo.fail())
		throw FatalException("Fatal error: Could'nt open me.info file!");
}

bool isMeInfoFileValidAndRead(std::ifstream& file, std::string& userName, std::string& id, std::string& privateKey)
{
	std::string _userName;
	std::string _id;
	std::string _privateKey;

	std::string line;

	std::getline(file, line);
	_userName = line;

	if (line.length() > MAX_NAME_LENGTH)
		return false;


	std::getline(file, line);
	_id = line;

	if (line.length() > MAX_CLIENT_ID_LENGTH_IN_HEX)
		return false;
	for (char& c : line)
	{
		if (!isxdigit(c))
			return false;
	}


	std::getline(file, line);
	_privateKey = line;


	for (char& c : line)
	{
		if (c == '=')
		if (!Base64Wrapper::isBase64Digit(c))
			return false;
	}

	size_t fEqualSignPos = line.find('=');
	if (fEqualSignPos != std::string::npos)
	{
		std::cout << line.at(line.size() - 2) << '\n';
		if ((fEqualSignPos != line.size() - 2) && (fEqualSignPos != line.size() - 1))
			return false;
		if ((fEqualSignPos == line.size() - 2) && (line.at(line.size() - 1)) != '=')
			return false;
	}

	userName = _userName;
	id = _id;
	privateKey = _privateKey;
	return true;
}

bool isTransferInfoFileValidAndRead(std::ifstream& file, std::string& ip, std::string& port, std::string& userName, std::string& filePath)
{
	std::string line;
	std::getline(file, line);

	size_t delimPos = line.find_last_of(':');
	if (delimPos == std::string::npos)
		return false;

	std::string _ip = line.substr(0, delimPos);
	unsigned long long res;
	unsigned long long* resP = &res;
	if (isAdditionOverflow(resP, delimPos, 1))
		return false;
	delimPos = res;
	std::string _port = line.substr(delimPos);

	if (_port.length() > 5) //5 - max length of port
		return false;

	for (char& c : _port)
	{
		if (!isdigit(c))
			return false;
	}

	try
	{
		long portNum = stol(_port);
		if (portNum > UINT16_MAX)
			return false;
	}
	catch (...) { return false; }
	port = _port;

	boost::system::error_code ec;
	boost::asio::ip::address::from_string(_ip, ec);
	if (ec)
		return false;
	ip = _ip;


	std::getline(file, line);
	if (line.length() > MAX_NAME_LENGTH_TRANSER_FILE || line.empty())
		return false;
	userName = line;

	std::getline(file, line);
	if (!std::filesystem::exists(line))
		return false;
	filePath = line;

	return true;
}

void readFromTransferInfo(std::string& ip, std::string& port, std::string& userName, std::string& filePath)
{
	if (!std::filesystem::exists(TRANSFER_INFO_FILE_PATH))
		throw FatalException(std::string("Fatal error: Could'nt find transfer.info file!"));

	std::ifstream tfInfo;
	tfInfo.open(TRANSFER_INFO_FILE_PATH, std::ios::in);

	if (!isTransferInfoFileValidAndRead(tfInfo, ip, port, userName, filePath))
		throw FatalException(std::string("Fatal error: transfer.info file is corrupted!"));

	if (tfInfo.fail())
		throw FatalException(std::string("Fatal error: Could'nt open transfer.info file!"));
}

bool readFromMeInfo(std::string& userName, std::string& id, std::string& privateKey)
{
	if (!std::filesystem::exists(ME_INFO_FILE_PATH))
		return false;

	std::ifstream meInfo;
	meInfo.open(ME_INFO_FILE_PATH, std::ios::in);

	if (!isMeInfoFileValidAndRead(meInfo, userName, id, privateKey))
		throw FatalException(std::string("Fatal error: me.info file is corrupted!"));

	if (meInfo.fail())
		throw FatalException(std::string("Fatal error: Could'nt open me.info file!"));

	return true;
}