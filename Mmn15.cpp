#include "Comm.h"
#include "FilesHandler.h"
#include "Util.h"
#include "RSAWrapper.h"
#include "AESWrapper.h"
#include "crc.h"

using boost::asio::ip::tcp;

void run()
{
	//1. read from transfer.info
	std::string ip;
	std::string port;

	std::string userName;
	std::string filePath;
	std::string id;

	std::string publicKey;
	std::string privateKey;

	std::string aesKey;

	boost::asio::io_context io_context;
	tcp::socket s(io_context);

	//Read from transfer.info and me.info if exists
	bool meInfoExists;
	try
	{
		readFromTransferInfo(ip, port, userName, filePath);
		meInfoExists = readFromMeInfo(userName, id, privateKey);

		tcp::resolver resolver(io_context);
	}
	catch (const FatalException& e) { throw e; }
	catch (...) { throw; }

	//Converting client id form hex string to uint8_t pointer
	//{ move into readFromMe so 'id' will be uint8_t already
	uint8_t* clientID = new uint8_t[MAX_CLIENT_ID_LENGTH_IN_BYTES]{ 0 };
	char temp[2] = { 0, 0 };
	if (id.size() % 2 != 0)
		id.insert(id.begin(), '0');
	for (unsigned int i = 0; i < id.size() - 1; i += 2)
	{
		temp[0] = id[i];
		temp[1] = id[i + 1];
		clientID[i / 2] = (uint8_t)strtol(temp, nullptr, 16);
	}
	//}


	RSAPrivateWrapper wrap;
	publicKey = wrap.getPublicKey();
	privateKey = wrap.getPrivateKey();

	std::vector<uint8_t> reqPayload(userName.begin(), userName.end());
	std::vector<uint8_t> resPayload;
	uint16_t resCode;

	if (!meInfoExists) //Checks if me.info file not exists
	{
		RequestHeader* registerReq = new RequestHeader(clientID, CLIENT_VERSION, RequestCode::Register, reqPayload.size());
		try
		{
			int i = 0;
			do {
				if (i == RETRY_NUM)
					throw FatalException("Server responded with an error. Couldn't register: client name is already registered.");
				sendReq(s, *registerReq, reqPayload);
				recvRes(s, resCode, resPayload);
				i++;
			} while (resCode != ResponseCode::RegisterSuccess);

			createOrFixMeInfo(userName, resPayload, privateKey);
		}
		catch (...) { throw; }

	}
	try
	{
		//send public key
		reqPayload.insert(reqPayload.end(), publicKey.begin(), publicKey.end());
		RequestHeader* sendPublickKeyReq = new RequestHeader(clientID, CLIENT_VERSION, RequestCode::SendPubKey, reqPayload.size());
		sendReq(s, *sendPublickKeyReq, reqPayload);
		//if (resCode != ResponseCode::SendEncAESKey)
		//	throw FatalException("Didn't expect this response;"); //TODO: remove those comments

		//receive aes key
		recvRes(s, resCode, resPayload);
		resPayload.erase(resPayload.begin(), resPayload.begin() + MAX_CLIENT_ID_LENGTH_IN_BYTES); //get only encrypted aes key (delete clientID)

		//Encrypy file
		aesKey = wrap.decrypt(std::string(resPayload.begin(), resPayload.end()));
		AESWrapper aesWrap(reinterpret_cast<const unsigned char*>(aesKey.c_str()), (unsigned int)aesKey.size());
		std::string encfileContent = readFileIntoString(filePath);
		aesWrap.encrypt(encfileContent.c_str(), encfileContent.size());

		//Calculate checksum TODO: test it!!
		CRC digest = CRC();
		unsigned char* buffer = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(encfileContent.c_str()));

		typedef struct
		{
			unsigned char buf[4096]; //4096 bytes. Move 4096 to constant.
		} readBlock;
		readBlock* start = (readBlock*)buffer;

		size_t div = std::floor(encfileContent.size() / 4096);
		int left = encfileContent.size() % 4096;
		int counter = 0;
		while (start->buf)
		{
			if (++counter >= div)
				break;
			digest.update(start->buf, 4096);
			counter++;
			start++;
		}
		digest.update(buffer, left);
		uint32_t checksum = digest.digest();

		counter = 0;
		while (true)
		{
			//send file
			reqPayload.assign(id.begin(), id.end());
			//Serialize file size
			size_t fileSize = encfileContent.size();
			uint8_t* serializedFileSize = new uint8_t[sizeof(uint32_t)];
			memcpy(serializedFileSize, &fileSize, sizeof(uint32_t));
			reqPayload.insert(reqPayload.end(), serializedFileSize, serializedFileSize + sizeof(uint32_t));

			std::string fileName = filePath.substr(filePath.find_last_of("/\\") + 1); //No integer overflow possible, file path in windows has a maximum length of 256 characters.
			reqPayload.insert(reqPayload.end(), fileName.begin(), fileName.end()); //File name field is entire file path or just name? TODO: substr(last '\' - end);
			reqPayload.insert(reqPayload.end(), encfileContent.begin(), encfileContent.end());
			RequestHeader* sendFileReq = new RequestHeader(clientID, CLIENT_VERSION, RequestCode::SendFile, reqPayload.size());
			sendReq(s, *sendFileReq, reqPayload);

			//Recieve response from server
			recvRes(s, resCode, resPayload);
			resPayload.erase(resPayload.begin(), resPayload.begin() + MAX_CLIENT_ID_LENGTH_IN_BYTES + sizeof(uint32_t) + MAX_NAME_LENGTH);
			uint32_t checksumFromServer = resPayload[0] | (resPayload[1] << sizeof(uint8_t) * 1) | (resPayload[2] << (sizeof(uint8_t) * 2)) | (resPayload[3] << (sizeof(uint8_t) * 3));

			if (checksum == checksumFromServer)
			{
				//Send crc valid
				break;
			}
			else if (++counter >= RETRY_NUM)
			{
				//Send crc invalid, done
				break;
			}
			//Send crc invalid, resending
		}
	}
	catch (...) { throw; }
}

int main()
 {
	try { run(); }
	catch (const FatalException& e)
	{
		std::cout << e.msg << std::endl;
		exit(EXIT_FAILURE);
	}
	catch (...)
	{
		std::cout << "A Fatal error occurred, exiting." << std::endl;
		exit(EXIT_FAILURE);
	}
}