#include "Comm.h"
#include "FilesHandler.h"
#include "Util.h"
#include "RSAWrapper.h"
#include "AESWrapper.h"
#include "Base64Wrapper.h"
#include "crc.h"

using boost::asio::ip::tcp;
const int CHECKSUM_BUFFER_SIZE = 4096;

void run()
{
	//1. read from transfer.info
	std::string ip = "";
	std::string port = "";

	std::string userName = "";
	std::string filePath = "";
	std::string id = "";

	std::string publicKey = "";
	std::string privateKey = "";

	std::string aesKey = "";

	boost::asio::io_context io_context;
	tcp::socket s(io_context);

	//Read from transfer.info and me.info if exists
	bool meInfoExists;
	try
	{
		readFromTransferInfo(ip, port, userName, filePath);
		meInfoExists = readFromMeInfo(userName, id, privateKey);

		//Connect to server
		tcp::resolver resolver(io_context);
		boost::asio::connect(s, resolver.resolve(ip, port));
	}
	catch (const FatalException& e) { throw e; }
	catch (...) { throw; }

	//Get file name from path
	size_t nameStartInPath = filePath.find_last_of("/\\");
	std::string fileName = filePath;
	if (nameStartInPath != std::string::npos)
		fileName = filePath.substr(nameStartInPath + 1); //No integer overflow possible, file path in windows has a maximum length of 256 characters.

	//Create client id
	uint8_t* clientID = new uint8_t[MAX_CLIENT_ID_LENGTH_IN_BYTES]{ 0 };

	//RSA keys
	RSAPrivateWrapper wrap;
	Base64Wrapper b64;
	publicKey = wrap.getPublicKey();
	privateKey = wrap.getPrivateKey();
	std::string base64PrivateKey = b64.encode(privateKey);
	base64PrivateKey.erase(std::remove(base64PrivateKey.begin(), base64PrivateKey.end(), '\n'), base64PrivateKey.end()); //remove new line characters in encoded private keyss

	//Fill user name and file name to 255 bits with null characters
	userName.resize(MAX_NAME_LENGTH);
	fileName.resize(MAX_NAME_LENGTH);

	//Create request and response payload
	std::vector<uint8_t> reqPayload(userName.begin(), userName.end());
	std::vector<uint8_t> resPayload;
	uint16_t resCode;


	if (!meInfoExists) //Checks if me.info file not exists
	{
		//Create register request header
		RequestHeader* registerReq = new RequestHeader(clientID, CLIENT_VERSION, RequestCode::Register, reqPayload.size());
		try
		{
			// if server returned error, send register request up to 3 times
			int i = 0;
			do {
				if (i == RETRY_NUM)
					throw FatalException("Server responded with an error. Couldn't register: client name is already registered.");
				sendReq(s, *registerReq, reqPayload);
				recvRes(s, resCode, resPayload);
				i++;
			} while (resCode != ResponseCode::RegisterSuccess);
			//Create me.info file with client id from server
			std::string name = userName.substr(0, userName.find('\0'));
			createOrFixMeInfo(name, resPayload, base64PrivateKey);
		}
		catch (...) { throw; }
		delete registerReq;
	}
	try
	{
		if (meInfoExists)
		{
			//Converting client id from hex string to uint8_t pointer
			char temp[2] = { 0, 0 };
			if (id.size() % 2 != 0)
				id.insert(id.begin(), '0');
			for (unsigned int i = 0; i < id.size() - 1; i += 2)
			{
				temp[0] = id[i];
				temp[1] = id[i + 1];
				clientID[i / 2] = (uint8_t)strtol(temp, nullptr, 16);
			}
		}
		
		//send public key request
		reqPayload.insert(reqPayload.end(), publicKey.begin(), publicKey.end());
		RequestHeader* sendPublickKeyReq = new RequestHeader(clientID, CLIENT_VERSION, RequestCode::SendPubKey, reqPayload.size());
		sendReq(s, *sendPublickKeyReq, reqPayload);

		//receive aes key
		recvRes(s, resCode, resPayload);
		resPayload.erase(resPayload.begin(), resPayload.begin() + MAX_CLIENT_ID_LENGTH_IN_BYTES); //get only encrypted aes key (delete clientID)

		//Encrypy file
		aesKey = wrap.decrypt(std::string(resPayload.begin(), resPayload.end()));
		AESWrapper aesWrap(reinterpret_cast<const unsigned char*>(aesKey.c_str()), (unsigned int)aesKey.size());
		std::string fileContent = readFileIntoString(filePath);
		std::string encfileContent = aesWrap.encrypt(fileContent.c_str(), fileContent.size());

		//Calculate checksum
		CRC digest = CRC();
		unsigned char* buffer = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(fileContent.c_str()));

		typedef struct
		{
			unsigned char buf[CHECKSUM_BUFFER_SIZE];
		} readBlock;
		readBlock* start = (readBlock*)buffer;

		size_t quotient = std::floor(fileContent.size() / CHECKSUM_BUFFER_SIZE);
		int reminder = fileContent.size() % CHECKSUM_BUFFER_SIZE;
		int counter = 0;
		while (start->buf)
		{
			if (++counter >= quotient)
				break;
			digest.update(start->buf, CHECKSUM_BUFFER_SIZE);
			counter++;
			start++;
		}
		digest.update(buffer, reminder);
		uint32_t checksum = digest.digest();

		counter = 0;
		//send file up to 3 times until checksum is valid
		while (true)
		{
			//Add client id to payload
			reqPayload.assign(clientID, clientID + MAX_CLIENT_ID_LENGTH_IN_BYTES);

			//Serialize file size
			size_t fileSize = encfileContent.size();
			uint8_t* serializedFileSize = new uint8_t[sizeof(uint32_t)];
			memcpy(serializedFileSize, &fileSize, sizeof(uint32_t));
			//Add file size to payload
			reqPayload.insert(reqPayload.end(), serializedFileSize, serializedFileSize + sizeof(uint32_t));

			//Add file name to payload
			reqPayload.insert(reqPayload.end(), fileName.begin(), fileName.end());

			//Add encrypted file to payload
			reqPayload.insert(reqPayload.end(), encfileContent.begin(), encfileContent.end());

			//Send request
			RequestHeader* sendFileReq = new RequestHeader(clientID, CLIENT_VERSION, RequestCode::SendFile, reqPayload.size());
			sendReq(s, *sendFileReq, reqPayload);

			//Recieve response from server
			recvRes(s, resCode, resPayload);
			//Get checksum from responses
			resPayload.erase(resPayload.begin(), resPayload.begin() + MAX_CLIENT_ID_LENGTH_IN_BYTES + sizeof(uint32_t) + MAX_NAME_LENGTH);
			//Deserialize checksum
			uint32_t checksumFromServer = resPayload[0] | (resPayload[1] << 8 * 1) | (resPayload[2] << 8 * 2) | (resPayload[3] << 8 * 3);

			//Prepare payload for crc requests
			reqPayload.assign(clientID, clientID + MAX_CLIENT_ID_LENGTH_IN_BYTES);
			reqPayload.insert(reqPayload.end(), fileName.begin(), fileName.end());

			//Check checksum validity
			if (checksum == checksumFromServer)
			{
				//Send crc valid
				RequestHeader* sendCRCValid = new RequestHeader(clientID, CLIENT_VERSION, RequestCode::CRCValid, reqPayload.size());
				sendReq(s, *sendCRCValid, reqPayload);
				delete sendCRCValid;
				break;
			}
			else if (++counter >= RETRY_NUM)
			{
				//Send crc invalid, done
				RequestHeader* sendCRCInvalidDone = new RequestHeader(clientID, CLIENT_VERSION, RequestCode::CRCInvalidError, reqPayload.size());
				sendReq(s, *sendCRCInvalidDone, reqPayload);
				delete sendCRCInvalidDone;
				break;
			}

			//Send crc invalid, resending.
			RequestHeader* sendCRCInvalidResending = new RequestHeader(clientID, CLIENT_VERSION, RequestCode::CRCInvalidResend, reqPayload.size());
			sendReq(s, *sendCRCInvalidResending, reqPayload);
			delete sendCRCInvalidResending;

			delete[] serializedFileSize;
			delete sendFileReq;
		}
		delete sendPublickKeyReq;
	}
	catch (...) { throw; }
	delete[] clientID;

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