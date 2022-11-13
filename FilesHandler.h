#pragma once
#include <filesystem>

const std::filesystem::path ME_INFO_FILE_PATH = std::string("me.info");
const std::filesystem::path TRANSFER_INFO_FILE_PATH = std::string("transfer.info");

std::string readFileIntoString(const std::string& filePath);

void createOrFixMeInfo(const std::string& userName, const std::vector<uint8_t> clientID, const std::string& privateKey);

bool isMeInfoFileValidAndRead(std::ifstream& file, std::string& userName, std::string& id, std::string& privateKey);
bool isTransferInfoFileValidAndRead(std::ifstream& file, std::string& ip, std::string& port, std::string& userName, std::string& filePath);

void readFromTransferInfo(std::string& ip, std::string& port, std::string& userName, std::string& filePath);
bool readFromMeInfo(std::string& userName, std::string& id, std::string& privateKey);