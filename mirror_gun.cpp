// mirror_gun.cpp: определяет точку входа для приложения.
//

#include "mirror_gun.h"
#include <iostream>
#include <vector>
#include <string>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <openssl/sha.h>
using namespace std;
namespace fs = std::filesystem;

std::string calculateHash(const std::string& file_path) {
    std::ifstream file(file_path, std::ios::binary);
    if (!file) {
        std::cerr << "Error opening file: " << file_path << std::endl;
        return "";
    }

    SHA256_CTX sha256_context;
    SHA256_Init(&sha256_context);

    char buffer[1024];
    while (file.read(buffer, sizeof(buffer))) {
        SHA256_Update(&sha256_context, buffer, file.gcount());
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &sha256_context);

    std::stringstream hash_stream;
    hash_stream << std::hex << std::setfill('0');
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        hash_stream << std::setw(2) << static_cast<unsigned int>(hash[i]);
    }

    return hash_stream.str();
}
void traverseDirectory(const std::string& directory_path, std::vector<std::pair<std::string, std::string>>& hashes) {
    for (const auto& entry : fs::recursive_directory_iterator(directory_path)) {
        if (fs::is_regular_file(entry.path())) {
            std::string file_path = entry.path().string();
            std::string file_hash = calculateHash(file_path);
            if (!file_hash.empty()) {
                hashes.push_back(std::make_pair(file_path, file_hash));
            }
        }
    }
}
int main()
{
    std::string directory_path;
    std::cout << "Enter the directory path: ";
    std::cin >> directory_path;

    std::vector<std::pair<std::string, std::string>> hashes;
    traverseDirectory(directory_path, hashes);

    std::cout << "Hashes of files in the directory:" << std::endl;
    for (const auto& hash : hashes) {
        std::cout << hash.first << ": " << hash.second << std::endl;
    }
    std::ofstream file(fs::current_path().append(".bin"), std::ios::binary);
    if (!file) {
        std::cerr << "Error opening file: " << fs::current_path().append(".bin") << std::endl;
        return 0;
    }
    file.write((char*)hashes.data(), hashes.size());
    file.close();
	return 0;
}
