#include "utils.h"
#include <openssl/md5.h>
#include <sstream>
#include <iomanip>
#include <cstdlib>

std::vector<unsigned char> md5sum(const std::vector<unsigned char>& data) {
    std::vector<unsigned char> digest(MD5_DIGEST_LENGTH);
    MD5(data.data(), data.size(), digest.data());
    return digest;
}

std::vector<unsigned char> dump(unsigned long long n) {
    std::stringstream ss;
    ss << std::hex << n;
    std::string s = ss.str();
    if (s.size() % 2 != 0) {
        s = "0" + s;
    }
    return hexToBytes(s);
}

std::vector<unsigned char> ror(const std::vector<unsigned char>& md5bytes, const std::string& pwd) {
    std::vector<unsigned char> ret;
    size_t len = pwd.size();
    ret.resize(len);
    for (size_t i = 0; i < len; i++) {
        unsigned char x = md5bytes[i] ^ static_cast<unsigned char>(pwd[i]);
        ret[i] = static_cast<unsigned char>(((x << 3) & 0xFF) + (x >> 5));
    }
    return ret;
}

std::vector<unsigned char> hexToBytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(std::strtol(byteString.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

std::string bytesToHex(const std::vector<unsigned char>& bytes) {
    std::stringstream ss;
    for (unsigned char byte : bytes) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    }
    return ss.str();
}
