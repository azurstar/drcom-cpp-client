#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <chrono>
#include <thread>
#include <stdexcept>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include "config.h"
#include "utils.h"

// 全局配置和 socket 对象
Config config;
int sockfd;
std::vector<unsigned char> SALT;
std::vector<unsigned char> AUTH_INFO;

std::string log_path;
bool DEBUG_MODE = false;

// 简单日志函数：输出到控制台及（若开启）写入日志文件
void logMessage(const std::string &msg) {
    std::cout << msg << std::endl;
    if (DEBUG_MODE) {
        std::ofstream ofs(log_path, std::ios::app);
        ofs << msg << std::endl;
    }
}

// 如果配置中指定了网卡名称，则绑定对应网卡，返回 IP 地址（仅限 Unix 系统）
std::string bind_nic(const std::string &nic_name) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        logMessage("Socket creation failed for NIC binding.");
        return "0.0.0.0";
    }
    struct ifreq ifr;
    std::strncpy(ifr.ifr_name, nic_name.c_str(), IFNAMSIZ-1);
    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        logMessage(nic_name + " is unacceptable!");
        close(fd);
        return "0.0.0.0";
    }
    close(fd);
    struct sockaddr_in* ipaddr = (struct sockaddr_in*)&ifr.ifr_addr;
    return inet_ntoa(ipaddr->sin_addr);
}

// challenge 函数：向认证服务器发送挑战数据包，返回接收到的 salt（数据[4:8]）
std::vector<unsigned char> challenge(const std::string &svr, unsigned int ran) {
    // 构造 challenge 数据包：b"\x01\x02" + t(2字节，小端) + b"\x09" + 15 个 0
    std::vector<unsigned char> challengePacket = {0x01, 0x02};
    uint16_t t = ran % 0xFFFF;
    challengePacket.push_back(t & 0xFF);
    challengePacket.push_back((t >> 8) & 0xFF);
    challengePacket.push_back(0x09);
    for (int i = 0; i < 15; i++) {
        challengePacket.push_back(0x00);
    }
    
    struct sockaddr_in svr_addr;
    std::memset(&svr_addr, 0, sizeof(svr_addr));
    svr_addr.sin_family = AF_INET;
    svr_addr.sin_port = htons(61440);
    inet_pton(AF_INET, svr.c_str(), &svr_addr.sin_addr);
    
    while (true) {
        sendto(sockfd, challengePacket.data(), challengePacket.size(), 0,
               (struct sockaddr*)&svr_addr, sizeof(svr_addr));
        unsigned char buffer[1024];
        int n = recvfrom(sockfd, buffer, sizeof(buffer), 0, nullptr, nullptr);
        if (n < 0) {
            logMessage("[challenge] timeout, retrying...");
            std::this_thread::sleep_for(std::chrono::seconds(1));
            continue;
        }
        logMessage("[challenge] recv: " + bytesToHex(std::vector<unsigned char>(buffer, buffer+n)));
        if (buffer[0] != 0x02)
            throw std::runtime_error("ChallengeException");
        if(n >= 8)
            return std::vector<unsigned char>(buffer+4, buffer+8);
        else
            throw std::runtime_error("Invalid challenge packet");
    }
}

// 构造 keep-alive 数据包
std::vector<unsigned char> keep_alive_package_builder(unsigned char number,
                                                      const std::vector<unsigned char>& randomBytes,
                                                      const std::vector<unsigned char>& tail,
                                                      int type = 1,
                                                      bool first = false) {
    std::vector<unsigned char> data;
    data.push_back(0x07);
    data.push_back(number);
    data.push_back(0x28);
    data.push_back(0x00);
    data.push_back(0x0B);
    data.push_back(static_cast<unsigned char>(type));
    if (first) {
        data.push_back(0x0F);
        data.push_back(0x27);
    } else {
        // 从配置中读取 KEEP_ALIVE_VERSION（十六进制字符串转字节数组）
        std::vector<unsigned char> kv = hexToBytes(config.KEEP_ALIVE_VERSION);
        data.insert(data.end(), kv.begin(), kv.end());
    }
    data.push_back(0x2F);
    data.push_back(0x12);
    for (int i = 0; i < 6; i++) {
        data.push_back(0x00);
    }
    data.insert(data.end(), tail.begin(), tail.end());
    for (int i = 0; i < 4; i++) {
        data.push_back(0x00);
    }
    if (type == 3) {
        // 添加 host_ip（形如 x.x.x.x）
        std::istringstream iss(config.host_ip);
        std::string token;
        while (std::getline(iss, token, '.')) {
            data.push_back(static_cast<unsigned char>(std::stoi(token)));
        }
        // CRC 字段填 4 个 0
        for (int i = 0; i < 4; i++) data.push_back(0x00);
        // 再填 8 个 0
        for (int i = 0; i < 8; i++) data.push_back(0x00);
    } else {
        // type == 1 时补 16 个 0
        for (int i = 0; i < 16; i++) data.push_back(0x00);
    }
    return data;
}

// 计算 checksum：参照 Python 代码逻辑
std::vector<unsigned char> checksum(const std::vector<unsigned char>& s) {
    unsigned int ret = 1234;
    size_t len = s.size();
    for (size_t i = 0; i < ((len + 3) / 4); i++) {
        unsigned int chunk = 0;
        for (size_t j = 0; j < 4; j++) {
            size_t index = i*4 + j;
            unsigned char byte = (index < len) ? s[index] : 0;
            chunk |= (byte << (j*8));
        }
        ret ^= chunk;
    }
    ret = (1968 * ret) & 0xffffffff;
    std::vector<unsigned char> out(4);
    out[0] = ret & 0xFF;
    out[1] = (ret >> 8) & 0xFF;
    out[2] = (ret >> 16) & 0xFF;
    out[3] = (ret >> 24) & 0xFF;
    return out;
}

// 构造认证数据包，参照原 Python 代码中的 mkpkt()
std::vector<unsigned char> mkpkt(const std::vector<unsigned char>& salt,
                                 const std::string& usr,
                                 const std::string& pwd,
                                 unsigned long long mac_val) {
    std::vector<unsigned char> data;
    // 固定头部： b'\x03\x01\x00'
    data.push_back(0x03);
    data.push_back(0x01);
    data.push_back(0x00);
    data.push_back(static_cast<unsigned char>(usr.size() + 20));
    
    // md5sum(b'\x03\x01' + salt + pwd)
    std::vector<unsigned char> md5_input = {0x03, 0x01};
    md5_input.insert(md5_input.end(), salt.begin(), salt.end());
    md5_input.insert(md5_input.end(), pwd.begin(), pwd.end());
    std::vector<unsigned char> md5_1 = md5sum(md5_input);
    data.insert(data.end(), md5_1.begin(), md5_1.end());
    
    // 用户名（不足 36 字节用 0 填充）
    std::vector<unsigned char> usr_bytes(36, 0);
    std::copy(usr.begin(), usr.end(), usr_bytes.begin());
    data.insert(data.end(), usr_bytes.begin(), usr_bytes.end());
    
    // CONTROLCHECKSTATUS 与 ADAPTERNUM
    std::vector<unsigned char> cc = hexToBytes(config.CONTROLCHECKSTATUS);
    data.insert(data.end(), cc.begin(), cc.end());
    std::vector<unsigned char> an = hexToBytes(config.ADAPTERNUM);
    data.insert(data.end(), an.begin(), an.end());
    
    // 计算 data[4:10] 与 mac 的异或，并取最后 6 字节
    std::vector<unsigned char> slice(data.begin()+4, data.begin()+10);
    unsigned long long slice_val = 0;
    for (unsigned char b : slice) {
        slice_val = (slice_val << 8) | b;
    }
    unsigned long long xor_val = slice_val ^ mac_val;
    std::vector<unsigned char> mac_bytes = dump(xor_val);
    if (mac_bytes.size() > 6)
        mac_bytes = std::vector<unsigned char>(mac_bytes.end()-6, mac_bytes.end());
    data.insert(data.end(), mac_bytes.begin(), mac_bytes.end());
    
    // md5sum(b'\x01' + pwd + salt + 4*'\x00')
    std::vector<unsigned char> md5_input2 = {0x01};
    md5_input2.insert(md5_input2.end(), pwd.begin(), pwd.end());
    md5_input2.insert(md5_input2.end(), salt.begin(), salt.end());
    for (int i = 0; i < 4; i++) md5_input2.push_back(0x00);
    std::vector<unsigned char> md5_2 = md5sum(md5_input2);
    data.insert(data.end(), md5_2.begin(), md5_2.end());
    
    // 写入 IP 数量（1）及 host_ip
    data.push_back(0x01);
    std::istringstream iss(config.host_ip);
    std::string token;
    while (std::getline(iss, token, '.')) {
        data.push_back(static_cast<unsigned char>(std::stoi(token)));
    }
    // 补充后面 3 个 IP 地址均为 0（每个 4 字节）
    for (int i = 0; i < 3; i++)
        for (int j = 0; j < 4; j++)
            data.push_back(0x00);
    
    // md5sum(data + b'\x14\x00\x07\x0B') 取前 8 字节
    std::vector<unsigned char> md5_input3 = data;
    md5_input3.insert(md5_input3.end(), {0x14, 0x00, 0x07, 0x0B});
    std::vector<unsigned char> md5_3 = md5sum(md5_input3);
    data.insert(data.end(), md5_3.begin(), md5_3.begin()+8);
    
    // IPDOG 与 4 字节未知字段
    std::vector<unsigned char> ipdog = hexToBytes(config.IPDOG);
    data.insert(data.end(), ipdog.begin(), ipdog.end());
    for (int i = 0; i < 4; i++) data.push_back(0x00);
    
    // _tagHostInfo.HostName (32 字节)
    std::vector<unsigned char> hostname_bytes(32, 0);
    std::copy(config.host_name.begin(), config.host_name.end(), hostname_bytes.begin());
    data.insert(data.end(), hostname_bytes.begin(), hostname_bytes.end());
    
    // PRIMARY_DNS 与 dhcp_server（各 4 字节）
    std::istringstream iss_dns(config.PRIMARY_DNS);
    while (std::getline(iss_dns, token, '.'))
        data.push_back(static_cast<unsigned char>(std::stoi(token)));
    std::istringstream iss_dhcp(config.dhcp_server);
    while (std::getline(iss_dhcp, token, '.'))
        data.push_back(static_cast<unsigned char>(std::stoi(token)));
    // DNSIP2、WINSIP1、WINSIP2 各 4 字节均填 0
    for (int i = 0; i < 4*3; i++) data.push_back(0x00);
    
    // OSVersionInfo：各字段固定写入
    unsigned char osInfo[4] = {0x94, 0x00, 0x00, 0x00};
    data.insert(data.end(), osInfo, osInfo+4);
    unsigned char major[4] = {0x05, 0x00, 0x00, 0x00};
    data.insert(data.end(), major, major+4);
    unsigned char minor[4] = {0x01, 0x00, 0x00, 0x00};
    data.insert(data.end(), minor, minor+4);
    unsigned char build[4] = {0x28, 0x0A, 0x00, 0x00};
    data.insert(data.end(), build, build+4);
    unsigned char platform[4] = {0x02, 0x00, 0x00, 0x00};
    data.insert(data.end(), platform, platform+4);
    // ServicePack： host_os 字符串补 32 字节
    std::vector<unsigned char> hostos_bytes(32, 0);
    std::copy(config.host_os.begin(), config.host_os.end(), hostos_bytes.begin());
    data.insert(data.end(), hostos_bytes.begin(), hostos_bytes.end());
    // 再填 96 个 0
    for (int i = 0; i < 96; i++) data.push_back(0x00);
    
    // AUTH_VERSION
    std::vector<unsigned char> auth_ver = hexToBytes(config.AUTH_VERSION);
    data.insert(data.end(), auth_ver.begin(), auth_ver.end());
    
    if (config.ror_version) {
        // 若使用 ror 版本，写入 LDAPAuth 结构
        data.push_back(0x00);
        data.push_back(static_cast<unsigned char>(pwd.size()));
        std::vector<unsigned char> md5_input4 = {0x03, 0x01};
        md5_input4.insert(md5_input4.end(), salt.begin(), salt.end());
        md5_input4.insert(md5_input4.end(), pwd.begin(), pwd.end());
        std::vector<unsigned char> md5_for_ror = md5sum(md5_input4);
        std::vector<unsigned char> ror_result = ror(md5_for_ror, pwd);
        data.insert(data.end(), ror_result.begin(), ror_result.end());
    }
    
    // _tagDrcomAuthExtData： Code、Len
    data.push_back(0x02);
    data.push_back(0x0C);
    // CRC：对 (data + 固定字段 + dump(mac)) 计算 checksum
    std::vector<unsigned char> crc_input = data;
    crc_input.insert(crc_input.end(), {0x01, 0x26, 0x07, 0x11, 0x00, 0x00});
    // 将 config.mac 转换为数值后 dump
    unsigned long long mac_num = 0;
    {
        std::vector<unsigned char> macBytes = hexToBytes(config.mac);
        for (unsigned char b : macBytes) {
            mac_num = (mac_num << 8) | b;
        }
    }
    std::vector<unsigned char> mac_dump = dump(mac_num);
    crc_input.insert(crc_input.end(), mac_dump.begin(), mac_dump.end());
    std::vector<unsigned char> crc_val = checksum(crc_input);
    data.insert(data.end(), crc_val.begin(), crc_val.end());
    // Option 两字节 0
    data.push_back(0x00); data.push_back(0x00);
    // AdapterAddress: dump(mac)
    data.insert(data.end(), mac_dump.begin(), mac_dump.end());
    // auto logout、broadcast mode、unknown (0xE9 0x13)
    data.push_back(0x00);
    data.push_back(0x00);
    data.push_back(0xE9);
    data.push_back(0x13);
    
    logMessage("[mkpkt] " + bytesToHex(data));
    return data;
}

// login 过程
std::vector<unsigned char> login(const std::string& usr, const std::string& pwd, const std::string& svr) {
    int attempts = 0;
    while (true) {
        unsigned int rand_val = std::rand() % 0xFFFF + std::rand() % 0xFF;
        std::vector<unsigned char> salt = challenge(svr, rand_val);
        SALT = salt;
        // 将 config.mac 转换为数值
        unsigned long long mac_num = 0;
        {
            std::vector<unsigned char> macBytes = hexToBytes(config.mac);
            for (unsigned char b : macBytes)
                mac_num = (mac_num << 8) | b;
        }
        std::vector<unsigned char> packet = mkpkt(salt, usr, pwd, mac_num);
        logMessage("[login] send " + bytesToHex(packet));
        
        struct sockaddr_in svr_addr;
        std::memset(&svr_addr, 0, sizeof(svr_addr));
        svr_addr.sin_family = AF_INET;
        svr_addr.sin_port = htons(61440);
        inet_pton(AF_INET, svr.c_str(), &svr_addr.sin_addr);
        
        sendto(sockfd, packet.data(), packet.size(), 0, (struct sockaddr*)&svr_addr, sizeof(svr_addr));
        unsigned char buffer[1024];
        int n = recvfrom(sockfd, buffer, sizeof(buffer), 0, nullptr, nullptr);
        if (n < 0) continue;
        logMessage("[login] recv " + bytesToHex(std::vector<unsigned char>(buffer, buffer+n)));
        if (buffer[0] == 0x04) {
            logMessage("[login] logged in");
            AUTH_INFO = std::vector<unsigned char>(buffer+23, buffer+39);
            return AUTH_INFO;
        } else {
            logMessage("[login] login failed.");
            if (config.IS_TEST)
                std::this_thread::sleep_for(std::chrono::seconds(3));
            else
                std::this_thread::sleep_for(std::chrono::seconds(30));
            attempts++;
            if (attempts >= 5)
                exit(1);
        }
    }
}

// logout 过程
void logout(const std::string& usr, const std::string& pwd, const std::string& svr,
            unsigned long long mac_val, const std::vector<unsigned char>& auth_info) {
    std::vector<unsigned char> salt = challenge(svr, std::time(nullptr) + std::rand()%0xFF);
    if (!salt.empty()) {
        std::vector<unsigned char> data;
        data.push_back(0x06);
        data.push_back(0x01);
        data.push_back(0x00);
        data.push_back(static_cast<unsigned char>(usr.size() + 20));
        std::vector<unsigned char> md5_input = {0x03, 0x01};
        md5_input.insert(md5_input.end(), salt.begin(), salt.end());
        md5_input.insert(md5_input.end(), pwd.begin(), pwd.end());
        std::vector<unsigned char> md5_1 = md5sum(md5_input);
        data.insert(data.end(), md5_1.begin(), md5_1.end());
        std::vector<unsigned char> usr_bytes(36, 0);
        std::copy(usr.begin(), usr.end(), usr_bytes.begin());
        data.insert(data.end(), usr_bytes.begin(), usr_bytes.end());
        std::vector<unsigned char> cc = hexToBytes(config.CONTROLCHECKSTATUS);
        data.insert(data.end(), cc.begin(), cc.end());
        std::vector<unsigned char> an = hexToBytes(config.ADAPTERNUM);
        data.insert(data.end(), an.begin(), an.end());
        std::vector<unsigned char> slice(data.begin()+4, data.begin()+10);
        unsigned long long slice_val = 0;
        for (unsigned char b : slice)
            slice_val = (slice_val << 8) | b;
        unsigned long long xor_val = slice_val ^ mac_val;
        std::vector<unsigned char> mac_bytes = dump(xor_val);
        if (mac_bytes.size() > 6)
            mac_bytes = std::vector<unsigned char>(mac_bytes.end()-6, mac_bytes.end());
        data.insert(data.end(), mac_bytes.begin(), mac_bytes.end());
        data.insert(data.end(), auth_info.begin(), auth_info.end());
        
        struct sockaddr_in svr_addr;
        std::memset(&svr_addr, 0, sizeof(svr_addr));
        svr_addr.sin_family = AF_INET;
        svr_addr.sin_port = htons(61440);
        inet_pton(AF_INET, svr.c_str(), &svr_addr.sin_addr);
        
        sendto(sockfd, data.data(), data.size(), 0, (struct sockaddr*)&svr_addr, sizeof(svr_addr));
        unsigned char buffer[1024];
        int n = recvfrom(sockfd, buffer, sizeof(buffer), 0, nullptr, nullptr);
        if (n > 0 && buffer[0] == 0x04)
            logMessage("[logout] logged out.");
    }
}

// keep_alive1：发送第一个保活包
void keep_alive1(const std::vector<unsigned char>& salt, const std::vector<unsigned char>& tail,
                 const std::string& pwd, const std::string& svr) {
    uint16_t time_val = std::time(nullptr) % 0xFFFF;
    std::vector<unsigned char> foo = { static_cast<unsigned char>(time_val & 0xFF),
                                        static_cast<unsigned char>((time_val >> 8) & 0xFF) };
    std::vector<unsigned char> data;
    data.push_back(0xff);
    std::vector<unsigned char> md5_input = {0x03, 0x01};
    md5_input.insert(md5_input.end(), salt.begin(), salt.end());
    md5_input.insert(md5_input.end(), pwd.begin(), pwd.end());
    std::vector<unsigned char> md5_val = md5sum(md5_input);
    data.insert(data.end(), md5_val.begin(), md5_val.end());
    for (int i = 0; i < 3; i++) data.push_back(0x00);
    data.insert(data.end(), tail.begin(), tail.end());
    data.insert(data.end(), foo.begin(), foo.end());
    for (int i = 0; i < 4; i++) data.push_back(0x00);
    logMessage("[keep_alive1] send " + bytesToHex(data));
    
    struct sockaddr_in svr_addr;
    std::memset(&svr_addr, 0, sizeof(svr_addr));
    svr_addr.sin_family = AF_INET;
    svr_addr.sin_port = htons(61440);
    inet_pton(AF_INET, svr.c_str(), &svr_addr.sin_addr);
    sendto(sockfd, data.data(), data.size(), 0, (struct sockaddr*)&svr_addr, sizeof(svr_addr));
    unsigned char buffer[1024];
    int n = recvfrom(sockfd, buffer, sizeof(buffer), 0, nullptr, nullptr);
    if (n > 0 && buffer[0] == 0x07)
        logMessage("[keep_alive1] recv " + bytesToHex(std::vector<unsigned char>(buffer, buffer+n)));
    else
        logMessage("[keep_alive1] unexpected response");
}

// 清空 socket 缓冲区
void empty_socket_buffer() {
    logMessage("Starting to empty socket buffer");
    unsigned char buffer[1024];
    while (true) {
        int n = recvfrom(sockfd, buffer, sizeof(buffer), MSG_DONTWAIT, nullptr, nullptr);
        if (n <= 0) break;
        logMessage("Received unexpected: " + bytesToHex(std::vector<unsigned char>(buffer, buffer+n)));
    }
    logMessage("Socket buffer emptied");
}

// 简化的 keep_alive2 实现
void keep_alive2(const std::vector<unsigned char>& salt, const std::vector<unsigned char>& package_tail,
                 const std::string& pwd, const std::string& svr) {
    unsigned char svr_num = 0;
    unsigned int rand_val = std::rand() % 0xFFFF;
    rand_val += std::rand() % 10 + 1;
    std::vector<unsigned char> packet = keep_alive_package_builder(svr_num, dump(rand_val), std::vector<unsigned char>(4,0), 1, true);
    
    struct sockaddr_in svr_addr;
    std::memset(&svr_addr, 0, sizeof(svr_addr));
    svr_addr.sin_family = AF_INET;
    svr_addr.sin_port = htons(61440);
    inet_pton(AF_INET, svr.c_str(), &svr_addr.sin_addr);
    
    while (true) {
        logMessage("[keep_alive2] send1 " + bytesToHex(packet));
        sendto(sockfd, packet.data(), packet.size(), 0, (struct sockaddr*)&svr_addr, sizeof(svr_addr));
        unsigned char buffer[1024];
        int n = recvfrom(sockfd, buffer, sizeof(buffer), 0, nullptr, nullptr);
        if(n > 0) {
            std::vector<unsigned char> recv_data(buffer, buffer+n);
            logMessage("[keep_alive2] recv1 " + bytesToHex(recv_data));
            if ((recv_data[0] == 0x07 && recv_data[1] == 0x00) ||
                (recv_data[0] == 0x07 && recv_data[1] == svr_num && recv_data[2] == 0x28 && recv_data[3] == 0x00))
                break;
            else if (recv_data[0] == 0x07 && recv_data[2] == 0x10) {
                logMessage("[keep_alive2] recv file, resending..");
                svr_num++;
                break;
            } else {
                logMessage("[keep_alive2] unexpected " + bytesToHex(recv_data));
            }
        }
    }
    rand_val += std::rand() % 10 + 1;
    packet = keep_alive_package_builder(svr_num, dump(rand_val), std::vector<unsigned char>(4,0), 1, false);
    logMessage("[keep_alive2] send2 " + bytesToHex(packet));
    sendto(sockfd, packet.data(), packet.size(), 0, (struct sockaddr*)&svr_addr, sizeof(svr_addr));
    unsigned char buffer[1024];
    int n = recvfrom(sockfd, buffer, sizeof(buffer), 0, nullptr, nullptr);
    if(n > 0) svr_num++;
    std::vector<unsigned char> tail(buffer+16, buffer+20);
    rand_val += std::rand() % 10 + 1;
    packet = keep_alive_package_builder(svr_num, dump(rand_val), tail, 3, false);
    logMessage("[keep_alive2] send3 " + bytesToHex(packet));
    sendto(sockfd, packet.data(), packet.size(), 0, (struct sockaddr*)&svr_addr, sizeof(svr_addr));
    n = recvfrom(sockfd, buffer, sizeof(buffer), 0, nullptr, nullptr);
    if(n > 0) {
        svr_num++;
        tail = std::vector<unsigned char>(buffer+16, buffer+20);
    }
    logMessage("[keep_alive2] keep-alive2 loop in daemon.");
    unsigned char i = svr_num;
    while (true) {
        try {
            std::this_thread::sleep_for(std::chrono::seconds(20));
            keep_alive1(salt, tail, pwd, svr);
            rand_val += std::rand() % 10 + 1;
            packet = keep_alive_package_builder(i, dump(rand_val), tail, 1, false);
            logMessage("[keep_alive2] send " + std::to_string(i) + " " + bytesToHex(packet));
            sendto(sockfd, packet.data(), packet.size(), 0, (struct sockaddr*)&svr_addr, sizeof(svr_addr));
            n = recvfrom(sockfd, buffer, sizeof(buffer), 0, nullptr, nullptr);
            tail = std::vector<unsigned char>(buffer+16, buffer+20);
            rand_val += std::rand() % 10 + 1;
            packet = keep_alive_package_builder(i+1, dump(rand_val), tail, 3, false);
            sendto(sockfd, packet.data(), packet.size(), 0, (struct sockaddr*)&svr_addr, sizeof(svr_addr));
            logMessage("[keep_alive2] send " + std::to_string(i+1) + " " + bytesToHex(packet));
            n = recvfrom(sockfd, buffer, sizeof(buffer), 0, nullptr, nullptr);
            tail = std::vector<unsigned char>(buffer+16, buffer+20);
            i = (i+2) % 127;
        } catch (...) {
            // 忽略异常
        }
    }
}

// 简单守护进程化（写入 pid 文件）
void daemonize() {
    std::ofstream pidFile("/var/run/jludrcom.pid");
    if(pidFile.is_open()){
        pidFile << getpid();
        pidFile.close();
    }
}

int main() {
    std::srand(std::time(nullptr));
    if (!loadConfig("config.yaml", config)) {
        return 1;
    }
    DEBUG_MODE = config.DEBUG;
    log_path = config.LOG_PATH;
    
    if (remove(log_path.c_str()) == 0) {
        std::cout << "旧日志删除成功" << std::endl;
    } else {
        perror("旧日志删除失败");
    }
    std::string bind_ip = "0.0.0.0";
    if (!config.nic_name.empty())
        bind_ip = bind_nic(config.nic_name);
    
    // 创建 UDP socket 并绑定到端口 61440
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        logMessage("Socket creation failed.");
        return 1;
    }
    struct sockaddr_in local_addr;
    std::memset(&local_addr, 0, sizeof(local_addr));
    local_addr.sin_family = AF_INET;
    local_addr.sin_port = htons(61440);
    inet_pton(AF_INET, bind_ip.c_str(), &local_addr.sin_addr);
    if (bind(sockfd, (struct sockaddr*)&local_addr, sizeof(local_addr)) < 0) {
        logMessage("Bind failed.");
        return 1;
    }
    // 设置接收超时为 3 秒
    struct timeval tv;
    tv.tv_sec = 3;
    tv.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
    
    if (!config.IS_TEST) {
        daemonize();
        // 可根据需要加载额外配置（例如 /etc/drcom.conf）
    }
    logMessage("auth svr: " + config.server + "\nusername: " + config.username +
               "\npassword: " + config.password + "\nmac: " + config.mac);
    logMessage("bind ip: " + bind_ip);
    
    while (true) {
        try {
            std::vector<unsigned char> package_tail = login(config.username, config.password, config.server);
            logMessage("package_tail: " + bytesToHex(package_tail));
            empty_socket_buffer();
            keep_alive1(SALT, package_tail, config.password, config.server);
            keep_alive2(SALT, package_tail, config.password, config.server);
        } catch (const std::exception &e) {
            logMessage(std::string("Exception: ") + e.what());
            continue;
        }
    }
    close(sockfd);
    return 0;
}
