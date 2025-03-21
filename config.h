#ifndef CONFIG_H
#define CONFIG_H

#include <string>

// 配置结构体，保存所有配置信息
struct Config {
    std::string server;
    std::string username;
    std::string password;
    std::string host_name;
    std::string host_os;
    std::string host_ip;
    std::string PRIMARY_DNS;
    std::string dhcp_server;
    std::string mac;
    std::string CONTROLCHECKSTATUS;
    std::string ADAPTERNUM;
    std::string KEEP_ALIVE_VERSION;
    std::string AUTH_VERSION;
    std::string IPDOG;
    bool ror_version;
    std::string nic_name;
    bool IS_TEST;
    bool DEBUG;
    std::string LOG_PATH;
};

bool loadConfig(const std::string& filename, Config &config);

#endif // CONFIG_H
