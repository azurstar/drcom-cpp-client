#include "config.h"
#include <yaml-cpp/yaml.h>
#include <iostream>

bool loadConfig(const std::string& filename, Config &config) {
    try {
        YAML::Node node = YAML::LoadFile(filename);
        config.server = node["server"].as<std::string>();
        config.username = node["username"].as<std::string>();
        config.password = node["password"].as<std::string>();
        config.host_name = node["host_name"].as<std::string>();
        config.host_os = node["host_os"].as<std::string>();
        config.host_ip = node["host_ip"].as<std::string>();
        config.PRIMARY_DNS = node["PRIMARY_DNS"].as<std::string>();
        config.dhcp_server = node["dhcp_server"].as<std::string>();
        config.mac = node["mac"].as<std::string>();
        config.CONTROLCHECKSTATUS = node["CONTROLCHECKSTATUS"].as<std::string>();
        config.ADAPTERNUM = node["ADAPTERNUM"].as<std::string>();
        config.KEEP_ALIVE_VERSION = node["KEEP_ALIVE_VERSION"].as<std::string>();
        config.AUTH_VERSION = node["AUTH_VERSION"].as<std::string>();
        config.IPDOG = node["IPDOG"].as<std::string>();
        config.ror_version = node["ror_version"].as<bool>();
        config.nic_name = node["nic_name"].as<std::string>();
        config.IS_TEST = node["IS_TEST"].as<bool>();
        config.DEBUG = node["DEBUG"].as<bool>();
        config.LOG_PATH = node["LOG_PATH"].as<std::string>();
    } catch (const std::exception &e) {
        std::cerr << "Error loading config: " << e.what() << std::endl;
        return false;
    }
    return true;
}
