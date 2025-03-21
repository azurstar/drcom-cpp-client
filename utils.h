#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <vector>

// 计算输入数据的 MD5 摘要，返回 16 字节的二进制结果
std::vector<unsigned char> md5sum(const std::vector<unsigned char>& data);

// 模拟 Python 中 dump() 函数：将整数转换为“二进制”表示（按十六进制转换后转为字节数组）
std::vector<unsigned char> dump(unsigned long long n);

// 按照 Python 代码定义的 ror 逻辑处理：对 md5 字节与密码逐字节异或后，进行位旋转
std::vector<unsigned char> ror(const std::vector<unsigned char>& md5bytes, const std::string& pwd);

// 辅助函数：将十六进制字符串转换为字节数组
std::vector<unsigned char> hexToBytes(const std::string& hex);

// 辅助函数：将字节数组转换为十六进制字符串
std::string bytesToHex(const std::vector<unsigned char>& bytes);

#endif // UTILS_H
