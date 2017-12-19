#ifndef UTILS_H
#define UTILS_H

#include <vector>

template<typename T>
std::vector<T> operator+(const std::vector<T>& lhs, const std::vector<T>& rhs) {
    std::vector<T> vec;
    vec.insert(vec.end(), lhs.begin(), lhs.end());
    vec.insert(vec.end(), rhs.begin(), rhs.end());
    return vec;
}

template<typename T>
std::vector<T> operator+=(std::vector<T>& lhs, const std::vector<T>& rhs) {
    lhs.insert(lhs.end(), rhs.begin(), rhs.end());
    return lhs;
}

const char* strerror_newl(int err);

// inflates data compressed with Deflate algorithm. Returns: (error,
// uncompressed). For human-readable description of error use zerror()
std::pair<int,std::vector<uint8_t>> inflate(const std::vector<uint8_t> in);
void zerror(int zlib_ret);

#endif //UTILS_H
