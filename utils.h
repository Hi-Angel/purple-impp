/*
 * Trillian IMPP for libpurple/Pidgin
 * Copyright (c) 2017 Konstantin Kharlamov
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

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
