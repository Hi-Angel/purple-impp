#include <string>
#include <cstring>
#include "utils.h"

const char* strerror_newl(int err) {
    return (strerror(err) + std::string{"\n"}).c_str();
}
