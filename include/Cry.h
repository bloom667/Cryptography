#ifndef CRYPTOGRHY_CRY_H
#define CRYPTOGRHY_CRY_H

#include <string>

namespace cry{
    std::string sha512_hash(const std::string& file_path);
}

#endif