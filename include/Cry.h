#ifndef CRYPTOGRHY_CRY_H
#define CRYPTOGRHY_CRY_H

#include <string>

namespace cry{
    std::string sha512_hash(const std::string& file_path);
    void generate_rsa_key(const std::string& private_key_file, const std::string& public_key_file);
}

#endif