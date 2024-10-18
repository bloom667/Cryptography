#ifndef CRYPTOGRHY_CRY_H
#define CRYPTOGRHY_CRY_H

#include <string>

namespace cry{
    std::string sha512_hash(const std::string& file_path);
    void generate_rsa_key(const std::string& private_key_file, const std::string& public_key_file);
    void sign_file(const std::string& file_path, const std::string& private_key_file, const std::string& signed_file_path);
    bool verify_signature(const std::string& file_path, const std::string& signature_file, const std::string& public_key_file);
}

#endif