#ifndef CRYPTOGRHY_CRY_H
#define CRYPTOGRHY_CRY_H

#include <string>

namespace cry{
    std::string sha512_hash(const std::string& file_path);
    void generate_rsa_key(const std::string& private_key_file, const std::string& public_key_file);
    void sign_file(const std::string& file_path, const std::string& private_key_file, const std::string& signed_file_path);
    bool verify_signature(const std::string& file_path, const std::string& signature_file, const std::string& public_key_file);
    void generate_aes_key(const std::string& aes_key_file);
    void encrypt_aes_key(const std::string& aes_key_file, const std::string& public_key_file, const std::string& encrypted_aes_key_file);
    void decrypt_aes_key(const std::string& encrypted_aes_key_file, const std::string& private_key_file, const std::string& decrypted_aes_key_file);
    bool compare_res(const std::string decrypted_aes_key_file, const std::string aes_key_file);
    void encrypt_file_aes_gcm(const std::string& plaintext_file, const std::string& aes_key_file, const std::string& iv_file, const std::string& ciphertext_file, const std::string& tag_file);
    void decrypt_file_aes_gcm(const std::string& ciphertext_file, const std::string& aes_key_file, const std::string& iv_file, const std::string& tag_file, const std::string& decrypted_file);
    void sha512_digest_file(const std::string& file_path, const std::string& digest_file);
}

#endif