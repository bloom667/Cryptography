#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#define KEY_LENGTH 4096


using namespace std;

namespace cry{
    
    string sha512_hash(const string& file_path){
        // Open the plaintext file and throw an error if there are problems
        ifstream file(file_path, ios::binary);
        if (!file.is_open()) {
            throw logic_error("cannot open the file");
        }

        // Use EVP interface instead of deprecated SHA512_CTX
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (ctx == nullptr) {
            throw runtime_error("failed to create EVP_MD_CTX");
        }

        if (EVP_DigestInit_ex(ctx, EVP_sha512(), nullptr) != 1) {
            EVP_MD_CTX_free(ctx);
            throw logic_error("failed to initialize digest");
        }   

        char buffer[8192];
        while (file.read(buffer, sizeof(buffer))) {
            if (EVP_DigestUpdate(ctx, buffer, file.gcount()) != 1) {
                EVP_MD_CTX_free(ctx);
                throw runtime_error("failed to update digest");
            }
        }

        // Handle any remaining bytes
        if (file.gcount() > 0) {
            if (EVP_DigestUpdate(ctx, buffer, file.gcount()) != 1) {
                EVP_MD_CTX_free(ctx);
                throw runtime_error("failed to update digest");
            }
        }

        unsigned char hash[SHA512_DIGEST_LENGTH];
        unsigned int lengthOfHash = 0;
        if (EVP_DigestFinal_ex(ctx, hash, &lengthOfHash) != 1) {
            EVP_MD_CTX_free(ctx);
            throw runtime_error("failed to finalize digest");
        }

        EVP_MD_CTX_free(ctx);

        // Convert hash to hexadecimal string
        ostringstream oss;
        for (unsigned int i = 0; i < lengthOfHash; ++i) {
            oss << hex << setw(2) << setfill('0') << (int)hash[i];
        }
        return oss.str();
    }

    void generate_rsa_key(const std::string& private_key_file, const std::string& public_key_file){
        // Generate RSA-4096 key pair
        RSA* rsa = RSA_new();
        BIGNUM* bne = BN_new();
        BN_set_word(bne, RSA_F4);

        rsa = RSA_generate_key(KEY_LENGTH, RSA_F4, nullptr, nullptr);
        if(!rsa){
            throw runtime_error("fail to generate RSA key");
        }

        //Save private key
        FILE* private_key_fp = fopen(private_key_file.c_str(),"wb");
        if(! private_key_fp){
            RSA_free(rsa);
            throw runtime_error("fail to open the file to write private key");
        }
        PEM_write_RSAPrivateKey(private_key_fp, rsa, nullptr, nullptr, 0, nullptr, nullptr);
        fclose(private_key_fp);

        //Save public key
        FILE* public_key_fp = fopen(public_key_file.c_str(),"wb");
        if(! public_key_fp){
            RSA_free(rsa);
            throw runtime_error("fail to open the file to write public key");
        }
        PEM_write_RSAPublicKey(private_key_fp, rsa);
        fclose(public_key_fp);   

        RSA_free(rsa);
        BN_free(bne);     
    }

    void sign_file(const string& file_path, const string& private_key_file, const string& signed_file_path){
        //Read the private key
        FILE* private_key_fp = fopen(private_key_file.c_str(),"rb");
        if(!private_key_fp){
            throw runtime_error("fail to open the file");
        }
        RSA* rsa = PEM_read_RSAPrivateKey(private_key_fp, nullptr, nullptr, nullptr);
        fclose(private_key_fp);
        if(!rsa){
            throw runtime_error("fail to read the private key");
        }

        //Hash the file
        ifstream file(file_path, ios::binary);
        if(!file.is_open()){
            RSA_free(rsa);
            throw logic_error("cannot open the file");
        }

        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);

        char buffer[8192];
        while(file.read(buffer, sizeof(buffer))){
            if (EVP_DigestUpdate(ctx, buffer, file.gcount()) != 1) {
            EVP_MD_CTX_free(ctx);
            RSA_free(rsa);
            throw runtime_error("fail to update digest");
            }
        }

        unsigned char hash[SHA256_DIGEST_LENGTH];
        unsigned int lengthOfHash = 0;
        if (EVP_DigestFinal_ex(ctx, hash, &lengthOfHash) != 1) {
            EVP_MD_CTX_free(ctx);
            RSA_free(rsa);
            throw runtime_error("fail to finalize digest");
        }

        EVP_MD_CTX_free(ctx);

        // Sign the hash
        unsigned char signature[RSA_size(rsa)];
        unsigned int signature_length = 0;
        if (RSA_sign(NID_sha256, hash, lengthOfHash, signature, &signature_length, rsa) != 1) {
            RSA_free(rsa);
            throw runtime_error("failed to sign the file");
        }

        RSA_free(rsa);

        ofstream signed_file(signed_file_path, ios::binary);
        if(!signed_file.is_open()){
            throw runtime_error("fail to create signed file to write");
        }
        signed_file.write(reinterpret_cast<const char*>(signature), signature_length);
        signed_file.close();

    }

    bool verify_signature(const string& file_path, const string& signature_file, const string& public_key_file){
        // Read public key
        FILE* public_key_fp = fopen(public_key_file.c_str(), "rb");
        if (!public_key_fp) {
            throw runtime_error("fail to open public key file");
        }
        RSA* rsa = PEM_read_RSAPublicKey(public_key_fp, nullptr, nullptr, nullptr);
        fclose(public_key_fp);
        if (!rsa) {
            throw runtime_error("fail to read public key");
        }

        // Hash the file
        ifstream file(file_path, ios::binary);
        if (!file.is_open()) {
            RSA_free(rsa);
            throw logic_error("cannot open the file");
        }

        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);

        char buffer[8192];
        while (file.read(buffer, sizeof(buffer))) {
            if (EVP_DigestUpdate(ctx, buffer, file.gcount()) != 1) {
                EVP_MD_CTX_free(ctx);
                RSA_free(rsa);
                throw runtime_error("fail to update digest");
            }
        }

        unsigned char hash[SHA256_DIGEST_LENGTH];
        unsigned int lengthOfHash = 0;
        if (EVP_DigestFinal_ex(ctx, hash, &lengthOfHash) != 1) {
            EVP_MD_CTX_free(ctx);
            RSA_free(rsa);
            throw runtime_error("fail to finalize digest");
        }

        EVP_MD_CTX_free(ctx);

         // Read the signature from the signed file
        ifstream signature_file_stream(signature_file, ios::binary);
        if (!signature_file_stream.is_open()) {
            RSA_free(rsa);
            throw runtime_error("cannot open signature file");
        }
        vector<unsigned char> signature((istreambuf_iterator<char>(signature_file_stream)), istreambuf_iterator<char>());
        signature_file_stream.close();

        // Verify the signature
        bool result = RSA_verify(NID_sha256, hash, lengthOfHash, signature.data(), signature.size(), rsa) == 1;

        RSA_free(rsa);
        return result;
    }

    void generate_aes_key(const std::string& aes_key_file){
        unsigned char aes_key[32];//32bytes=256bits
        if(RAND_bytes(aes_key, sizeof(aes_key))!=1){
            throw runtime_error("fail to generate aes key");
        }

        ofstream file(aes_key_file, ios::binary);
        if(!file.is_open()){
            throw runtime_error("cannot open file to write aes key");
        }
        file.write(reinterpret_cast<const char*>(aes_key), sizeof(aes_key));
        file.close();
    }

    void encrypt_aes_key(const string& aes_key_file, const string& public_key_file, const string& encrypted_aes_key_file) {
        // Read AES key
        ifstream key_file(aes_key_file, ios::binary);
        if (!key_file.is_open()) {
            throw runtime_error("cannot open AES key file for reading");
        }
        vector<unsigned char> aes_key((istreambuf_iterator<char>(key_file)), istreambuf_iterator<char>());
        key_file.close();

        // Read public key
        FILE* public_key_fp = fopen(public_key_file.c_str(), "rb");
        if (!public_key_fp) {
            throw runtime_error("fail to open public key file");
        }
        RSA* rsa = PEM_read_RSAPublicKey(public_key_fp, nullptr, nullptr, nullptr);
        fclose(public_key_fp);
        if (!rsa) {
            throw runtime_error("fail to read public key");
        }

        // Encrypt AES key
        vector<unsigned char> encrypted_key(RSA_size(rsa));
        int encrypted_length = RSA_public_encrypt(aes_key.size(), aes_key.data(), encrypted_key.data(), rsa, RSA_PKCS1_OAEP_PADDING);
        if (encrypted_length == -1) {
            RSA_free(rsa);
            throw runtime_error("fail to encrypt AES key");
        }

        RSA_free(rsa);

        // Write encrypted AES key to file
        ofstream encrypted_key_file(encrypted_aes_key_file, ios::binary);
        if (!encrypted_key_file.is_open()) {
            throw runtime_error("cannot open encrypted AES key file for writing");
        }
        encrypted_key_file.write(reinterpret_cast<const char*>(encrypted_key.data()), encrypted_length);
        encrypted_key_file.close();
    }

    void decrypt_aes_key(const string& encrypted_aes_key_file, const string& private_key_file, const string& decrypted_aes_key_file) {
        // Read encrypted AES key
        ifstream encrypted_key_file(encrypted_aes_key_file, ios::binary);
        if (!encrypted_key_file.is_open()) {
            throw runtime_error("cannot open encrypted AES key file for reading");
        }
        vector<unsigned char> encrypted_key((istreambuf_iterator<char>(encrypted_key_file)), istreambuf_iterator<char>());
        encrypted_key_file.close();

        // Read private key
        FILE* private_key_fp = fopen(private_key_file.c_str(), "rb");
        if (!private_key_fp) {
            throw runtime_error("failed to open private key file");
        }
        RSA* rsa = PEM_read_RSAPrivateKey(private_key_fp, nullptr, nullptr, nullptr);
        fclose(private_key_fp);
        if (!rsa) {
            throw runtime_error("failed to read private key");
        }

        // Decrypt AES key
        vector<unsigned char> decrypted_key(RSA_size(rsa));
        int decrypted_length = RSA_private_decrypt(encrypted_key.size(), encrypted_key.data(), decrypted_key.data(), rsa, RSA_PKCS1_OAEP_PADDING);
        if (decrypted_length == -1) {
            RSA_free(rsa);
            throw runtime_error("failed to decrypt AES key");
        }

        RSA_free(rsa);

        // Write decrypted AES key to file
        ofstream decrypted_key_file(decrypted_aes_key_file, ios::binary);
        if (!decrypted_key_file.is_open()) {
            throw runtime_error("cannot open decrypted AES key file for writing");
        }
        decrypted_key_file.write(reinterpret_cast<const char*>(decrypted_key.data()), decrypted_length);
        decrypted_key_file.close();
    }

    bool compare_res(const std::string decrypted_aes_key_file, const std::string aes_key_file){
        //Use string to store the content in the file
        ifstream decrypted_key_file(decrypted_aes_key_file, ios::binary);
        if(!decrypted_key_file.is_open()){
            throw runtime_error("cannot open decrypted AES key file for reading");
        }
        string str_decrypted_file;
        decrypted_key_file >> str_decrypted_file;

        ifstream key_file(aes_key_file, ios::binary);
        if(!key_file.is_open()){
            throw runtime_error("cannot open AES key file for reading");
        }
        string str_key_file;
        key_file >> str_key_file;

        bool res = (str_key_file == str_decrypted_file ? true:false);
        return res;
    }
}

