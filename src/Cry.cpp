#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <string>

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

        //save public key
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
}