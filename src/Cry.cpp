#include <openssl/evp.h>
#include <openssl/sha.h>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <string>


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
}