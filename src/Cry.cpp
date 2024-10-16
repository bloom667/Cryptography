#include "Cry.h"
#include <iostream>
#include <fstream>
#include <iomanip>
#include <openssl/sha.h>


using namespace std;

namespace cry{
    
    string sha512_hash(const string& file_path){
        //open the plaintext file and throw an error when facing problems
        ifstream file(file_path, ios::binary);
        if(!file.is_open()){
            throw logic_error("cannot open the file");
        }

        SHA512_CTX ctx;
        SHA512_Init(&ctx);

        char buffer [8192];
        while (file.read(buffer, sizeof(buffer))){
            SHA512_Update(&ctx, buffer, file.gcount());
        }

        unsigned char hash[SHA512_DIGEST_LENGTH];
        SHA512_Final(hash, &ctx);

        ostringstream oss;
        for(int i = 0; i < SHA512_DIGEST_LENGTH; i++){
            oss << hex << setw(2) << setfill('0') << (int)hash[i];
        }
        return oss.str();

    }
}