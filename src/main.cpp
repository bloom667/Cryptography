#include "Cry.h"
#include <iostream>
#include <fstream>

using namespace std;
using namespace cry;

int main(){
    //Hash function 
    try{
        string hash = sha512_hash("../plaintext_file.pdf");

        ofstream out("digest file.hex");
        out << hash;
        out.close();

        cout << "SHA-512 has been written into digestfile.hex" << endl;
    }catch (const exception& e){
        cerr << e.what() << endl;
        return 1;
    }
    //RSA key pair
    try{
        generate_rsa_key("RSA_private_key.pem", "RSA_public_key.pem");
        cout << "RSA key pair has been generated";
    }catch (const exception& e){
        cerr << e.what() << endl;
        return 1;
    }
        
    return 0;
}