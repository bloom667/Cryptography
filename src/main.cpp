#include "Cry.h"
#include <iostream>
#include <fstream>
#include <string>

using namespace std;
using namespace cry;

int main(){
    //Hash function 
    try{
        string hash = sha512_hash("../plaintext_file.txt");

        ofstream out("digest_file.hex");
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
        cout << "RSA key pair has been generated" << endl;
    }catch (const exception& e){
        cerr << e.what() << endl;
        return 1;
    }
    //Sign the file and verify the signature
    try{
        sign_file("../plaintext_file.txt", "RSA_private_key.pem", "signed_file");
        cout << "File signed successfully." << endl;

        bool is_valid = verify_signature("../plaintext_file.txt", "signed_file", "RSA_public_key.pem");
        cout << "Signature verification: " << (is_valid ? "Valid" : "Invalid") << endl;
    }catch (const exception& e){
        cerr << e.what() << endl;
        return 1;
    }
    //AES key part
    try{
        // Generate AES-256 key and save to file
        generate_aes_key("AES_key.txt");
        cout << "AES key generated successfully." << endl;

        // Encrypt the AES key using RSA public key
        encrypt_aes_key("AES_key.txt", "RSA_public_key.pem", "encrypted_AES_key.txt");
        cout << "AES key encrypted successfully." << endl;

        // Decrypt the encrypted AES key using RSA private key
        decrypt_aes_key("encrypted_AES_key.txt", "RSA_private_key.pem", "decrypted_AES_key.txt");
        cout << "AES key decrypted successfully." << endl;

        bool res = compare_res("decrypted_AES_key.txt", "AES_key.txt");
        cout << "The decrypted AES key is " << (res ? "same" : "different") << " with AES key." << endl;
    }catch (const exception& e){
        cerr << e.what() << endl;
        return 1;
    }

    try{
        // Encrypt the plaintext file using AES-256 GCM
        encrypt_file_aes_gcm("../plaintext_file.txt", "AES_key.txt", "iv.txt", "ciphertext.txt", "tag.txt");
        cout << "Plaintext file encrypted successfully." << endl;

        // Decrypt the ciphertext file using AES-256 GCM
        decrypt_file_aes_gcm("ciphertext.txt", "AES_key.txt", "iv.txt", "tag.txt", "decrypted.txt");
        cout << "Ciphertext file decrypted successfully." << endl;

        // Compute SHA-512 digest of decrypted file
        string hash = sha512_hash("decrypted.txt");

        ofstream out("digest_decrypted_file.hex");
        out << hash;
        out.close();

        bool res = compare_res("digest_file.hex", "digest_decrypted_file.hex");
        cout << "The decrypted file digest is " << (res ? "same" : "different") << " with file digest." << endl;
    }catch (const exception& e){
        cerr << e.what() << endl;
        return 1;
    }

    return 0;
}