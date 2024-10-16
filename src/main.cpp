#include "Cry.h"
#include <iostream>
#include <fstream>

using namespace std;
using namespace cry;

int main(){
    //Hash function 
    try{
        string hash = sha512_hash("plaintext_file.pdf");

        ofstream out("digest file.hex");
        out << hash;
        out.close();

        cout << "SHA-512哈希已成功写入digestfile.hex" << endl;
    }catch (const exception& e){
        cerr << e.what() << endl;
        return 1;
    }
        
    return 0;
}