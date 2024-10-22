```
cd build
cmake ..
make
./cryptography
```

Based on the above command line, the corresponding file can be obtained.

And the output is listed as follow:
```
SHA-512 has been written into digestfile.hex
RSA key pair has been generated
File signed successfully.
Signature verification: Valid
AES key generated successfully.
AES key encrypted successfully.
AES key decrypted successfully.
The decrypted AES key is same with AES key.
Length of final block (encryption): 0
Plaintext file encrypted successfully.
Ciphertext file decrypted successfully.
The decrypted file digest is same with file digest.
```

* Some bugs when writing the gcm mode code.

In the initial phase, I noticed that when decrypting the ciphertext, it differed from the original plaintext. I began investigating to determine where the issue occurred. I found that the file was missing only the tail portion of the plaintext. To identify the cause, I trimmed a small portion off the end of the file and observed that the decrypted file remained unchanged. I continued trimming the plaintext until it matched the decrypted file, then ran the program again, which succeeded. This indicated that there was an issue with the final part of the encryption and decryption process. Specifically, I discovered that if the block size is less than 4096 (the buffer size), it gets discarded, meaning that the last part requires additional handling.