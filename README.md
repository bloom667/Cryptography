```
cd build
cmake ..
make
./cryptography
```

Based on the above command line, the corresponding file can be obtained.

* Some bugs when writing the gcm mode code.

In the initial phase, I noticed that when decrypting the ciphertext, it differed from the original plaintext. I began investigating to determine where the issue occurred. I found that the file was missing only the tail portion of the plaintext. To identify the cause, I trimmed a small portion off the end of the file and observed that the decrypted file remained unchanged. I continued trimming the plaintext until it matched the decrypted file, then ran the program again, which succeeded. This indicated that there was an issue with the final part of the encryption and decryption process. Specifically, I discovered that if the block size is less than 4096 (the buffer size), it gets discarded, meaning that the last part requires additional handling.