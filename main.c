#include <openssl/sha.h>
#include <stdio.h>
#include <string.h>


// Assumes key is of length 16 bytes
unsigned char getSecretPrefixMAC_SHA1(unsigned char* key, int keysize, unsigned char* text, int textLength){
    size_t length = keysize+textLength;
    unsigned char* hash = malloc(SHA_DIGEST_LENGTH);
    size_t datasize = keysize + textLength;
    unsigned char* data = malloc(datasize);
    memcpy(data,key,keysize);
    memcpy(data+keysize,text,textLength);
    SHA1(data, datasize, hash);

    // Print the hash as a hexadecimal string
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");

    return hash;
}


int main() {
    //unsigned char* data = getSecretPrefixMAC_SHA1(NULL,0,"Hello, world!", 13);
    unsigned char* data = getSecretPrefixMAC_SHA1("Secret sauce",12,"Hello, world!", 13);
    
    return 0;
}