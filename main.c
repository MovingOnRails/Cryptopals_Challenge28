#include "./sha1.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>


int SHA_DIGEST_LENGTH = 20;
// Assumes key is of length 16 bytes
unsigned char* getSecretPrefixMAC_SHA1(unsigned char* key, int keylength,
                                      unsigned char* text, int textLength){
    size_t length = keylength+textLength;
    char* hash = malloc(SHA_DIGEST_LENGTH);
    size_t datasize = keylength + textLength;
    char* data = malloc(datasize);
    memcpy(data,key,keylength);
    memcpy(data+keylength,text,textLength);
    uint32_t datasize2 = (uint32_t)datasize;
    SHA1(hash, data, datasize2);

    // Print the hash as a hexadecimal string
    /*for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");*/

    free(data);
    return hash;
}

bool authenticate(unsigned char* key, int keylength, 
                  unsigned char* message, int messageLength, 
                  unsigned char* SHA1Digest){
    unsigned char* generatedDigest = getSecretPrefixMAC_SHA1(key, keylength, message, messageLength);
    return memcmp(generatedDigest,SHA1Digest,SHA_DIGEST_LENGTH) == 0;
}