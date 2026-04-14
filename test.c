#include "./main.c"


int main() {

    // Alice generates a MAC for text
    unsigned char text[78] = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
    int textLength = 77;
    unsigned char* originalMAC = getSecretPrefixMAC_SHA1("THISISATESTKEY!!", 16, text, textLength);

    // Attacker forges MAC that is of the form SHA1(key || text || gluePadding || ";admin=true")
    // Attacker knows the originalMAC and can initialize the SHA1 operation from where it was left

    // Is the originalMAC the state of the hash function after processing the padding for the original message?
    // AFTER processing the padding
    
    // Extracting registers from the 20-byte SHA-1 hash using bit operations for big endianness compliance
    uint32_t reg1 = (originalMAC[0] << 24) | (originalMAC[1] << 16) | (originalMAC[2] << 8) | (originalMAC[3]);
    uint32_t reg2 = (originalMAC[4] << 24) | (originalMAC[5] << 16) | (originalMAC[6] << 8) | (originalMAC[7]);
    uint32_t reg3 = (originalMAC[8] << 24) | (originalMAC[9] << 16) | (originalMAC[10] << 8) | (originalMAC[11]);
    uint32_t reg4 = (originalMAC[12] << 24) | (originalMAC[13] << 16) | (originalMAC[14] << 8) | (originalMAC[15]);
    uint32_t reg5 = (originalMAC[16] << 24) | (originalMAC[17] << 16) | (originalMAC[18] << 8) | (originalMAC[19]);

    // Attacker passes the alteredMAC with the new message for authentication
    // Just for now we're guessing that the keylength is 16, just for testing purposes
    int keylength = 16;
    int gluePaddingLength = 0;
    unsigned char* gluePadding = getGluePadding(text, textLength, keylength, &gluePaddingLength);
    // Total bytes = Key + Original Message + Glue Padding
    uint64_t bytesProcessed = (uint64_t)keylength + textLength + gluePaddingLength;

    unsigned char alteredMAC[20];
    SHA1WithStartingRegisters(alteredMAC,";admin=true",11,reg1,reg2,reg3,reg4,reg5,bytesProcessed);
    // Does the alteredMessage need to be prepended with the gluePadding? YES
    int totalLength = textLength + gluePaddingLength + 11;
    // alteredMessage = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon" + gluePadding + ";admin=true"
    unsigned char* alteredMessage = malloc(totalLength);
    memcpy(alteredMessage, text, textLength);
    memcpy(alteredMessage + textLength, gluePadding, gluePaddingLength);
    memcpy(alteredMessage + textLength + gluePaddingLength, ";admin=true", 11);

    bool authenticationStatus = authenticate("THISISATESTKEY!!",16,alteredMessage,77+gluePaddingLength+11,alteredMAC);
    return 0;
}