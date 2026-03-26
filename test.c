#include "./main.c"


int main() {
    unsigned char key[13] = "Secret sauce";
    int keylength = 12;
    unsigned char text[14] = "Hello, world!";
    int textLength = 13;
    unsigned char* data = getSecretPrefixMAC_SHA1("Secret sauce",12,"Hello, world!", 13);
    bool correctDigest = authenticate(key, keylength,text, textLength,data);
    
    
    bool messageTamperedDigest = authenticate(key, keylength, "Bye bye, world!",15, data);
    bool keyTamperedDigest = authenticate("Ultrasecret sauce", 17, text, textLength, data);


    return 0;
}