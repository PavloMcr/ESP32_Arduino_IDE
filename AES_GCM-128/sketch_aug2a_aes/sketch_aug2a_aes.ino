//    https://tls.mbed.org/api/gcm_8h.html

#include "mbedtls/gcm.h"

void setup() {
  Serial.begin(115200);
  mbedtls_gcm_context aes;
  char *key = "abcdefghijklmnop";
  char *input = "Mark C's ESP32 GCM Example code!";
  char *iv = "abababababababab";
  unsigned char output[64] = {0};
  unsigned char fin[64] = {0};
  Serial.println("[i] Encrypted into buffer:");
  // init the context...
  mbedtls_gcm_init( &aes );
  // Set the key. This next line could have CAMELLIA or ARIA as our GCM mode cipher... key = 16 byte
  mbedtls_gcm_setkey( &aes,MBEDTLS_CIPHER_ID_AES , (const unsigned char*) key, 16);
  // Initialise the GCM cipher...
  mbedtls_gcm_starts(&aes, MBEDTLS_GCM_ENCRYPT, (const unsigned char*)iv, 12, NULL, 0);
  // Send the intialised cipher some data and store it...
  mbedtls_gcm_update(&aes,strlen(input),(const unsigned char*)input, output);
  // Free up the context.
  mbedtls_gcm_free( &aes );
  for (int i = 0; i < strlen(input); i++) {  
    char str[3];
    sprintf(str, "%02x", (int)output[i]);
    Serial.print(str);
  }
  Serial.println("");
  Serial.println("[i] Decrypted from buffer:");
  mbedtls_gcm_init( &aes );
  mbedtls_gcm_setkey( &aes,MBEDTLS_CIPHER_ID_AES , (const unsigned char*) key, strlen(key) * 8);
  mbedtls_gcm_starts(&aes, MBEDTLS_GCM_DECRYPT, (const unsigned char*)iv, strlen(iv),NULL, 0);
  mbedtls_gcm_update(&aes,64,(const unsigned char*)output, fin);
  mbedtls_gcm_free( &aes );
  for (int i = 0; i < strlen(input); i++) {  
    char str[3];
    sprintf(str, "%c", (int)fin[i]);
    Serial.print(str);
  }
}

void loop() {}




