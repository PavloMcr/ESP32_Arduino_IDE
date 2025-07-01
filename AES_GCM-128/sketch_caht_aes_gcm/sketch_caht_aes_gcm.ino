
#include "mbedtls/gcm.h"
#include <mbedtls/ecdh.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include "mbedtls/error.h"
#include "mbedtls/ecp.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/sha256.h"

// Key and IV (Initialization Vector)
unsigned char key[16] = { 0 };
unsigned char iv[12]  = { 0 };
unsigned char out_session_key[32];
size_t key_len = sizeof(out_session_key);

// Plaintext to be encrypted
unsigned char plaintext[] = "This is a test text to check padding!";
unsigned char ciphertext[sizeof(plaintext) + 16]; // Output buffer (includes space for tag)
unsigned char tag[16]; // Buffer to hold the authentication tag

// Buffer to hold the decrypted plaintext
unsigned char decrypted[sizeof(plaintext)];

// Tries
int ret = 1;

/* HKDF SESSION KEY DERIVATION FUNCTION
int hkdf_sha256(unsigned char *out_session_key, size_t key_len, const unsigned char *secret, size_t secret_len, const unsigned char *salt, size_t salt_len, const unsigned char *info, size_t info_len) {
  
  const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  ret = mbedtls_hkdf(md_info, salt, salt_len, secret, secret_len, info, info_len, out_session_key, key_len);
  if (ret != 0) {
  printf("Failed to generate session key");
  ret = 0;
  }
  return ret;
}
*/

// Function to generate a session key from a shared secret using SHA-256
int generate_session_key(const unsigned char *shared_secret, size_t secret_len, unsigned char *out_session_key) {
    // Hash the shared secret using SHA-256
    mbedtls_sha256(shared_secret, secret_len, out_session_key, 0);
    
    return 0;    
}


void generate_iv(unsigned char* iv, size_t iv_len) {
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;

  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);

  // Seed the random number generator
  ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
  if (ret != 0) {
    printf("Failed to seed random number generator");
    ret = 0;
  }

  // Generate random bytes for the IV
  ret = mbedtls_ctr_drbg_random(&ctr_drbg, iv, iv_len);
  if (ret != 0) {
    printf("Failed to generate IV");
    return;
  }

  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
}

// Function to encrypt data
void encrypt(const unsigned char* plaintext, size_t plaintext_len, const unsigned char* key, unsigned char* iv, unsigned char* ciphertext, unsigned char* tag) {
  
  // Initialization
  mbedtls_gcm_context ctx;
  mbedtls_gcm_init(&ctx);

  // Set up the AES-GCM cipher with the key, print error if failed
  ret = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 128); 
  if (ret != 0) {
    printf("Failed to set key");
    ret = 0;
  }

  // Generate a random IV
  generate_iv(iv, 12);

  // Perform the encryption, encrypt the plaintext,  print error if failed
  ret = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, plaintext_len, iv, 12, NULL, 0, plaintext, ciphertext, 16, tag);
  if (ret != 0) {
    printf("Encryption failed");
    ret = 0 ;
  }
  
  mbedtls_gcm_free(&ctx);
}

// Function to decrypt data
int decrypt(const unsigned char* ciphertext, size_t ciphertext_len, const unsigned char* key, const unsigned char* iv, const unsigned char* tag, unsigned char* plaintext) {
  
  // Initialization
  mbedtls_gcm_context decrypt_ctx;
  mbedtls_gcm_init(&decrypt_ctx);

  // Set up the AES-GCM cipher with the key for decryption
  ret = mbedtls_gcm_setkey(&decrypt_ctx, MBEDTLS_CIPHER_ID_AES, key, 128);
  if (ret != 0) {
    printf("Failed to set key for decryption");
    ret = 0 ;
  }

  ret = mbedtls_gcm_auth_decrypt(&decrypt_ctx, ciphertext_len, iv, 12, NULL, 0, tag, 16, ciphertext, decrypted) ; 
  if (ret != 0) {
    printf("Decryption failed");
    ret = 0 ;
  }

  mbedtls_gcm_free(&decrypt_ctx);
  return ret;
  
}



void setup() {
  // Start serial communication for debugging
  Serial.begin(115200);

  // Session key generation
  // hkdf_sha256(out_session_key, key_len, key, 16, NULL, 0, NULL, 0); //secret
  if (generate_session_key(key, key_len, out_session_key) == 0) {
        // Successfully derived the session key
  } else {
        printf("Failed to generate session key");
  }
  
  // Encrypt the data
  encrypt(plaintext, sizeof(plaintext) - 1, out_session_key, iv, ciphertext, tag); //key

  // Print the ciphertext
  Serial.print("Ciphertext: ");
  for (size_t i = 0; i < sizeof(plaintext) - 1; i++) {
    Serial.print(ciphertext[i], HEX);
  }
  Serial.println();

  // Print Tag
  Serial.print("Tag: ");
  for (size_t i = 0; i < sizeof(tag) - 1; i++) {
    Serial.print(tag[i], HEX);
  }
  Serial.println();

  // Print iv
  Serial.print("iv: ");
  for (size_t i = 0; i < sizeof(iv) - 1; i++) {
    Serial.print(iv[i], HEX);
  }
  Serial.println();
  
  // Print iv
  Serial.print("Key: ");
  for (size_t i = 0; i < sizeof(key) - 1; i++) {
    Serial.print(out_session_key[i], HEX); // key
  }
  Serial.println();
  
  // DECRYPTION
  // Initialize a new GCM context for decryption
  decrypt(ciphertext, sizeof(plaintext) - 1, out_session_key, iv, tag, decrypted); //key

  // Print the decrypted plaintext
  Serial.print("Decrypted: ");
  for (size_t i = 0; i < sizeof(plaintext) - 1; i++) {
    Serial.print((char)decrypted[i]);
  }
  Serial.println();

}



void loop() {
  // Your main loop code here
}
