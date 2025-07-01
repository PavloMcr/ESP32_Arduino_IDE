#include "mbedtls/hkdf.h"

int hkdf_sha256(unsigned char *out_key, size_t key_len, const unsigned char *secret, size_t secret_len, const unsigned char *salt, size_t salt_len, const unsigned char *info, size_t info_len) {
  return mbedtls_hkdf(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), salt, salt_len, secret, secret_len, info, info_len, out_key, key_len);
}

void setup() {
  // Shared secret obtained from ECDH exchange
  unsigned char secret[32] = {0}; 
  size_t secret_len = sizeof(secret);

  // Optional salt (can be NULL if not used)
  unsigned char salt[32] = {0}; 
  size_t salt_len = sizeof(salt);

  // Optional info (can be NULL if not used)
  unsigned char info[] = "context-information";
  size_t info_len = sizeof(info) - 1;

  // Output key buffer
  unsigned char out_key[32];
  size_t key_len = sizeof(out_key);

  // Run HKDF
  int result = hkdf_sha256(out_key, key_len, secret, secret_len, salt, salt_len, info, info_len);
  if (result != 0) {
    // Handle error
  }

  // Now you can use 'out_key' for encryption
}

void loop() {
  // Your main code here
}