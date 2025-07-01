#include <mbedtls/ecdh.h>
#include <mbedtls/entropy.h>
#include "mbedtls/error.h"
#include "mbedtls/ecp.h"
#include "mbedtls/gcm.h"
#include <mbedtls/ctr_drbg.h>
#include "mbedtls/hkdf.h"
#include "mbedtls/sha256.h"
#include <WiFi.h>
#include <esp_wifi.h>
#include "nvs_flash.h"
#include <HardwareSerial.h>
#include <mbedtls/ecdsa.h>

#define CURVE_TYPE MBEDTLS_ECP_DP_SECP256R1

const unsigned char hardcoded_public_key[] = {
    0x04, 0x29, 0xF5, 0xC5, 0xD1, 0x2A, 0x67, 0x15, 0x4D, 0x96, 
    0x70, 0x44, 0x36, 0x88, 0xF8, 0x06, 0xE7, 0xD8, 0x74, 0x98, 
    0xED, 0x8F, 0xAD, 0xF7, 0x6C, 0x32, 0x8C, 0x70, 0x43, 0x73, 
    0x64, 0xC8, 0x14, 0x5E, 0x2D, 0x2B, 0x3F, 0x10, 0x6E, 0xEB, 
    0x36, 0x26, 0x21, 0x08, 0xEE, 0x3B, 0xDC, 0xF7, 0x5F, 0x2D, 
    0x79, 0x0F, 0xF7, 0x07, 0x4E, 0xE4, 0x68, 0x78, 0xBE, 0x41, 
    0x39, 0x18, 0x23, 0xAF, 0xA3};
size_t hardcoded_public_key_len = sizeof(hardcoded_public_key);

const unsigned char hardcoded_private_key[] = {
    0x2D, 0xD3, 0xE9, 0x9C, 0x2A, 0x75, 0x0A, 0xED, 0x83, 0xEA, 
    0x4B, 0x9C, 0x39, 0x94, 0x66, 0x86, 0xE3, 0xFF, 0x1C, 0x48, 
    0x4F, 0x30, 0xD2, 0x02, 0xE0, 0x7F, 0xFF, 0xDC, 0x27, 0x9A, 
    0x40, 0x77};
size_t hardcoded_private_key_len = sizeof(hardcoded_private_key);

unsigned char private_key[96];
size_t private_key_len = 0;

unsigned char public_key[96] = {0};
size_t public_key_len = 0;

mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_ecdsa_context ecdsa;

const char* message = "Hello, world!";
unsigned char hash[32]; // SHA-256 hash size
unsigned char signature[128]; // buffer to hold the signature
size_t sig_len;
int error;

void print_mbedtls_error(int err_code) {
    char error_buf[100];
    mbedtls_strerror(err_code, error_buf, sizeof(error_buf));
    Serial.print("Error: ");
    Serial.println(error_buf);
}

int generate_keys() {
    // Initialize ecdsa context  
    
    error = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, 0, 0);
    if (error != 0) {
        print_mbedtls_error(error);
        Serial.print("Failed to seed RNG. Error code: ");
        return error;
    }  

    // Generate EC key pair
    error = mbedtls_ecdsa_genkey(&ecdsa, CURVE_TYPE, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (error != 0) {
        print_mbedtls_error(error);
        return error;
    }
    private_key_len = mbedtls_mpi_size(&(ecdsa.d));
    // Extract and store the private key from the context
    error = mbedtls_mpi_write_binary(&(ecdsa.d), private_key, private_key_len);
    if (error != 0) {
        print_mbedtls_error(error);
        return error;
    }
    // Extract and store the public key from the context
    error = mbedtls_ecp_point_write_binary(&ecdsa.grp, &ecdsa.Q, MBEDTLS_ECP_PF_UNCOMPRESSED, 
                                         &public_key_len, public_key, sizeof(public_key));
    if (error != 0) {
        print_mbedtls_error(error);
        return error;
    }
    return 0;    
}


int sign_message(const unsigned char* msg, size_t msg_len, const unsigned char *priv_key, 
                 size_t priv_key_len, unsigned char* sig, size_t* sig_len) {
    // Compute SHA-256 hash of the message
    mbedtls_sha256(msg, msg_len, hash, 0);
    // Seed RNG
    error = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, 0, 0);
    if (error != 0) {
      print_mbedtls_error(error);
      Serial.print("Failed to seed RNG. Error code: ");
      return error;
    }
    // Load the public key into the ECDSA context
    error = mbedtls_ecp_group_load(&ecdsa.grp, CURVE_TYPE);
    if (error != 0) {
        print_mbedtls_error(error);
        return error;
    }
    error = mbedtls_mpi_read_binary(&ecdsa.d, priv_key, priv_key_len);
    if (error != 0) {
        print_mbedtls_error(error);
        return error;
    }
    // Sign the message hash
    error = mbedtls_ecdsa_write_signature(&ecdsa, MBEDTLS_MD_SHA256, hash, sizeof(hash), sig, sig_len, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (error != 0) {
        print_mbedtls_error(error);
    }
    return error;
}

int verify_signature(const unsigned char *pub_key, size_t pub_key_len,
                     const unsigned char *hash, size_t hash_len, 
                     const unsigned char *sig, size_t sig_len) {
    
    error = mbedtls_ecp_point_read_binary(&ecdsa.grp, &ecdsa.Q, pub_key, pub_key_len);
    if (error != 0) {
        print_mbedtls_error(error);
        return error;
    }
    error = mbedtls_ecp_check_pubkey(&ecdsa.grp, &ecdsa.Q);
    if (error != 0) {
        print_mbedtls_error(error);
        return error;
    }
    // Verify the signature
    error = mbedtls_ecdsa_read_signature(&ecdsa, hash, hash_len, sig, sig_len);
    if (error == 0) {
      Serial.println("Verified message succesfully.");
    }
    if (error != 0) {
        print_mbedtls_error(error);
        return error;
    }
    return 0;
}

void setup() {
    Serial.begin(115200);
    delay(1000);
    
    // Initialize mbedTLS contexts
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ecdsa_init(&ecdsa);

    // Generate keys
    if (generate_keys() != 0) {
        Serial.println("Failed to generate keys.");
    }

    // Sign the message
    if (sign_message((unsigned char*)message, strlen(message), hardcoded_private_key, 
                     hardcoded_private_key_len, signature, &sig_len) != 0) {
        Serial.println("Failed to sign message.");
        return;
    }
    // Verify Signature
    if (verify_signature(hardcoded_public_key, hardcoded_public_key_len, hash, sizeof(hash), 
                         signature, sig_len) != 0) {
        Serial.println("Failed to verify message.");
        return;
    }
    // Output the signature
    Serial.println("Signature bitwise:");
    for (size_t i = 0; i < sig_len; i++) {
        Serial.printf("0x%02X, ", signature[i]);
    }
    Serial.println();

    Serial.println("Privkey bitwise:");
    for (size_t i = 0; i < private_key_len; i++) {
        Serial.printf("0x%02X, ", private_key[i]);
    }
    Serial.println();
    Serial.println("Pubkey bitwise:");
    for (size_t i = 0; i < public_key_len; i++) {
        Serial.printf("0x%02X, ", public_key[i]);
    }
    Serial.println();


}

void loop() {
    // Do nothing in the loop for this example.
}






