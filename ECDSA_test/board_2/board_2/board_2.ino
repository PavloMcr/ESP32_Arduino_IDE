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

unsigned char hardcoded_signature[] = {
    0x30, 0x45, 0x02, 0x20, 0x11, 0xB0, 0x10, 0xDB, 0x38, 0x85, 
    0xB6, 0x51, 0x31, 0x4F, 0x78, 0x94, 0x88, 0x02, 0x28, 0xBB, 
    0x7D, 0x16, 0xE7, 0xA3, 0x17, 0xE9, 0x23, 0xB5, 0xDC, 0x39, 
    0x27, 0xE4, 0xA5, 0x55, 0x50, 0x43, 0x02, 0x21, 0x00, 0xF2, 
    0x7F, 0x5D, 0x76, 0xF9, 0x79, 0x86, 0xD6, 0x3D, 0xA2, 0xE3, 
    0x23, 0x68, 0xE5, 0x1D, 0x30, 0x6B, 0x00, 0x14, 0x81, 0x53, 
    0xD5, 0x4D, 0x55, 0x70, 0x6F, 0x41, 0x29, 0x3D, 0x88, 0x59, 0xDD,}; 
size_t hardcoded_signature_len = sizeof(hardcoded_signature);


mbedtls_ecdsa_context ecdsa;

const char* message = "Hello, world!";
unsigned char hash[32] = {0}; // SHA-256 hash size


void print_mbedtls_error(int err_code) {
    char error_buf[100];
    mbedtls_strerror(err_code, error_buf, sizeof(error_buf));
    Serial.print("Error: ");
    Serial.println(error_buf);
}

int verify_signature(const unsigned char *pub_key, size_t pub_key_len, 
                     const unsigned char *hash, size_t hash_len, 
                     const unsigned char *sig, size_t sig_len) {

    mbedtls_ecdsa_init(&ecdsa);    
    // Load the public key into the ECDSA context
    int error = mbedtls_ecp_group_load(&ecdsa.grp, CURVE_TYPE);
    if (error != 0) {
        print_mbedtls_error(error);
        return error;
    }
    error = mbedtls_ecp_point_read_binary(&ecdsa.grp, &ecdsa.Q, pub_key, pub_key_len);
    if (error != 0) {
        print_mbedtls_error(error);
        return error;
    }
    // Check if public key is valid (point is on the curve)
    error = mbedtls_ecp_check_pubkey(&ecdsa.grp, &ecdsa.Q);
    if (error != 0) {
        print_mbedtls_error(error);
        return error;
    }
    // Verify the signature
    error = mbedtls_ecdsa_read_signature(&ecdsa, hash, hash_len, sig, sig_len);
    if (error != 0) {
        print_mbedtls_error(error);
        return error;
    } else {
      Serial.println("Verified signature successfully.");
    }
    return 0;
}

void setup() {
    Serial.begin(115200);
    delay(1000);

    mbedtls_sha256((unsigned char*)message, strlen(message), hash, 0);
    // Verify Signature
    if (verify_signature(hardcoded_public_key, hardcoded_public_key_len, hash, sizeof(hash), 
                         hardcoded_signature, hardcoded_signature_len) != 0) {
        Serial.println("Failed to verify message.");
        return;
    }
}

void loop() {
    // Do nothing in the loop for this example.
}
