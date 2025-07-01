#include "mbedtls/entropy.h"
#include "mbedtls/pk.h"
#include <mbedtls/ecdh.h>
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

// Buffer sizes
#define RSA_KEY_SIZE 2048
#define RSA_EXPONENT 65537
#define MAX_PEM_SIZE 4096



int result = 0;


unsigned char pubkey[1024] =   {0};
size_t pubkey_len = sizeof(pubkey);
unsigned char privkey[3072] =  {0};
size_t privkey_len = sizeof(privkey);
unsigned char signature[256] = {0};
size_t signature_len = 256;

const char* message = "Hello world";

int generate_rsa_key(const unsigned char *message, size_t message_len, 
                      unsigned char *privkey, size_t *privkey_len,
                      unsigned char *pubkey, size_t *pubkey_len,
                      unsigned char *signature, size_t *signature_len) {
    int ret = 0;
    mbedtls_pk_context pk;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    char error_buf[100];

    mbedtls_pk_init(&pk);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    // Seed random number generator
    const char *pers = "rsa_genkey";
    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, 
                              (const unsigned char *)pers, strlen(pers))) != 0) {
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        Serial.printf("Error seeding RNG: %s\n", error_buf);
        goto cleanup;
    }

    // Generate RSA key pair
    if ((ret = mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA))) != 0 ||
        (ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(pk), mbedtls_ctr_drbg_random, &ctr_drbg, 
                            RSA_KEY_SIZE, RSA_EXPONENT)) != 0) {
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        Serial.printf("Error generating RSA key: %s\n", error_buf);
        goto cleanup;
    }

    // Write the public key to the provided buffer
    ret = mbedtls_pk_write_pubkey_der(&pk, pubkey, *pubkey_len);
    if (ret < 0) {
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        Serial.printf("Error writing public key in DER format: %s\n", error_buf);
        goto cleanup;
    }
    *pubkey_len = ret;

    // Write the private key to the provided buffer
    ret = mbedtls_pk_write_key_der(&pk, privkey, *privkey_len);
    if (ret < 0) {
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        Serial.printf("Error writing private key in DER format: %s\n", error_buf);
        goto cleanup;
    }
    *privkey_len = ret;

    unsigned char hash[32];
    mbedtls_sha256(message, message_len, hash, 0);

    // Signing the message
    if ((ret = mbedtls_pk_sign(&pk, MBEDTLS_MD_SHA256, hash, sizeof(hash), signature, 
                               signature_len, mbedtls_ctr_drbg_random, &ctr_drbg)) != 0) {
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        Serial.printf("Signing failed: %s\n", error_buf);
        goto cleanup;
    }

    if ((ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash, sizeof(hash), signature, *signature_len)) != 0) {
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        Serial.printf("ERROR: mbedtls_pk_verify failed: %s\n", error_buf);
        goto cleanup;
    }
cleanup:
    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return ret;
}


void setup() {

  Serial.begin(115200);  // Adjust baud rate as necessary
  delay(1000);

  result = generate_rsa_key((const unsigned char*)message, strlen(message), privkey, &privkey_len, pubkey, &pubkey_len, signature, &signature_len);

  Serial.println();

    if (result == 0) {
        Serial.println("Successfully generated RSA pair!");
        Serial.print("Signature: ");
        for (size_t i = 0; i < signature_len; i++) {
            if (signature[i] < 0x10) {
                Serial.print("0");
            }
            Serial.print(signature[i], HEX);
        }
        Serial.println();
    }
}

void loop() {
  // put your main code here, to run repeatedly:

}
