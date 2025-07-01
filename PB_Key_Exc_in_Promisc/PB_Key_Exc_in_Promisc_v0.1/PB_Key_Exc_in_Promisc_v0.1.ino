#include <mbedtls/ecdh.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include "mbedtls/error.h"
#include "mbedtls/ecp.h"
#include "mbedtls/gcm.h"
#include <mbedtls/ecdh.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include "mbedtls/error.h"
#include "mbedtls/ecp.h"
#include "mbedtls/hkdf.h"
#include "mbedtls/sha256.h"
#include "WiFi.h"

                                                  //INIZIALIZATION

// Elliptic-Curve Diffie-Hellman Key declarations

unsigned char my_pubkey[16] = { 0 }; 
unsigned char my_privkey[16] = { 0 };
unsigned char server_pubkey[16] = {0};
unsigned char server_privkey[16] = {0};
unsigned char shared_secret[16] = { 0 };
unsigned char shared_secret2[16] = { 0 };
unsigned char buffer[16] = {0};
char error_buf[100];

// Key for encryption and IV (Initialization Vector)

unsigned char key[16] = { 0 };
unsigned char iv[12]  = { 0 };
unsigned char out_session_key[16];
size_t key_len = sizeof(out_session_key);


// Plaintext to test encryption and decryption 
unsigned char plaintext[] = "This is a test plaintext!";
unsigned char ciphertext[sizeof(plaintext) + 16];                     // Output buffer (includes space for auth tag)
unsigned char tag[16];                                                // Buffer to hold the authentication tag

// Buffer to hold the decrypted plaintext
unsigned char decrypted[sizeof(plaintext)];

// Tries
int ret = 1;


//HELPER FUNCTION 

// Printer function for the Hex data 
void printhex(unsigned char* array, int size) {
  for (int i = 0; i < size ; i++) {
    char str[3];
    sprintf(str, "%02x", (int)array[i]);
    Serial.print(str);
  }
  Serial.println("\n");
}

//HELPER FUNCTION 

// Swap the byte order from big-endian to little-endian
void swapEndianArray(unsigned char* ptrIn[], unsigned char * ptrOut[], int size) {
    int i;
    for (i = 0; i < size; i++) {
        ptrOut[i] = ptrIn[size - i - 1];
    }
    return;
}

void genkeyx25519(unsigned char* pubkey, unsigned char* privkey) {
    //unsigned char my_pubkey[32] = {0};
    //unsigned char my_privkey[32] = {0};


    mbedtls_ecdh_context ctx;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    // generate the keys and save to buffer
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    mbedtls_ecdh_init(&ctx);
    mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, 0,  0);
        
    mbedtls_ecp_group_load(&ctx.grp, MBEDTLS_ECP_DP_CURVE25519);        
    mbedtls_ecdh_gen_public(&ctx.grp, &ctx.d, &ctx.Q, mbedtls_ctr_drbg_random, &ctr_drbg);

    mbedtls_mpi_write_binary_le(&ctx.Q.X, my_pubkey, sizeof(my_pubkey));
    mbedtls_mpi_write_binary_le(&ctx.d, my_privkey, sizeof(my_privkey));
    memcpy(pubkey, my_pubkey, sizeof(my_pubkey));
    memcpy(privkey, my_privkey, sizeof(my_privkey));
    mbedtls_ecdh_free(&ctx);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    
}





void setup() {

  Serial.begin(115200);
  setup_wifi();
  genkeyx25519(my_pubkey, my_privkey);



  // put your setup code here, to run once:

}

void loop() {
  // put your main code here, to run repeatedly:

}
