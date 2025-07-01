#include <mbedtls/ecdh.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include "mbedtls/error.h"
#include "mbedtls/ecp.h"


// Key declarations

unsigned char my_pubkey[32] = { 0 };
unsigned char my_privkey[32] = { 0 };
unsigned char server_pubkey[32] = {0};
unsigned char server_privkey[32] = {0};
unsigned char shared_secret[32] = { 0 };
unsigned char shared_secret2[32] = { 0 };


// Printer function for the Hex data 
void printhex(unsigned char* array, int size) {
  for (int i = 0; i < size ; i++) {
    char str[3];
    sprintf(str, "%02x", (int)array[i]);
    Serial.print(str);
  }
  Serial.println("\n");
}

// Swap the byte order from big-endian to little-endian
void swapEndianArray(unsigned char* ptrIn[], unsigned char * ptrOut[], int size) {
    int i;
    for (i = 0; i < size; i++) {
        ptrOut[i] = ptrIn[size - i - 1];
    }
    return;
}

// Key generation based on the Elliptic Curve25519

void genkeyx25519(unsigned char* pubkey, unsigned char* privkey) {
    unsigned char my_pubkey[32] = {0};
    unsigned char my_privkey[32] = {0};
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
void calcsecretx25519(unsigned char * privkey, unsigned char * serverpubkey, unsigned char* sharedsecret) {
    unsigned char my_privkey[32] = {0};
    unsigned char server_pubkey[32] = {0};
    unsigned char shared_secret[32] = {0};
    unsigned char buffer[32] = {0};
    char error_buf[100];

    // Changes to sizeof(privkey) and sizeof(serverpubkey))
    memcpy(my_privkey, privkey, 32);
    memcpy(server_pubkey, serverpubkey, 32);
    
    int ret = 1;
    mbedtls_ecdh_context ctx;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    // generate the keys and save to buffer
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    mbedtls_ecdh_init(&ctx);
    mbedtls_ctr_drbg_seed(
        &ctr_drbg,
        mbedtls_entropy_func,
        &entropy,
        0,
        0
    );

    ret = mbedtls_ecp_group_load(&ctx.grp, MBEDTLS_ECP_DP_CURVE25519);
      
    if (ret != 0) {
      printf("error in group load");
      ret = 0 ;
    }    
    
    // read my private key
    ret = mbedtls_mpi_read_binary_le(&ctx.d, my_privkey, sizeof(my_privkey));
    if (ret != 0) {
      printf("error in reading privkey");
      ret = 0 ;
    } 

    ret = mbedtls_mpi_lset(&ctx.Qp.Z, 1);
    if (ret != 0) {
      printf("error in mpi lset for secret");
      ret = 0 ;
    } 
    
    // read server key
    ret = mbedtls_mpi_read_binary_le(&ctx.Qp.X, server_pubkey, sizeof(server_pubkey));
    if (ret != 0) {
      printf("error in reading pubkey\n");
      ret = 0 ;
    } 


    // New Code
    ret = mbedtls_ecp_check_pubkey(&ctx.grp, &ctx.Qp);
    if (ret != 0) {
      printf("invalid public key\n");
      ret = 0 ;
    }
    
    
    
    // generate shared secret
    size_t olen;
    ret = mbedtls_ecdh_calc_secret(&ctx, &olen, shared_secret, 32, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
    printf("error in calculating secret\n");
    mbedtls_strerror(ret, error_buf, sizeof(error_buf));
    printf("Error message for error code %d: %s\n", ret, error_buf);
    ret = 0 ;
    }  



    mbedtls_mpi_write_binary_le(&ctx.z, buffer, sizeof(buffer));
    printf("Secret buffer :");
    for (size_t i = 0; i < sizeof(buffer); i++)
        printf("%02X", buffer[i]);
    printf("\n");

    printf("Secret :");
    for (size_t i = 0; i < sizeof(shared_secret); i++)
        printf("%02X", shared_secret[i]);
    printf("\n");

    // Change from sizeof(shared_secret) to 32 
    memcpy(sharedsecret, shared_secret, 32);
    mbedtls_ecdh_free(&ctx);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

   
}




void setup() {
  Serial.begin(115200);
  // put your setup code here, to run once:
  genkeyx25519(my_pubkey, my_privkey);
  printf("PUBKEY: ");
  for (size_t i = 0; i < sizeof(my_pubkey); i++)
        printf("%02x", my_pubkey[i]);
    printf("\n");
  printf("Privkey: ");
  for (size_t i = 0; i < sizeof(my_privkey); i++)
        printf("%02x", my_privkey[i]);
    printf("\n");  
   genkeyx25519(server_pubkey, server_privkey);
  printf("Server PUBKEY: ");
  for (size_t i = 0; i < sizeof(server_pubkey); i++)
        printf("%02x", server_pubkey[i]);
    printf("\n");
  printf("Server Privkey: ");
  for (size_t i = 0; i < sizeof(server_privkey); i++)
        printf("%02x", server_privkey[i]);
    printf("\n");   
  calcsecretx25519(my_privkey, server_pubkey, shared_secret);
   printf("My Shared Secret :");
    for (size_t i = 0; i < sizeof(shared_secret); i++)
        printf("%02X", shared_secret[i]);
    printf("\n");
  calcsecretx25519(server_privkey, my_pubkey, shared_secret2);
   printf("Server Shared Secret :");
    for (size_t i = 0; i < sizeof(shared_secret2); i++)
        printf("%02X", shared_secret2[i]);
    printf("\n");  


}

void loop() {
  // put your main code here, to run repeatedly:

}