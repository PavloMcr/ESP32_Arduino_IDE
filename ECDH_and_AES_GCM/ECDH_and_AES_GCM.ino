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


/////////////////////////////////////////////////////ECDH//////////////////////////////////////////////////////////


// Key generation based on the Elliptic Curve25519

void genkeyx25519(unsigned char* pubkey, unsigned char* privkey) {
    unsigned char my_pubkey[16] = {0};
    unsigned char my_privkey[16] = {0};


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
    unsigned char my_privkey[16] = {0};
    unsigned char server_pubkey[16] = {0};
    unsigned char shared_secret[16] = {0};


    // Changes to sizeof(privkey) and sizeof(serverpubkey))
    memcpy(my_privkey, privkey, 16);
    memcpy(server_pubkey, serverpubkey, 16);
    
    
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

/////////////////////////////////////////////////////ENCRYPTION//////////////////////////////////////////////////////////


// Function to generate a session key from a shared secret using SHA-256 hashing of the shared secret
int generate_session_key(const unsigned char *shared_secret, size_t secret_len, unsigned char *out_session_key) {
    // Hash the shared secret using SHA-256
    mbedtls_sha256(shared_secret, secret_len, out_session_key, 0);
    
    return 0;    
}

// Generate a random Inizialization Vector
void generate_iv(unsigned char* iv, size_t iv_len) {
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;

  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);

  // Seed the random number generator
  ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
  if (ret != 0) {
    printf("Failed to seed random number generator for the IV");
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

// Function to encrypt Plaintext data
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

/////////////////////////////////////////////////////DECRYPTION//////////////////////////////////////////////////////////


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

  Serial.begin(115200);                                                                 // Initialize Serial Port
  genkeyx25519(my_pubkey, my_privkey);                                                  // Generare a private/public key pair for the Sender
  genkeyx25519(server_pubkey, server_privkey);                                          // Generare a private/public key pair for the Receiver
  calcsecretx25519(my_privkey, server_pubkey, shared_secret);                           // Calculate a Shared Secret from the Sender's Private and Receiver's Public key pair
  calcsecretx25519(server_privkey, my_pubkey, shared_secret2);                          // Calculate a Shared Secret from the Receiver's Private and Sender's Public key pair
  if (memcmp(shared_secret, shared_secret2, 16) == 0) {                                 // If the shared secrets are identical, proceed with the next steps, otherwise print error message                                                             
  } else {
  printf("Error: Shared secrets do not match!");
  }
  generate_session_key(shared_secret, key_len, out_session_key);                        // Generate a Session Key by hashing the Shared Secret
  encrypt(plaintext, sizeof(plaintext) - 1, out_session_key, iv, ciphertext, tag);      // Encrtypt plaintext
  decrypt(ciphertext, sizeof(plaintext) - 1, out_session_key, iv, tag, decrypted);      // Decrypt ciphertext



  printf("Shared Secret :");                                                            // Print Shared Secret
  for (size_t i = 0; i < sizeof(shared_secret); i++)
        printf("%02X", shared_secret[i]);
  printf("\n");

  printf("Session Key :");                                                              // Print Session Key
  for (size_t i = 0; i < sizeof(out_session_key); i++)
        printf("%02X", out_session_key[i]);
  printf("\n");

  // Print the ciphertext
  Serial.print("Ciphertext: ");
  for (size_t i = 0; i < sizeof(plaintext) - 1; i++) {
    Serial.print(ciphertext[i], HEX);
  }
  Serial.println();

  Serial.print("Decrypted: ");
  for (size_t i = 0; i < sizeof(plaintext) - 1; i++) {
    Serial.print((char)decrypted[i]);
  }
  Serial.println();

//}



                                                                      // Optional, Print all of the keys to the Serial 
  printf("PUBKEY: ");                                                 // Print Sender's PUB KEY to Serial
  for (size_t i = 0; i < sizeof(my_pubkey); i++)      
        printf("%02x", my_pubkey[i]);
  printf("\n");
}
/*  printf("Privkey: ");                                                // Print Sender's PRIV KEY to Serial
  for (size_t i = 0; i < sizeof(my_privkey); i++)
        printf("%02x", my_privkey[i]);
  printf("\n");

  printf("Server PUBKEY: ");                                          // Print Receiver's PUB KEY to Serial
  for (size_t i = 0; i < sizeof(server_pubkey); i++)
        printf("%02x", server_pubkey[i]);
  printf("\n");
  printf("Server Privkey: ");                                         // Print Receivers's PRIV KEY to Serial
  for (size_t i = 0; i < sizeof(server_privkey); i++)
        printf("%02x", server_privkey[i]);
  printf("\n");

/*
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
*/


void loop() {
  // put your main code here, to run repeatedly:

}
