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
#define FRAME_LENGTH 96
#define CURVE_TYPE MBEDTLS_ECP_DP_SECP256R1



/* INIZIALIZATION BOARD 1 */
unsigned char plaintext[] = "newtestofencryption";
bool keyReceived = false;
int broadcastCount = 0;
const int maxBroadcastCount = 3; // maximum number of times to broadcast
int ret = 1;

bool bw40 = false;
int primary_channel = 13;
int secondary_channel = WIFI_SECOND_CHAN_NONE;
int txpower = 40;

// Private ECDSA key of Board 1
const unsigned char hardcoded_private_key[] = {
    0x2D, 0xD3, 0xE9, 0x9C, 0x2A, 0x75, 0x0A, 0xED, 0x83, 0xEA, 
    0x4B, 0x9C, 0x39, 0x94, 0x66, 0x86, 0xE3, 0xFF, 0x1C, 0x48, 
    0x4F, 0x30, 0xD2, 0x02, 0xE0, 0x7F, 0xFF, 0xDC, 0x27, 0x9A, 
    0x40, 0x77};
size_t hardcoded_private_key_len = sizeof(hardcoded_private_key);

// Public ECDSA key of Board 2
const unsigned char hardcoded_public_key[] = {
    0x04, 0x9F, 0xF8, 0x85, 0x85, 0x70, 0x29, 0x23, 0x05, 0x7A,
    0x19, 0x62, 0x14, 0x4E, 0x97, 0x39, 0x69, 0xF9, 0xDC, 0x99, 
    0x5B, 0x89, 0xC7, 0xAD, 0xA0, 0x3D, 0x3C, 0xB9, 0xE0, 0xC8, 
    0x46, 0x78, 0xD5, 0xE1, 0x55, 0xF4, 0xA5, 0x54, 0x25, 0x79, 
    0xA0, 0xD5, 0x11, 0x15, 0x19, 0x1B, 0x4A, 0x6C, 0xD5, 0xAE, 
    0x82, 0x44, 0x31, 0x41, 0xCC, 0x18, 0xF8, 0x6F, 0xF3, 0x82, 
    0xE4, 0xA3, 0x3A, 0x49, 0xBA};
size_t hardcoded_public_key_len = sizeof(hardcoded_public_key);

unsigned char signature[128]; // buffer to hold the ECDSA signature
size_t sig_len;

// Differentiate betweeen two states
typedef enum {
    StateBroadcasting,
    StateListening,
    Standby
} KeyExchangeState;

// Set the current state for Board1 to Broadcasting
KeyExchangeState currentState = StateBroadcasting;

uint8_t broadcastAddress[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};  // Broadcast MAC address for everyone in the network
uint8_t mac_other[6] = {0x7C,0xDF,0xA1,0xE8,0x3,0x10};              //NODE 1 P1_N8R8
//uint8_t mac_other[6] = {0xF4,0x12,0xFA,0xE3,0x59,0xB0};           //NODE 2 M0_N8R8
uint8_t mac_own[6];
uint8_t entire_packet[FRAME_LENGTH] = {0};

// Elliptic-Curve Diffie-Hellman Key declarations
unsigned char my_pubkey[32] = { 0 }; 
unsigned char my_privkey[32] = { 0 };
unsigned char received_pubkey[32] = {0};
unsigned char shared_secret[32] = { 0 };
unsigned char out_session_key[32] = { 0 };
unsigned char buffer[16] = {0};
char error_buf[100];
//AES-GCM Declarations
unsigned char key[32] = { 0 };
unsigned char iv[12]  = { 0 };
unsigned char ciphertext[sizeof(plaintext)];   
unsigned char tag[16] = { 0 }; 
unsigned char decrypted[sizeof(plaintext)] = { 0 };
unsigned char encrypted_payload[FRAME_LENGTH] = { 0 };
unsigned char decrypted_payload[FRAME_LENGTH] = { 0 };

// Error printer function
void print_mbedtls_error(int err_code) {
    char error_buf[100];
    mbedtls_strerror(err_code, error_buf, sizeof(error_buf));
    Serial.print("Error: ");
    Serial.println(error_buf);
}

bool isNotZero(const unsigned char *array, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (array[i] != 0) {
            return true; // Found a non-zero byte
        }
    }
    return false; // All bytes are zero
}

// Initialize Wifi
void initWiFi() {
  esp_err_t ret = nvs_flash_init();
  if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
      ESP_ERROR_CHECK(nvs_flash_erase());
      ret = nvs_flash_init();
  } 
  ESP_ERROR_CHECK( ret );
  ESP_ERROR_CHECK(esp_netif_init());
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&cfg));
  wifi_country_t wifi_country = {.cc="DE", .schan = 1, .nchan = 13};
  ESP_ERROR_CHECK( esp_wifi_set_country(&wifi_country) ); /* set country for channel range [1, 13] */
  ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM) ); 
  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA) );
  WiFi.disconnect();
  delay(100);

  // sniff traffic
  esp_wifi_set_promiscuous(false); 
  esp_wifi_set_promiscuous_rx_cb(&promiscuousCallback);
  wifi_promiscuous_filter_t filter;
  filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT + WIFI_PROMIS_FILTER_MASK_DATA; //+ WIFI_PROMIS_FILTER_MASK_CTRL ; // + WIFI_PROMIS_FILTER_MASK_DATA_MPDU + WIFI_PROMIS_FILTER_MASK_DATA_AMPDU; // WIFI_PROMIS_FILTER_MASK_MGMT + WIFI_PROMIS_FILTER_MASK_CTRL + WIFI_PROMIS_FILTER_MASK_DATA + WIFI_PROMIS_FILTER_MASK_MISC + WIFI_PROMIS_FILTER_MASK_DATA_MPDU + WIFI_PROMIS_FILTER_MASK_DATA_AMPDU + WIFI_PROMIS_FILTER_MASK_FCSFAIL;
  ESP_ERROR_CHECK( esp_wifi_set_promiscuous_filter(&filter) );
  filter.filter_mask = WIFI_PROMIS_CTRL_FILTER_MASK_ALL;
  ESP_ERROR_CHECK( esp_wifi_set_promiscuous_ctrl_filter(&filter) );

  ESP_ERROR_CHECK( esp_wifi_start() );  
  ESP_ERROR_CHECK( esp_wifi_set_protocol(WIFI_IF_STA, WIFI_PROTOCOL_11B|WIFI_PROTOCOL_11G|WIFI_PROTOCOL_11N|WIFI_PROTOCOL_LR) );
  ESP_ERROR_CHECK(esp_wifi_set_bandwidth(WIFI_IF_STA, WIFI_BW_HT40));
  ESP_ERROR_CHECK(esp_wifi_set_channel(primary_channel, WIFI_SECOND_CHAN_NONE));
  esp_wifi_set_max_tx_power(txpower);
  ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));
  esp_read_mac(mac_own, ESP_MAC_WIFI_STA); 
  esp_err_t err = esp_wifi_set_promiscuous(true);
  if (err != ESP_OK) {
      Serial.println("Error setting promiscuous mode");
  }  
}
// Callback to sniff packets
void promiscuousCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
  if (!keyReceived){

    const wifi_promiscuous_pkt_t* pkt = (const wifi_promiscuous_pkt_t*)buf;
    const uint8_t* payload = pkt->payload;
    uint16_t frame_ctrl = (payload[1] << 8) | payload[0];
    uint8_t type = (frame_ctrl & 0x0C) >> 2;
    uint8_t subtype = (frame_ctrl & 0xF0) >> 4;
    uint8_t llc_hdr[8];
    memcpy(llc_hdr, payload + 24, 8);
    uint8_t expected_llc_hdr[] = {0xAA, 0xAA, 0x03, 0xE1, 0xFA, 0x73, 0x00, 0x18};
    if (type == 2 && subtype == 0 && memcmp(llc_hdr, expected_llc_hdr, 8) == 0) {
        memcpy(received_pubkey, payload + 32, 32);       
        keyReceived = true;        
    }
    else 
    {
        return;
    }    
  }  
}
// Prepare the frame to be sent
void prepareFrame(uint8_t *frame, uint8_t *my_pubkey, unsigned char* sig) {
    // Define some of the frame fields:
    uint8_t frameControl[] = {0x08, 0x00}; // type = 2 (data), subtype = 0
    uint8_t duration[] = {0x00, 0x00};
    uint8_t seqControl[] = {0x00, 0x00};
    uint8_t LLCHeader[] = {0xAA, 0xAA, 0x03, 0xE1, 0xFA, 0x73, 0x00, 0x18};

    // Construct the frame:
    memcpy(frame, frameControl, 2);
    memcpy(frame + 2, duration, 2);
    memcpy(frame + 4, broadcastAddress, 6);
    memcpy(frame + 10, mac_own, 6);
    memcpy(frame + 16, mac_own, 6); // using the sender MAC address as BSSID
    memcpy(frame + 22, seqControl, 2);
    memcpy(frame + 24, LLCHeader, 8); // appending the public key
    memcpy(frame + 32, my_pubkey, 32); // appending the public key
    memcpy(frame + 64, &sig_len, 4);
    memcpy(frame + 68, sig, sig_len); // appending the signature
}

// Send the frame and print it to the Serial
void sendRawFrameWithPublicKey() {
    uint8_t packet[256] = {0};
    prepareFrame(packet, my_pubkey, signature); 

    ESP_ERROR_CHECK( esp_wifi_start() );
    ESP_ERROR_CHECK( esp_wifi_set_protocol(WIFI_IF_STA, WIFI_PROTOCOL_11B|WIFI_PROTOCOL_11G|WIFI_PROTOCOL_11N|WIFI_PROTOCOL_LR) );
    ESP_ERROR_CHECK(esp_wifi_set_bandwidth(WIFI_IF_STA, WIFI_BW_HT40));
    ESP_ERROR_CHECK(esp_wifi_set_channel(primary_channel, WIFI_SECOND_CHAN_NONE));
    esp_wifi_set_max_tx_power(txpower);
    ESP_ERROR_CHECK( esp_wifi_config_80211_tx_rate(WIFI_IF_STA, WIFI_PHY_RATE_6M));  

    ESP_ERROR_CHECK_WITHOUT_ABORT(esp_wifi_80211_tx(WIFI_IF_STA, packet, sizeof(packet), true));
}
//HELPER FUNCTION FOR ECDH
// Swap the byte order from big-endian to little-endian
void swapEndianArray(unsigned char* ptrIn[], unsigned char * ptrOut[], int size) {
    int i;
    for (i = 0; i < size; i++) {
        ptrOut[i] = ptrIn[size - i - 1];
    }
    return;
}

int sign_message(const unsigned char* ECDH_pubkey, size_t ECDH_pubkey_len, const unsigned char *priv_key, 
                 size_t priv_key_len, unsigned char* sig, size_t* sig_len) {

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ecdsa_context ecdsa;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ecdsa_init(&ecdsa);
    // Compute SHA-256 hash of the message
    unsigned char hash[32];
    mbedtls_sha256(ECDH_pubkey, ECDH_pubkey_len, hash, 0);
    // Seed RNG
    int error = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, 0, 0);
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
        return error;
    }
    else{
        Serial.println("Signed Successfully:");
    }

    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_ecdsa_free(&ecdsa);
    
}


int verify_signature(const unsigned char *pub_key, size_t pub_key_len, 
                     const unsigned char *sig, size_t sig_len) {                      

    mbedtls_ecdsa_context ecdsa;
    mbedtls_ecdsa_init(&ecdsa); 
    unsigned char hash[32];
    mbedtls_sha256(received_pubkey, 32, hash, 0);   
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
    error = mbedtls_ecdsa_read_signature(&ecdsa, hash, 32, sig, sig_len);
    if (error != 0) {
        Serial.println("Verification failed.");
        print_mbedtls_error(error);
        return error;
    } else {
      Serial.println("Verified signature successfully.");
    }
    return 0;
}

// Generate local public/private key pair based on curve25519
void genkeyx25519(unsigned char* pubkey, unsigned char* privkey) {

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

void calcsecretx25519(unsigned char * my_privkey, unsigned char * received_pubkey, unsigned char* shared_secret) { 
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
      Serial.print("Error in group load\n");
      mbedtls_strerror(ret, error_buf, sizeof(error_buf));
      Serial.println(error_buf);
      return ;
    }  
    // read my private key
    ret = mbedtls_mpi_read_binary_le(&ctx.d, my_privkey, 32);
    if (ret != 0) {
      Serial.print("Error in reading privkey\n");
      mbedtls_strerror(ret, error_buf, sizeof(error_buf));
      Serial.println(error_buf);
      return ;
    }
    ret = mbedtls_mpi_lset(&ctx.Qp.Z, 1);
    if (ret != 0) {
      Serial.print("Error in mpi lset for secret\n");
      mbedtls_strerror(ret, error_buf, sizeof(error_buf));
      Serial.println(error_buf);
      return ;
    }    
    // read received pub key
    ret = mbedtls_mpi_read_binary_le(&ctx.Qp.X, received_pubkey, 32);
    if (ret != 0) {
      Serial.print("Error in reading pubkey\n");
      mbedtls_strerror(ret, error_buf, sizeof(error_buf));
      Serial.println(error_buf);
      return ;
    }
    // check pub key
    ret = mbedtls_ecp_check_pubkey(&ctx.grp, &ctx.Qp);
    if (ret != 0) {
      Serial.print("Invalid public key\n");
      mbedtls_strerror(ret, error_buf, sizeof(error_buf));
      Serial.println(error_buf);
      return ;
    }    
    // generate shared secret
    size_t olen;
    ret = mbedtls_ecdh_calc_secret(&ctx, &olen, shared_secret, 32, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
    Serial.print("error in calculating shared secret\n");
    mbedtls_strerror(ret, error_buf, sizeof(error_buf));
    Serial.print("Error message for error code: ");
    Serial.println(error_buf);
    return ;
    }  
    mbedtls_mpi_write_binary_le(&ctx.z, shared_secret, 32);
    mbedtls_ecdh_free(&ctx);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}

// Function to generate a session key from the shared secret using SHA-256 hashing of the shared secret
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
    Serial.print("Failed to seed random number generator for the IV\n");
    mbedtls_strerror(ret, error_buf, sizeof(error_buf));
    Serial.println(error_buf);
    return ;
  }
  // Generate random bytes for the IV
  ret = mbedtls_ctr_drbg_random(&ctr_drbg, iv, iv_len);
  if (ret != 0) {
    Serial.print("Failed to generate IV\n");
    mbedtls_strerror(ret, error_buf, sizeof(error_buf));
    Serial.println(error_buf);
    return;
  }
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
}
// Encrypt data
void encrypt(const unsigned char* plaintext, size_t plaintext_len, const unsigned char* key, unsigned char* iv, unsigned char* ciphertext, unsigned char* tag) {
  // Initialization
  mbedtls_gcm_context ctx;
  mbedtls_gcm_init(&ctx);
  // Set up the AES-GCM cipher with the key, print error if failed
  ret = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 256); 
  if (ret != 0) {
    Serial.print("Failed to set encr key\n");
    mbedtls_strerror(ret, error_buf, sizeof(error_buf));
    Serial.println(error_buf);    
  }
  // Generate a random IV
  generate_iv(iv, 12);
  // Perform the encryption, encrypt the plaintext,  print error if failed
  ret = mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, plaintext_len, iv, 12, NULL, 0, plaintext, ciphertext, 16, tag);
  if (ret != 0) {
    Serial.print("Encryption failed\n");
    mbedtls_strerror(ret, error_buf, sizeof(error_buf));
    Serial.println(error_buf);
  }
  mbedtls_gcm_free(&ctx);
}

// Decrypt data
int decrypt(const unsigned char* ciphertext, size_t ciphertext_len, const unsigned char* key, const unsigned char* iv, const unsigned char* tag, unsigned char* plaintext) {
  // Initialization
  mbedtls_gcm_context decrypt_ctx;
  mbedtls_gcm_init(&decrypt_ctx);
  // Set up the AES-GCM cipher with the key for decryption
  ret = mbedtls_gcm_setkey(&decrypt_ctx, MBEDTLS_CIPHER_ID_AES, key, 256);
  if (ret != 0) {
    Serial.print("Failed to set key for decryption\n");
    mbedtls_strerror(ret, error_buf, sizeof(error_buf));
    Serial.println(error_buf);
  }
  ret = mbedtls_gcm_auth_decrypt(&decrypt_ctx, ciphertext_len, iv, 12, NULL, 0, tag, 16, ciphertext, plaintext) ; 
  if (ret != 0) {
    Serial.print("Decryption failed\n");
    mbedtls_strerror(ret, error_buf, sizeof(error_buf));
    Serial.println(error_buf);
  }
  mbedtls_gcm_free(&decrypt_ctx);
  return ret;  
}

// Setup the board
void setup() {
  Serial.begin(115200);
  unsigned long startTime = micros();
  genkeyx25519(my_pubkey, my_privkey);
  sign_message((unsigned char*)my_pubkey, 32, hardcoded_private_key, hardcoded_private_key_len, signature, &sig_len);
  unsigned long elapsed_ECDH_ECDSA = micros() - startTime;
  Serial.printf("ECDH_ECDSA Time taken: %lu microseconds\n", elapsed_ECDH_ECDSA);
  initWiFi(); 
 

}
// Broadcast own Pubkey 3 times, then switch to Listening, return if received other's pub key.
void loop() {
  static bool Loop_braker = false;

  if (executedOnce) {
    return; // Exit if this code has been run before
  }
  if (!keyReceived) {                
      sendRawFrameWithPublicKey();
      delay(100);        
  }
  else {
      verify_signature(hardcoded_public_key, hardcoded_public_key_len, signature, sig_len);
      calcsecretx25519(my_privkey, received_pubkey, shared_secret);
      generate_session_key(shared_secret, sizeof(out_session_key), out_session_key);
      Serial.println("Success!");
      Loop_braker = true;    
  }       
    //encrypt(plaintext, sizeof(plaintext) - 1, out_session_key, iv, ciphertext, tag);
}


