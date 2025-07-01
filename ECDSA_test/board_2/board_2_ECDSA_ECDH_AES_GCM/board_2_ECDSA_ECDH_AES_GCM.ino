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

/* INIZIALIZATION BOARD 2 */
unsigned char plaintext[] = "Hello";
bool keyReceived = false;
int broadcastCount = 0;
const int maxBroadcastCount = 5; // maximum number of times to broadcast
int ret = 1;

bool bw40 = false;
int primary_channel = 13;
int secondary_channel = WIFI_SECOND_CHAN_NONE;
int txpower = 40;

const unsigned char hardcoded_public_key[] = {
    0x04, 0x29, 0xF5, 0xC5, 0xD1, 0x2A, 0x67, 0x15, 0x4D, 0x96, 
    0x70, 0x44, 0x36, 0x88, 0xF8, 0x06, 0xE7, 0xD8, 0x74, 0x98, 
    0xED, 0x8F, 0xAD, 0xF7, 0x6C, 0x32, 0x8C, 0x70, 0x43, 0x73, 
    0x64, 0xC8, 0x14, 0x5E, 0x2D, 0x2B, 0x3F, 0x10, 0x6E, 0xEB, 
    0x36, 0x26, 0x21, 0x08, 0xEE, 0x3B, 0xDC, 0xF7, 0x5F, 0x2D, 
    0x79, 0x0F, 0xF7, 0x07, 0x4E, 0xE4, 0x68, 0x78, 0xBE, 0x41, 
    0x39, 0x18, 0x23, 0xAF, 0xA3};
size_t hardcoded_public_key_len = sizeof(hardcoded_public_key);

unsigned char signature[128] = {0}; // buffer to hold the ECDSA signature
size_t sig_len;

// Differentiate betweeen two states
typedef enum {
    StateBroadcasting,
    StateListening,
    Standby
} KeyExchangeState;

// Set the current state for Board1 to Broadcasting
KeyExchangeState currentState = StateListening;

uint8_t broadcastAddress[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};  // Broadcast MAC address for everyone in the network
uint8_t mac_other[6] = {0xF4,0x12,0xFA,0xE3,0x59,0xB0};  // NODE 2 M0_N8R8
//uint8_t mac_other[6] = {0x7C,0xDF,0xA1,0xE8,0x3,0x10}; //NODE 1 P1_N8R8
uint8_t mac_own[6];
uint8_t entire_packet[256] = {0};

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
  if (!keyReceived)
  {
    if (currentState == StateListening) {

        const wifi_promiscuous_pkt_t* pkt = (const wifi_promiscuous_pkt_t*)buf;
        const uint8_t* payload = pkt->payload;
        uint16_t frame_ctrl = (payload[1] << 8) | payload[0];
        uint8_t type = (frame_ctrl & 0x0C) >> 2;
        uint8_t subtype = (frame_ctrl & 0xF0) >> 4;
        uint8_t llc_hdr[8];
        memcpy(llc_hdr, payload + 24, 8);
        memcpy(entire_packet, payload, 256);
        
        int rssi = pkt->rx_ctrl.rssi;
        int8_t noise_floor = pkt->rx_ctrl.noise_floor;
        Serial.print("RSSI: ");
        Serial.println(rssi);
        //Serial.print("Noise Floor: ");
        //Serial.println(noise_floor);
        int snr = rssi - noise_floor;
        Serial.print("SNR: ");
        Serial.println(snr);
        
        uint8_t expected_llc_hdr[] = {0xAA, 0xAA, 0x03, 0xE1, 0xFA, 0x73, 0x00, 0x18};

        if (type == 2 && subtype == 0 && memcmp(llc_hdr, expected_llc_hdr, 8) == 0) {

            Serial.print("Received Packet Data: ");
            for (size_t i = 0; i < 256; i++)
                Serial.print(entire_packet[i], HEX);
            Serial.print("\n");
            memcpy(received_pubkey, payload + 32, 32);
            memcpy(&sig_len, payload + 64, 4);
            memcpy(signature, payload + 68, sig_len);
            if (verify_signature(hardcoded_public_key, hardcoded_public_key_len, signature, sig_len)!= 0) {
                Serial.println("Failed to verify message.");
            }            
            currentState = StateBroadcasting;
            keyReceived = true;
        } 
        else 
        {
            return;
        }        
    }
  }  
}
// Callback to read Data Payload
void promiscuous_payload_Callback(void* buf, wifi_promiscuous_pkt_type_t type) {

    const wifi_promiscuous_pkt_t* pkt = (const wifi_promiscuous_pkt_t*)buf;
    const uint8_t* payload = pkt->payload;
    uint16_t frame_ctrl = (payload[1] << 8) | payload[0];
    uint8_t ptype = (frame_ctrl & 0x0C) >> 2;
    uint8_t subtype = (frame_ctrl & 0xF0) >> 4;
    uint8_t llc_hdr[8];
    uint8_t payload_size;
    uint8_t plaintext_size;
    unsigned char received_tag[16] = { 0 }; 
    unsigned char received_iv[12]  = { 0 };
    /*
    int rssi = pkt->rx_ctrl.rssi;
    int8_t noise_floor = pkt->rx_ctrl.noise_floor;
    Serial.print("RSSI: ");
    Serial.println(rssi);
    Serial.print("Noise Floor: ");
    Serial.println(noise_floor);
    */     
    memcpy(llc_hdr, payload + 24, 8);
    uint8_t expected_llc_hdr[] = {0xAA, 0xAA, 0x03, 0xE1, 0xFA, 0x73, 0x00, 0x18};
    if (ptype == 2 && subtype == 0 && memcmp(llc_hdr, expected_llc_hdr, 8) == 0) {
        memcpy(entire_packet, payload, 96);        
        memcpy(received_iv, payload + 32, 12);
        memcpy(received_tag, payload + 44 , 16);
        memcpy(&payload_size, payload + 60, 1);
        memcpy(&plaintext_size, payload + 61, 1);        
        Serial.print("Received Encrypted Packet: ");
        for (size_t i = 0; i < FRAME_LENGTH; i++)
            Serial.print(entire_packet[i], HEX);
        Serial.print("\n");
        memcpy(encrypted_payload, payload + 62, plaintext_size);
        Serial.print("ciphertext: ");
        for (size_t i = 0; i < plaintext_size; i++)
            Serial.print(encrypted_payload[i], HEX);
        Serial.print("\n"); 

        Serial.print("IV: ");
        for (size_t i = 0; i < 12; i++)
            Serial.print(received_iv[i], HEX);
        Serial.print("\n");               
        Serial.print("Tag: ");
        for (size_t i = 0; i < 16; i++)
            Serial.print(received_tag[i], HEX);
        Serial.print("\n");                
        decrypt(encrypted_payload, payload_size - 1, out_session_key, received_iv, received_tag, decrypted_payload);
        Serial.print("Decrypted: ");
        for (size_t i = 0; i < plaintext_size - 1; i++)
            Serial.print((char)decrypted_payload[i]);        
        Serial.print("\n");        
    } 
    else 
    {
        return;
    }  
}

// Prepare the frame to be sent
void prepareFrame(uint8_t *frame, uint8_t *my_pubkey) {
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
}

// Send the frame and print it to the Serial
void sendRawFrameWithPublicKey() {
    uint8_t packet[FRAME_LENGTH] = {0};
    prepareFrame(packet, my_pubkey); 

    Serial.print("Transmitted PBK Packet :");                                   
    for (size_t i = 0; i < FRAME_LENGTH; i++)
        Serial.print(packet[i], HEX);
    Serial.print("\n");

    ESP_ERROR_CHECK( esp_wifi_start() );
    ESP_ERROR_CHECK( esp_wifi_set_protocol(WIFI_IF_STA, WIFI_PROTOCOL_11B|WIFI_PROTOCOL_11G|WIFI_PROTOCOL_11N|WIFI_PROTOCOL_LR) );
    ESP_ERROR_CHECK(esp_wifi_set_bandwidth(WIFI_IF_STA, WIFI_BW_HT40));
    ESP_ERROR_CHECK(esp_wifi_set_channel(primary_channel, WIFI_SECOND_CHAN_NONE));
    esp_wifi_set_max_tx_power(txpower);
    ESP_ERROR_CHECK( esp_wifi_config_80211_tx_rate(WIFI_IF_STA, WIFI_PHY_RATE_6M));  

    ESP_ERROR_CHECK_WITHOUT_ABORT(esp_wifi_80211_tx(WIFI_IF_STA, packet, sizeof(packet), true));
}

void prepareDataFrame(uint8_t *frame, uint8_t *payload, size_t payload_length) {
    // Define some of the frame fields:
    uint8_t frameControl[] = {0x08, 0x00}; // type = 2 (data), subtype = 0
    uint8_t duration[] = {0x00, 0x00};
    uint8_t seqControl[] = {0x00, 0x00};
    uint8_t LLCHeader[] = {0xAA, 0xAA, 0x03, 0xE1, 0xFA, 0x73, 0x00, 0x18};
    uint8_t payload_size = sizeof(ciphertext);
    uint8_t plaintext_size = sizeof(plaintext);

    // Construct the frame:
    memcpy(frame, frameControl, 2);
    memcpy(frame + 2, duration, 2);
    memcpy(frame + 4, broadcastAddress, 6);
    memcpy(frame + 10, mac_own, 6);
    memcpy(frame + 16, mac_own, 6); // using the sender MAC address as BSSID
    memcpy(frame + 22, seqControl, 2);
    memcpy(frame + 24, LLCHeader, 8);
    memcpy(frame + 32, iv, 12);
    memcpy(frame + 44, tag, 16);    
    // appending the payload
    memcpy(frame + 60, &payload_size, 1);
    memcpy(frame + 61, &plaintext_size, 1); 
    memcpy(frame + 62, payload, payload_length);
}

void sendRawFrameWithPayload(uint8_t *payload, size_t payload_length) {
    uint8_t packet[FRAME_LENGTH] = {0};
    prepareDataFrame(packet, payload, payload_length); 

    Serial.print("Transmitted Data Packet :");                                   
    for (size_t i = 0; i < FRAME_LENGTH; i++)
        Serial.print(packet[i], HEX);
    Serial.print("\n");

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
  genkeyx25519(my_pubkey, my_privkey);

  Serial.print("PUBKEY: ");                                           // Print local PUB KEY to Serial
  for (size_t i = 0; i < sizeof(my_pubkey); i++)      
        Serial.print(my_pubkey[i], HEX);
  Serial.print("\n");

  initWiFi();
  Serial.print("Finished Set up \n");
  Serial.print("Listening State \n");

}
// Listen, then broadcast own Pubkey 5 times, return if received other's pub key.
void loop() {
    if (currentState == StateBroadcasting) {
        sendRawFrameWithPublicKey();
        delay(100);
        broadcastCount++;
        if (broadcastCount >= maxBroadcastCount) {
            currentState = StateListening;
            Serial.println("Switching to Listening State");
            delay(1000);
            if (keyReceived) {
                //keyReceived = false;  // Reset the flag for the next iteration
                Serial.print("Received PubKey: ");
                for (size_t i = 0; i < sizeof(received_pubkey); i++)
                    Serial.print(received_pubkey[i], HEX);
                Serial.print("\n");

                calcsecretx25519(my_privkey, received_pubkey, shared_secret);
                Serial.print("Shared Secret : ");
                for (size_t i = 0; i < sizeof(shared_secret); i++)
                    Serial.print(shared_secret[i], HEX);
                Serial.print("\n");
                
                generate_session_key(shared_secret, sizeof(out_session_key), out_session_key);
                Serial.print("Session Key: ");
                for (size_t i = 0; i < sizeof(out_session_key); i++)
                    Serial.print(out_session_key[i], HEX);
                Serial.print("\n");
                return;
            }           
            else {
                Serial.println("No PubKey received, switching back to Broadcasting State");
                //memset(received_pubkey, 0, sizeof(received_pubkey));  // Reset received_pubkey to zero
                broadcastCount = 0;
                currentState = StateBroadcasting;
                delay(1000);
            }
        }
        delay(1000);  // Send every second, adjust as needed
    }

    if (currentState == StateListening && keyReceived && isNotZero(out_session_key, 32)) {

      /* 
        encrypt(plaintext, sizeof(plaintext) - 1, out_session_key, iv, ciphertext, tag);
        Serial.print("IV: ");
        for (size_t i = 0; i < 12; i++)
            Serial.print(iv[i], HEX);
        Serial.print("\n");
        Serial.print("Tag: ");
        for (size_t i = 0; i < 16; i++)
            Serial.print(tag[i], HEX);
        Serial.print("\n");
        Serial.print("Ciphertext: ");
        for (size_t i = 0; i < sizeof(ciphertext) - 1; i++)
            Serial.print(ciphertext[i], HEX);
        Serial.print("\n");
        for (size_t i = 0; i < 10; i++) {
            sendRawFrameWithPayload(ciphertext, sizeof(ciphertext));
            delay(1000);            
        }
      */      
        esp_wifi_set_promiscuous_rx_cb(&promiscuous_payload_Callback);
        delay(1000);
        currentState = Standby; 
    }
}    
