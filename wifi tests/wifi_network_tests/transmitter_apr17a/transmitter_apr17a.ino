
// Import required libraries
#include "WiFi.h"
#include "ESPAsyncWebServer.h"
#include <Wire.h>
/////////////////////////////
#include <AES32.h>
#include <esp32/aes.h>

#include <aes/esp_aes.h>
#include <esp_system.h>


// Set your access point network credentials
const char *ssid = "ESP32-Encryption-test";
const char *password = "StrongPassword123456789";


// Create AsyncWebServer object on port 80
AsyncWebServer server(80);

// Encryption part
#define BLOCK_SIZE 16  //the key size for AES-128 is 16 bytes

void bootloader_random_enable(void) {}
// Secret key
uint8_t aes_key[BLOCK_SIZE] = { 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00,
                                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09 };
// Note: generate a random IV using a cryptographically secure random generator of course
uint8_t aes_iv[BLOCK_SIZE] = { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
uint8_t *encrypted;
int encrypted_len;
// Message to encrypt
const char *to_encrypt = "This is the message";

AES32 aes32;

void encrypt(uint8_t *data, int data_length, uint8_t **output, int *output_length) {
  int data_length_padded = data_length % 16 == 0 ? data_length : (data_length - (data_length % 16)) + 16;
  uint8_t *enciphered = (uint8_t *)malloc((BLOCK_SIZE + data_length_padded) * sizeof(uint8_t));
  uint8_t *data_to_encrypt = (uint8_t *)calloc(data_length_padded, sizeof(uint8_t));
  memcpy(data_to_encrypt, data, data_length);
  memcpy(&enciphered[0], aes_iv, BLOCK_SIZE);
  size_t offset = 0;
  // Encrypt in CBC mode
  aes32.encryptCBC(data_length_padded, aes_iv, data_to_encrypt, &enciphered[BLOCK_SIZE]);
  *output = enciphered;
  *output_length = (BLOCK_SIZE + data_length_padded);
  free(data_to_encrypt);
}


void print_key(uint8_t *key, int key_length) {
  for (int i = 0; i < key_length; i++) {
    if (key[i] < 16) {
      Serial.print('0');
    }
    Serial.print(key[i], HEX);
  }
}



void setup() {
  // Serial port for debugging purposes
  Serial.begin(115200);
  aes32.setKey(aes_key, 128);
  Serial.println();
  
  encrypt((uint8_t *)to_encrypt, strlen(to_encrypt), &encrypted, &encrypted_len);

  Serial.println();
  Serial.print("Encrypted message: ");
  print_key(encrypted, encrypted_len);
  Serial.println();
  


  

  // Setting the ESP as an access point
  Serial.print("Setting AP (Access Point)…");
  // Remove the password parameter, if you want the AP (Access Point) to be open
  WiFi.softAP(ssid, password);

  IPAddress IP = WiFi.softAPIP();
  Serial.print("AP IP address: ");
  Serial.println(IP);

    

  server.on("/getstring", HTTP_GET, [](AsyncWebServerRequest *request);{
    request->send_P(200, "text/plain", );
  });
  
  



  // Start server
  server.begin();

  free(encrypted);
}

void loop() {

  /*encrypt((uint8_t *)to_encrypt, strlen(to_encrypt), &encrypted, &encrypted_len);

  Serial.println();
  Serial.print("Encrypted message: ");
  print_key(encrypted, encrypted_len);
  Serial.println();*/

  
  
}