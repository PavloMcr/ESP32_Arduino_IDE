
#include <WiFi.h>
#include <HTTPClient.h>
#include <AES32.h>
#include <esp32/aes.h>
#include <aes/esp_aes.h>
#include <esp_system.h>
#include <Wire.h>
#define BLOCK_SIZE 16 //the key size for AES-128 is 16 bytes

const char* ssid = "ESP32-Encryption-test";
const char* password = "StrongPassword123456789";

//Your IP address or domain name with URL path
const char* serverGetData = "http://192.168.4.1/getstring";


void bootloader_random_enable(void) {}

// Secret key
uint8_t aes_key[BLOCK_SIZE] = {0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09};

// Note: generate a random IV using a cryptographically secure random generator of course
uint8_t aes_iv[BLOCK_SIZE] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
                              
uint8_t *encrypted, *decrypted;
int decrypted_len;
AES32 aes32;


void decrypt(uint8_t* enciphered, int enciphered_length, uint8_t** output, int *output_length)
{
  uint8_t *deciphered = (uint8_t *) calloc(enciphered_length - BLOCK_SIZE, sizeof(uint8_t)); 
  memcpy(aes_iv, enciphered, BLOCK_SIZE);
  aes32.decryptCBC(enciphered_length - BLOCK_SIZE, aes_iv, &enciphered[BLOCK_SIZE], deciphered);

  *output = deciphered;
  *output_length = enciphered_length - BLOCK_SIZE;
}



String received_data;


void print_key(uint8_t *key, int key_length) {
  for (int i = 0; i < key_length; i++) {
    if (key[i] < 16) {
      Serial.print('0');
    }
    Serial.print(key[i], HEX);
  }
}

unsigned long previousMillis = 0;
const long interval = 5000; 

void setup() {
  Serial.begin(115200);
  aes32.setKey(aes_key, 128);  
  WiFi.begin(ssid, password);
  Serial.println("Connecting");
  while(WiFi.status() != WL_CONNECTED) { 
    delay(500);
    Serial.print(".");
  }
  Serial.println("");
  Serial.print("Connected to WiFi network with IP Address: ");
  Serial.println(WiFi.localIP());
}

void loop() {
  unsigned long currentMillis = millis();
  
  if(currentMillis - previousMillis >= interval) {
     // Check WiFi connection status
    if(WiFi.status()== WL_CONNECTED ){ 
      received_data = httpGETRequest(serverGetData);
      Serial.println("Received data: " + received_data);
      
      
      // save the last HTTP GET Request
      previousMillis = currentMillis;
    }
    else {
      Serial.println("WiFi Disconnected");
      delay(5000);
    }
  }

  
  
  //decrypt(encrypted, encrypted_len, &decrypted, &decrypted_len);

  
  //Serial.print("Decrypted data: ");
  //Serial.println((char *) decrypted);
  //Serial.print("Decrypted length (message + padding): ");
  //Serial.println(decrypted_len);
  Serial.println();
  //free(decrypted);
  delay(5000);

}

String httpGETRequest(const char* serverName) {
  WiFiClient client;
  HTTPClient http;
    
  // Your Domain name with URL path or IP address with path
  http.begin(client, serverName);
  
  // Send HTTP POST request
  int httpResponseCode = http.GET();
  
  String payload = "--"; 
  
  if (httpResponseCode>0) {
    Serial.print("HTTP Response code: ");
    Serial.println(httpResponseCode);
    payload = http.getString();
  }
  else {
    Serial.print("Error code: ");
    Serial.println(httpResponseCode);
  }
  // Free resources
  http.end();

  return payload;
}