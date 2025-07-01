/*
 * ESP32 AES-128 Hardware Encryption in CBC mode
 * Enable the use of built-in AES hardware capabilities
 */

#include <AES32.h>
//new libraries
#include <esp32/aes.h>
#include <aes/esp_aes.h>
#include <esp_system.h>

#define BLOCK_SIZE 16 //the key size for AES-128 is 16 bytes

void bootloader_random_enable(void) {}

// Secret key
uint8_t aes_key[BLOCK_SIZE] = {0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09};

// Note: generate a random IV using a cryptographically secure random generator of course
uint8_t aes_iv[BLOCK_SIZE] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

// This function generates a random AES key

//void generate_aes_key(uint8_t* aes_key) {
//    esp_fill_random(aes_key, BLOCK_SIZE);
//}

// This function generates a random IV:

//void generate_aes_iv(uint8_t* aes_iv) {
//    esp_fill_random(aes_iv, BLOCK_SIZE);
//}

                              

uint8_t *encrypted, *decrypted;
int encrypted_len, decrypted_len;

char *to_encrypt = "This is the message that should look the same after being decrypted on the other device";

AES32 aes32;

void encrypt(uint8_t* data, int data_length, uint8_t** output, int *output_length)
{
  int data_length_padded = data_length % 16 == 0 ? data_length : (data_length - (data_length % 16)) + 16;

  uint8_t* enciphered = (uint8_t*) malloc((BLOCK_SIZE + data_length_padded) * sizeof(uint8_t));
  
  uint8_t* data_to_encrypt = (uint8_t*) calloc(data_length_padded, sizeof(uint8_t));
  memcpy(data_to_encrypt, data, data_length);
  memcpy(&enciphered[0], aes_iv, BLOCK_SIZE);

  size_t offset = 0;
  
  aes32.encryptCBC(data_length_padded, aes_iv, data_to_encrypt, &enciphered[BLOCK_SIZE]);

  *output = enciphered;
  *output_length = (BLOCK_SIZE + data_length_padded);

  free(data_to_encrypt);
}

void decrypt(uint8_t* enciphered, int enciphered_length, uint8_t** output, int *output_length)
{
  uint8_t *deciphered = (uint8_t *) calloc(enciphered_length - BLOCK_SIZE, sizeof(uint8_t)); 
  memcpy(aes_iv, enciphered, BLOCK_SIZE);
  aes32.decryptCBC(enciphered_length - BLOCK_SIZE, aes_iv, &enciphered[BLOCK_SIZE], deciphered);

  *output = deciphered;
  *output_length = enciphered_length - BLOCK_SIZE;
}

void print_key(uint8_t *key, int key_length) {
  for(int i = 0; i < key_length; i++)
  {
    if (key[i] < 16) {
      Serial.print('0');
    }
    
    Serial.print(key[i], HEX);
  }
}

void setup() {
  Serial.begin(115200);
  aes32.setKey(aes_key, 128);

  //end of new code

}

void loop() {

  //new code
  Serial.print("Encryption key in bits: ");
  print_key(aes_key, BLOCK_SIZE); //in bits
  
    
  //Serial.print("Encryption key in byte: "); //byte
  //for (int i = 0; i < 16; i++) {
  //  Serial.print(aes_key[i], HEX);
  //}
  //Serial.println();

  //Serial.print("Generated IV: ");
  //for (int i = 0; i < 16; i++) {
  //  Serial.print(aes_iv[i], HEX);
  //}



  encrypt((uint8_t *) to_encrypt, strlen(to_encrypt), &encrypted, &encrypted_len);

  Serial.println();
  Serial.print("Encrypted message: ");
  print_key(encrypted, encrypted_len);
  Serial.println();
  
  Serial.print("Encrypted length (iv + message + padding): ");
  Serial.println(encrypted_len);
  Serial.println();

  delay(5000);

  decrypt(encrypted, encrypted_len, &decrypted, &decrypted_len);

  
  Serial.print("Decrypted message: ");
  Serial.println((char *) decrypted);
  Serial.print("Decrypted length (message + padding): ");
  Serial.println(decrypted_len);
  Serial.println();
  
  free(encrypted);
  free(decrypted);
  
  delay(5000);
}