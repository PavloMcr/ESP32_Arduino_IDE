# ESP32 Cryptography and Wireless Communication Tests

This repository contains a collection of C++ test programs and prototypes developed for the ESP32 platform using the Arduino IDE. The projects focus primarily on cryptographic operations, secure communication, key exchange protocols, and signal measurement, intended for experimentation and validation in wireless and embedded environments.

## 📂 Repository Structure

- **AES_GCM-128**  
  Implementation of AES-GCM-128 encryption and decryption routines for secure message confidentiality and integrity.

- **ECDH_and_AES_GCM**  
  Combines Elliptic Curve Diffie-Hellman (ECDH) key exchange with AES-GCM encryption for secure peer-to-peer communication.

- **ECDH_test/sketch_jul31a_v.0.1**  
  Prototype sketch for evaluating ECDH key agreement between ESP32 devices.

- **ECDSA_test**  
  Tests for ECDSA (Elliptic Curve Digital Signature Algorithm) to validate digital signatures and message authentication.

- **Encryption tests**  
  Miscellaneous test cases exploring different encryption mechanisms and parameters.

- **PB_Key_Exc_in_Promisc**  
  Passive broadcast key exchange experiments under promiscuous Wi-Fi mode — useful for analyzing uncoordinated key establishment methods.

- **RSA/rsa_test**  
  RSA public-key encryption/decryption and key generation tests tailored for embedded constraints.

- **RSSI test**  
  Measures and logs Wi-Fi RSSI (Received Signal Strength Indicator) to assess signal quality in different environments.

- **wifi tests**  
  Basic Wi-Fi scanning, connection handling, and diagnostics for ESP32 connectivity evaluation.

## Requirements

- **Hardware:** ESP32 Development Board  
- **Software:** Arduino IDE with ESP32 board support  
- **Libraries:** May require additional cryptographic and Wi-Fi libraries (e.g., `WiFi.h`, `mbedtls`, `Crypto.h`)

## License

MIT License
