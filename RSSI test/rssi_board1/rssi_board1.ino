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

// BOARD 1

uint8_t broadcastAddress[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};  // Broadcast MAC address for everyone in the network
uint8_t mac_own[6];
unsigned char frame_filler[32] = {0};
int primary_channel = 13;
int txpower = 40;

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
  //esp_wifi_set_promiscuous_rx_cb(&promiscuousCallback);
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

// Prepare the frame to be sent
void prepareFrame(uint8_t *frame) {
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
    memcpy(frame + 24, LLCHeader, 8); // appending the llc
    memcpy(frame + 32, frame_filler, 32); // appending thefiller
}

// Send the frame and print it to the Serial
void sendRawFrame() {
    uint8_t packet[256] = {0};
    prepareFrame(packet); 

    Serial.println("Transmitted a frame");                                   

    ESP_ERROR_CHECK( esp_wifi_start() );
    ESP_ERROR_CHECK( esp_wifi_set_protocol(WIFI_IF_STA, WIFI_PROTOCOL_11B|WIFI_PROTOCOL_11G|WIFI_PROTOCOL_11N|WIFI_PROTOCOL_LR) );
    ESP_ERROR_CHECK(esp_wifi_set_bandwidth(WIFI_IF_STA, WIFI_BW_HT40));
    ESP_ERROR_CHECK(esp_wifi_set_channel(primary_channel, WIFI_SECOND_CHAN_NONE));
    esp_wifi_set_max_tx_power(txpower);
    ESP_ERROR_CHECK( esp_wifi_config_80211_tx_rate(WIFI_IF_STA, WIFI_PHY_RATE_6M));
    ESP_ERROR_CHECK_WITHOUT_ABORT(esp_wifi_80211_tx(WIFI_IF_STA, packet, sizeof(packet), true));
}

void setup() {
  // put your setup code here, to run once:
  Serial.begin(115200);
  initWiFi();

}

void loop() {
  // put your main code here, to run repeatedly:
  sendRawFrame();
  delay(100);

}
