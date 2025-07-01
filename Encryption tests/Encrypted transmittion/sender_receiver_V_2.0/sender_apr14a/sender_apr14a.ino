#include <WiFi.h>

#define CHANNEL 9

uint8_t destMac[6] = { 0xF4, 0x12, 0xFA, 0xE3, 0x59, 0xB0 };

struct mgs {
  wifi_pkt_rx_ctrl_t rx_ctrl; /**< metadata header */
  uint8_t payload[0];
} wifi_promiscuous_pkt_t;

void setup_wifi() {

  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&cfg));
  wifi_country_t wifi_country = { .cc = "DE", .schan = 1, .nchan = 13 };
  ESP_ERROR_CHECK(esp_wifi_set_country(&wifi_country)); /* set country for channel range [1, 13] */
  ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));

  // promiscuous mode

  esp_wifi_set_promiscuous(false);
  esp_wifi_set_promiscuous_rx_cb(&process_promisc);
  wifi_promiscuous_filter_t filter;
  filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT + WIFI_PROMIS_FILTER_MASK_DATA;
  ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&filter));
  ESP_ERROR_CHECK(esp_wifi_start());
  esp_read_mac(mac_own, ESP_MAC_WIFI_STA);
}

void process_promisc(void *buf, wifi_promiscuous_pkt_type_t type) {
  const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
  const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *)pkt->payload;
}

void setup() {

  Serial.begin(115200);
  setup_wifi();
  esp_wifi_set_promiscuous(true);
}

void loop() {
  // Wait for Wi-Fi to connect
  while (WiFi.status() != WL_CONNECTED) {
    delay(1000);
    Serial.println("Connecting to Wi-Fi...");
  }

  // Send the message
  uint8_t destMac[6] = DEST_MAC_ADDR;
  const char *message = "Hello, ESP32-S3!";
  esp_wifi_80211_tx(WIFI_IF_STA, (void *)message, strlen(message), true, destMac);

  Serial.println("Message sent!");

  // Wait for a moment before sending the next message
  delay(5000);
}
