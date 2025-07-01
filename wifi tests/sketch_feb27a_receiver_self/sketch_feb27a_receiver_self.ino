#include <ESP32Time.h>
#include <time.h>
#include <sys/time.h>
#include "RTClib.h"
#include "nvs_flash.h"
#include "freertos/event_groups.h"
#include "esp_wifi.h"
#include <map>
#include "esp_private/wifi.h"
#include <Wire.h>
#include <Adafruit_GFX.h>
#include <Adafruit_SH110X.h>



static void event_handler(
  void *arg, esp_event_base_t event_base,
  int32_t event_id, void *event_data)
{
  Serial.printf("wifi event: %i\n", event_id);
}


//Wi-Fi data frame
struct wifi_ieee80211_data 
{  
  uint16_t frame_ctrl;
  uint16_t duration_id;
  uint8_t addr1[6]; /* receiver address */
  uint8_t addr2[6]; /* sender address */
  uint8_t addr3[6]; /* filtering address */
  uint16_t sequence_ctrl;
  //uint8_t addr4[6]; //Only fromDS and ToDS is 1
  uint16_t OLPC; // mysterious stuff for OLPC mesh routing
  uint8_t LLC_DSAP; // 802.2 Logical Link Layer header, simplest variant
  uint8_t LLC_SSAP;
  uint8_t LLC_CTRL;
  uint32_t organization_id:24; // SNAP OUI
  uint16_t protocol_id; //SNAP Proto ID
  uint8_t payload[0]; /* network data ended with 4 bytes csum (CRC32) */
  int version() const { return (frame_ctrl >> 0) & 3; }
  int type() const { return (frame_ctrl >> 2) & 3; }
  int subtype() const { return (frame_ctrl >> 4) & 0xF; }
  int flags() const { return (frame_ctrl >> 8) & 0xFF; }
  int fragment() const { return (sequence_ctrl >> 0) & 0xF; }
  int sequence() const { return (sequence_ctrl >> 4) & 0xFFF; }
} __attribute__ ((packed));

// only for vendor specific action category
struct wifi_ieee80211_action 
{
  uint16_t frame_ctrl;
  uint16_t duration_id;
  uint8_t addr1[6]; /* receiver address */
  uint8_t addr2[6]; /* sender address */
  uint8_t addr3[6]; /* filtering address */
  uint16_t sequence_ctrl;
  uint8_t category;
  uint8_t organization_identifier[3]; // 0x18fe34
  uint8_t body[0];
  int version() const { return (frame_ctrl >> 0) & 3; }
  int type() const { return (frame_ctrl >> 2) & 3; }
  int subtype() const { return (frame_ctrl >> 4) & 0xF; }
  int flags() const { return (frame_ctrl >> 8) & 0xFF; }
  int fragment() const { return (sequence_ctrl >> 0) & 0xF; }
  int sequence() const { return (sequence_ctrl >> 4) & 0xFFF; }
} __attribute__ ((packed));

//uint8_t mac_bcast[6] = {0x7C,0xDF,0xA1,0xE8,0x3,0x10}; //P1_N8R8
uint8_t mac_bcast[6] = {0xF4,0x12,0xFA,0xE3,0x59,0xB0}; //M0_N8R8
uint8_t mac_own[6];

struct bandwidth_action 
{
  wifi_ieee80211_data hdr;
  bool bw40; // true=40mhz, false=20mhz
  int primary_channel;
  int secondary_channel; // WIFI_SECOND_CHAN_ABOVE or WIFI_SECOND_CHAN_NONE
  int txpower; // in 0.25dBm steps
};

bool bw40 = false;
int primary_channel = 9;
int secondary_channel = WIFI_SECOND_CHAN_NONE;
int txpower = 40;

void setup_wifi() {
 esp_err_t ret = nvs_flash_init();
  if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
      ret = nvs_flash_init();
  } 
  ESP_ERROR_CHECK( ret );
  Serial.println("initializing WiFi");
  ESP_ERROR_CHECK(esp_netif_init());
  wifi_event_group = xEventGroupCreate();
  ESP_ERROR_CHECK( esp_event_loop_create_default() );
  esp_event_handler_instance_t instance_any_id;
  ESP_ERROR_CHECK(esp_event_handler_instance_register(
  WIFI_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL, &instance_any_id));

  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&cfg));
  wifi_country_t wifi_country = {.cc="DE", .schan = 1, .nchan = 13};
  ESP_ERROR_CHECK( esp_wifi_set_country(&wifi_country) ); /* set country for channel range [1, 13] */
  ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM) ); 
  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA) );


  // sniff traffic
  esp_wifi_set_promiscuous(false);
  esp_wifi_set_promiscuous_rx_cb(&process_promisc);
  wifi_promiscuous_filter_t filter;
  filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT + WIFI_PROMIS_FILTER_MASK_DATA; //+ WIFI_PROMIS_FILTER_MASK_CTRL ; // + WIFI_PROMIS_FILTER_MASK_DATA_MPDU + WIFI_PROMIS_FILTER_MASK_DATA_AMPDU; // WIFI_PROMIS_FILTER_MASK_MGMT + WIFI_PROMIS_FILTER_MASK_CTRL + WIFI_PROMIS_FILTER_MASK_DATA + WIFI_PROMIS_FILTER_MASK_MISC + WIFI_PROMIS_FILTER_MASK_DATA_MPDU + WIFI_PROMIS_FILTER_MASK_DATA_AMPDU + WIFI_PROMIS_FILTER_MASK_FCSFAIL;
  ESP_ERROR_CHECK( esp_wifi_set_promiscuous_filter(&filter) );
  filter.filter_mask = WIFI_PROMIS_CTRL_FILTER_MASK_ALL;
  ESP_ERROR_CHECK( esp_wifi_set_promiscuous_ctrl_filter(&filter) );

  ESP_ERROR_CHECK( esp_wifi_start() );  
  ESP_ERROR_CHECK( esp_wifi_set_protocol(WIFI_IF_STA, WIFI_PROTOCOL_11B|WIFI_PROTOCOL_11G|WIFI_PROTOCOL_11N|WIFI_PROTOCOL_LR) );
  ESP_ERROR_CHECK(esp_wifi_set_bandwidth(WIFI_IF_STA, (bw40)?WIFI_BW_HT40 : WIFI_BW_HT20));
  ESP_ERROR_CHECK(esp_wifi_set_channel(primary_channel, (wifi_second_chan_t)secondary_channel));
  esp_wifi_set_max_tx_power(txpower);
  ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));
  esp_read_mac(mac_own, ESP_MAC_WIFI_STA); 
}


bool settings_changed = false;
unsigned long settings_timestamp;

//Receiver 
void process_promisc(void *buf, wifi_promiscuous_pkt_type_t type)
{
  const wifi_promiscuous_pkt_t* pkt = (const wifi_promiscuous_pkt_t*)buf; // RSSI packets , noise floor
  auto frame = (const wifi_ieee80211_data *)pkt->payload;

  if (frame->version() == 0 && frame->type() == WIFI_PKT_DATA && frame->subtype() == 0x00 && 
      frame->organization_id == 0xE1FA73 && frame->protocol_id == 0x18) {
    auto msg =  (const bandwidth_action*)pkt->payload;
    bw40 = msg->bw40;
    primary_channel = msg->primary_channel;
    secondary_channel = msg->secondary_channel;
    txpower = msg->txpower;
    //rssi = msg->rssi;
    Serial.printf("%i\n",bw40);
    //Serial.println(rssi);

    settings_changed = true;
    settings_timestamp = millis();
  }
}



void setup() {
  Serial.begin(115200);
  // setup_display();
  setup_wifi();
   
  // activate the wifi monitor
  esp_wifi_set_promiscuous(true);
  //Turn on Green LED
  neopixelWrite(RGB_BUILTIN,0,RGB_BRIGHTNESS,0); // Green
  Serial.println("Set up successful");
  delay(1000);
  neopixelWrite(RGB_BUILTIN,0,0,0); // Off / black
  delay(1000);
}

void loop() {


  
  delay(10);
  if (settings_changed == true) {
    if (millis() - settings_timestamp > 400) {
      settings_changed = false;
      Serial.printf("apply change %i,%i,%i,%i\n",bw40,primary_channel,secondary_channel,txpower);
      ESP_ERROR_CHECK(esp_wifi_set_bandwidth(WIFI_IF_STA, (bw40)?WIFI_BW_HT40 : WIFI_BW_HT20));
      ESP_ERROR_CHECK(esp_wifi_set_channel(primary_channel, (wifi_second_chan_t)secondary_channel));      
      // esp_wifi_set_max_tx_power(txpower);

      
    }
  }
  
}

