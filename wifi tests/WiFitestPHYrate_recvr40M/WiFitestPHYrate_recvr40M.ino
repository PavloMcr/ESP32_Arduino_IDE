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

QueueHandle_t wifisd_queue;

//display
Adafruit_SH1107 display = Adafruit_SH1107(64, 128, &Wire);

static const char* TAG="sneha";

//Event handlers for Wi-Fi
static EventGroupHandle_t wifi_event_group;

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

  //NEW CODE
  //int rssi;

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

  //NEW CODE
  //int rssi;


} __attribute__ ((packed));

//uint8_t mac_bcast[6] = {0x7C,0xDF,0xA1,0xE8,0x3,0x10}; //P1_N8R8
uint8_t mac_bcast[6] = {0xF4,0x12,0xFA,0xE3,0x59,0xB0}; //M0_N8R8
uint8_t mac_own[6];

//New Code
struct Rxbuf
{
  int16_t rssi;
  int16_t noise;
  uint8_t source[6];
  uint8_t channel;
  uint8_t dummy; // add info about bitrate
  uint32_t sec;
  uint32_t usec;
  uint16_t sequence;
  uint16_t pkt_size;
} __attribute__ ((packed));
//New Code

struct bandwidth_action 
{
  wifi_ieee80211_data hdr;
  bool bw40; // true=40mhz, false=20mhz
  int primary_channel;
  int secondary_channel; // WIFI_SECOND_CHAN_ABOVE or WIFI_SECOND_CHAN_NONE
  int txpower; // in 0.25dBm steps
  
  //NEW CODE
  //int rssi;
};

bool bw40 = false;
int primary_channel = 9;
int secondary_channel = WIFI_SECOND_CHAN_NONE;
int txpower = 40;



//Setups for Display, SD Card, Time and Wi-Fi
/*void setup_display()
{
  // For intializing display
  Wire.begin(8, 9, 800000);
  delay(250); // wait for the OLED to power up
  display.begin(0x3C, true);
  display.setRotation(1);
  display.setCursor(0,0);
  display.setTextSize(1);
  display.setTextColor(SH110X_WHITE);

  // Clear the buffer.
  display.setRotation(1);
  display.clearDisplay();
  display.display();  
}
*/
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

  //NEW CODE
  //ESP_ERROR_CHECK(esp_wifi_rxctrl_t(rssi));

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
    
    //New Code
    Rxbuf buf;
    buf.rssi = pkt->rx_ctrl.rssi;
    buf.noise = pkt->rx_ctrl.noise_floor;
        
    buf.channel = pkt->rx_ctrl.channel;
    buf.dummy = 0;
    buf.pkt_size = pkt->rx_ctrl.sig_len;

    buf.sequence = frame->sequence_ctrl >> 4; // without fragment, always 0

    

        


    //Serial.printf("%i,%i,%i,%i\n",bw40,primary_channel,secondary_channel,txpower);

    settings_changed = true;
    settings_timestamp = millis();

    //Timestamp       
    Serial.printf("%i,%i,%i,%i\n",buf.rssi,buf.noise,buf.sequence,settings_timestamp);
    //New Code

  }
}

// NEW Code

struct StaStatistics
{
  uint64_t mac;
  uint32_t rcv_count = 0;
  int16_t rssi = 0;
  int16_t noise = 0;
  float pdr = 0;
  float kbitspersec = 0;

  uint64_t measurement_begin = 0; // timestamp of when the measurement began in milliseconds
  uint32_t measurement_pkts = 0; // number of received packets
  uint32_t measurement_pkts_missing = 0;  // based on skipped sequence numbers
  uint32_t measurement_size = 0; // sum of size of all received packets
  uint16_t last_sequence;

  StaStatistics(uint64_t mac) : mac(mac) { }
};

std::map<uint64_t, StaStatistics*> stats;

// NEW Code
/*
void wifisd_receiver_handler( void * pvParameters ){

  while(true){
    Rxbuf buf;
    StaStatistics* stat;
    stat = new StaStatistics(1);

    stat->measurement_begin = millis();
    stat->measurement_pkts += 1;
    stat->measurement_pkts_missing = 0;
    stat->measurement_size = buf.pkt_size;
    stat->last_sequence = buf.sequence;

    stat->measurement_pkts_missing = uint16_t(buf.sequence - stat->last_sequence) - 1;
    
    stat->last_sequence = buf.sequence;
    
    // update statistics
    stat->rcv_count++;
    stat->rssi = buf.rssi;
    stat->noise = buf.noise;

    Serial.printf("%i\n",stat->measurement_pkts_missing);

    
  }  
}
*/


void setup() {
  Serial.begin(115200);
 // setup_display();
  setup_wifi();
  pinMode(11,OUTPUT);
  digitalWrite(11,LOW);
  
  // activate the wifi monitor
  esp_wifi_set_promiscuous(true);
  //NEW Code here
  Serial.print("Finished Set up \n");
  neopixelWrite(RGB_BUILTIN,0,RGB_BRIGHTNESS,0);
  delay(500);
  neopixelWrite(RGB_BUILTIN,0,0,0);
  delay(500);

}








void loop() {
  
  neopixelWrite(RGB_BUILTIN,0,RGB_BRIGHTNESS,0); // Red
  delay(1000);
  //Serial.println("Receiving packets");  
  neopixelWrite(RGB_BUILTIN,0,0,0); // Off / black
  delay(1000);
  
  
  
  delay(100);
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
