#include <WiFi.h>
// other additional libs
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
#include <HardwareSerial.h>
// encryption libs
#include <AES32.h>
#include <esp32/aes.h>
#include <aes/esp_aes.h>
#include <esp_system.h>
// that should do with these libs

// #define BLOCK_SIZE 16 // the key size for AES-128 is 16 bytes

// void bootloader_random_enable(void) {} 
// Enable true random number generator, it should be enabled by default though

// Set up destination mac and custom action frame to recognize the messages easier

// Message encryption with AES-128

// Note: Secret key should be randomly generated, for now it is hardcoded for testing
// uint8_t aes_key[BLOCK_SIZE] = {0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00,
                               //0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09};

// Note: generate a random IV using a cryptographically secure random generator of course
// uint8_t aes_iv[BLOCK_SIZE] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                              //0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

// uint8_t *encrypted;
// int encrypted_len;

// AES32 aes32;

// Encryption including padding the message in 16 byte blocks
// void encrypt(uint8_t* data, int data_length, uint8_t** output, int *output_length)
/*{
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

  // Flash LED to indicate encryption successfull
  neopixelWrite(RGB_BUILTIN,0,RGB_BRIGHTNESS,0);
  delay(500);
  neopixelWrite(RGB_BUILTIN,0,0,0);
  delay(500);
}*/
HardwareSerial SerialT(0);


static const char* TAG="sneha";


TaskHandle_t wifisender_task;

//Semaphore for counter
SemaphoreHandle_t xSemaphore;
SemaphoreHandle_t queueSemaphore;



//Event handlers for Wi-Fi
static EventGroupHandle_t wifi_event_group;

static void event_handler(
  void *arg, esp_event_base_t event_base,
  int32_t event_id, void *event_data)
{
  ESP_LOGI(TAG, "wifi event: %i", event_id);
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


wifi_ieee80211_data

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

//Wi-Fi packet
struct my_frame_t 
{
  wifi_ieee80211_data hdr;
  char str[1500-4-sizeof(hdr)];
  char fcs[4];
};

/*
struct my_payload
{
    wifi_pkt_rx_ctrl_t rx_ctrl; // metadata header 
    uint8_t payload[0];         // Data or management payload. Length of payload is described by rx_ctrl.sig_len. Type of content determined by packet type argument of callback. 
} wifi_promiscuous_pkt_t;
*/

uint8_t mac_bcast[6] = {0x7C,0xDF,0xA1,0xE8,0x3,0x10}; //NODE 1 P1_N8R8
//uint8_t mac_bcast[6] = {0xF4,0x12,0xFA,0xE3,0x59,0xB0}; //NODE 2 M0_N8R8
uint8_t mac_own[6];


//For Data Rates
uint8_t rates[] = 
    {
        WIFI_PHY_RATE_2M_L,
        WIFI_PHY_RATE_2M_S,
        WIFI_PHY_RATE_5M_L,
        WIFI_PHY_RATE_5M_S,
        WIFI_PHY_RATE_11M_L,
        WIFI_PHY_RATE_11M_S,

        WIFI_PHY_RATE_6M,
        WIFI_PHY_RATE_9M,
        WIFI_PHY_RATE_12M,
        WIFI_PHY_RATE_18M,
        WIFI_PHY_RATE_24M,
        WIFI_PHY_RATE_36M,
        WIFI_PHY_RATE_48M,
        WIFI_PHY_RATE_54M,

        WIFI_PHY_RATE_MCS0_LGI,
        WIFI_PHY_RATE_MCS0_SGI,
        WIFI_PHY_RATE_MCS1_LGI,
        WIFI_PHY_RATE_MCS1_SGI,
        WIFI_PHY_RATE_MCS2_LGI,
        WIFI_PHY_RATE_MCS2_SGI,
        WIFI_PHY_RATE_MCS3_LGI,
        WIFI_PHY_RATE_MCS3_SGI,
        WIFI_PHY_RATE_MCS4_LGI,
        WIFI_PHY_RATE_MCS4_SGI,
        WIFI_PHY_RATE_MCS5_LGI,
        WIFI_PHY_RATE_MCS5_SGI,
        WIFI_PHY_RATE_MCS6_LGI,
        WIFI_PHY_RATE_MCS6_SGI,
        WIFI_PHY_RATE_MCS7_LGI,
        WIFI_PHY_RATE_MCS7_SGI,
    };



//Bandwidth
struct bandwidth_action 
{
  wifi_ieee80211_data hdr;
  bool bw40; // true=40mhz, false=20mhz
  int primary_channel;
  int secondary_channel; // WIFI_SECOND_CHAN_ABOVE or WIFI_SECOND_CHAN_NONE
  int txpower; // in 0.25dBm steps
};



void setup_wifi() {
 esp_err_t ret = nvs_flash_init();
  if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
      ret = nvs_flash_init();
  } 
  ESP_ERROR_CHECK( ret );
  ESP_LOGI(TAG, "initializing WiFi");
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
  ESP_ERROR_CHECK(esp_wifi_set_bandwidth(WIFI_IF_STA, WIFI_BW_HT40));
  ESP_ERROR_CHECK(esp_wifi_set_channel(9, WIFI_SECOND_CHAN_ABOVE));
  ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));
  esp_read_mac(mac_own, ESP_MAC_WIFI_STA); 
  ESP_ERROR_CHECK(esp_wifi_set_tx_done_cb(&my_tx_done_handler));

}



// Transmitt
void process_promisc(void *buf, wifi_promiscuous_pkt_type_t type)
{
  const wifi_promiscuous_pkt_t* pkt = (const wifi_promiscuous_pkt_t*)buf; // contains RSSI
  const wifi_ieee80211_data *hdr = (const wifi_ieee80211_data *)pkt->payload;

  if (hdr->version() == 0 && hdr->type() == WIFI_PKT_MGMT && hdr->subtype() == 0xD) {
    auto frame = (const wifi_ieee80211_action *)hdr;
    // check if vendor specific category (127) and our action type (142)
    if (frame->category == 127 ) { // && frame->action == 142
      int len= pkt->rx_ctrl.sig_len - sizeof(wifi_ieee80211_action) - 4; // FCS is 4 bytes CRC 
    }
    
  } else if (hdr->version() == 0 && hdr->type() == 0x02 && hdr->subtype() == 0x0) {
    auto frame = (const wifi_ieee80211_data *)hdr;
    // check if vendor specific category (127) and our action type (142)
    if (frame->LLC_CTRL == 0x03 && frame->organization_id == 0xE1FA73) {
      int len= pkt->rx_ctrl.sig_len - sizeof(wifi_ieee80211_data) - 4; // FCS is 4 bytes CRC     
    }    
  }
}



void setup() { 
  SerialT.begin(115200);
  Serial.begin(115200);
  setup_wifi();
 
  xSemaphore = xSemaphoreCreateBinary();
  queueSemaphore = xSemaphoreCreateCounting(7,7);

  xTaskCreatePinnedToCore(
                    &wifisd_sender_handler,   /* Task function. */
                    "wifisender_task",     /* name of task. */
                    10000,       /* Stack size of task */
                    NULL,        /* parameter of the task */
                    1,           /* priority of the task */
                    &wifisender_task,      /* Task handle to keep track of created task */
                    1);          /* pin task to core 1 */
  // activate the wifi monitor
  esp_wifi_set_promiscuous(true);
}


my_frame_t myframe;
int msgdonecount=0;
int msgtxokcount = 0;

void my_tx_done_handler(uint8_t ifidx, uint8_t *data, uint16_t *data_len, bool txStatus) {
  msgdonecount--;
  if (txStatus == true) msgtxokcount++;
  if (msgdonecount==0) xSemaphoreGive(xSemaphore); 
  xSemaphoreGive(queueSemaphore);
}

bandwidth_action bw_frame;

// frame needs to have bw40, channels and txpower set correctly
void send_bandwidth(bool bw40, int prim, int sec, int txpower) 
{
  ESP_ERROR_CHECK( esp_wifi_start() );  
  ESP_ERROR_CHECK( esp_wifi_set_protocol(WIFI_IF_STA, WIFI_PROTOCOL_11B|WIFI_PROTOCOL_11G|WIFI_PROTOCOL_11N|WIFI_PROTOCOL_LR) );
  ESP_ERROR_CHECK(esp_wifi_set_bandwidth(WIFI_IF_STA, (bw_frame.bw40)?WIFI_BW_HT40 : WIFI_BW_HT20));
  ESP_ERROR_CHECK(esp_wifi_set_channel(bw_frame.primary_channel, (wifi_second_chan_t)bw_frame.secondary_channel));      

  bw_frame.bw40 = bw40;
  bw_frame.primary_channel = prim;
  bw_frame.secondary_channel =  sec;
  bw_frame.txpower = txpower;
 
  // set the bitrate to something safe, eg. 6Mbps
  ESP_ERROR_CHECK( esp_wifi_config_80211_tx_rate(WIFI_IF_STA, WIFI_PHY_RATE_6M));
    
  // set txpower to something safe, eg. 40
  esp_wifi_set_max_tx_power(40);

  while(true){
    // SerialT.printf("# setting bw and channel to %i, %i, %i, %i\n",
    // bw_frame.bw40, bw_frame.primary_channel, bw_frame.secondary_channel, bw_frame.txpower);
    msgdonecount=1;
    msgtxokcount=0;
  
    // send the frame
    ESP_ERROR_CHECK_WITHOUT_ABORT(esp_wifi_80211_tx(WIFI_IF_STA, &bw_frame, sizeof(bw_frame), true)); // sender command
  
    // sleep on the binary semaphore
    if (xSemaphoreTake(xSemaphore,10000) == pdFALSE) {
      ESP_LOGI(TAG, "ERROR");
     }
  
    // check msgtxokcount, if 0 repeat from (1)
    if(msgtxokcount==1) break; 
  }  

  ESP_ERROR_CHECK( esp_wifi_stop() );  
  vTaskDelay(500);
}


void measure_throughput(int phase, int index)
{
  ESP_ERROR_CHECK( esp_wifi_start() );  
  ESP_ERROR_CHECK( esp_wifi_set_protocol(WIFI_IF_STA, WIFI_PROTOCOL_11B|WIFI_PROTOCOL_11G|WIFI_PROTOCOL_11N|WIFI_PROTOCOL_LR) );
  
  // now we can change bandwidth, channel
  ESP_ERROR_CHECK(esp_wifi_set_bandwidth(WIFI_IF_STA, (bw_frame.bw40)?WIFI_BW_HT40 : WIFI_BW_HT20));
  ESP_ERROR_CHECK(esp_wifi_set_channel(bw_frame.primary_channel, (wifi_second_chan_t)bw_frame.secondary_channel));             
  ESP_ERROR_CHECK(esp_wifi_config_80211_tx_rate(WIFI_IF_STA, (wifi_phy_rate_t)rates[index]));

  // send burst of 147 packets----200KB or more
  int msgcount = 5*1024/1400+1; //50 instead of 200 --> 37 packets
  msgdonecount = msgcount;
  msgtxokcount = 0;

  int64_t tx_start = esp_timer_get_time();
     
  for (int i=0; i<msgcount; i++) {
    if (xSemaphoreTake(queueSemaphore,10000) == pdFALSE) {
      ESP_LOGI(TAG, "ERROR");
    }
    esp_wifi_set_max_tx_power(bw_frame.txpower);
    esp_err_t res = esp_wifi_80211_tx(WIFI_IF_STA, &myframe, sizeof(myframe), false);
    ESP_ERROR_CHECK_WITHOUT_ABORT(res);
    if (res == 0) {
      myframe.hdr.sequence_ctrl += (1<<4);
    //packetsent++;
    }
  }
  if (xSemaphoreTake(xSemaphore,10000) == pdFALSE) {
    ESP_LOGI(TAG, "ERROR");
  }
  ESP_ERROR_CHECK( esp_wifi_stop() );
    

  int64_t tx_stop = esp_timer_get_time();  
  int64_t tx_diff = tx_stop-tx_start;
  float pdr = float(msgtxokcount) / msgcount * 100.0;
  float thr = float(msgtxokcount*sizeof(myframe.str)) / tx_diff *1000*1000; // bytes per second
  //ESP_LOGI(TAG,"rateidx:%i PDR:%3.0f%% Throughput:%4.2f kBps ", index, pdr,thr/1024);
  SerialT.printf("%i,%i,%i,%.3f,%.3f,%2.2f,%i,%i\n", 
    phase, index, msgtxokcount*sizeof(myframe.str), pdr, thr/1024,
    bw_frame.txpower*0.25, bw_frame.bw40, bw_frame.primary_channel);

  vTaskDelay(100);
}

uint8_t powerlevels[] = {8, 20, 28, 34, 44, 52, 56, 60, 66, 72, 80};

//Wi_Fi Sender 
void wifisd_sender_handler( void * pvParameters )
{ 
  // Data Frame  
  bw_frame.hdr.frame_ctrl = 0x0008; 
  bw_frame.hdr.duration_id = 0;
  memcpy(bw_frame.hdr.addr1, mac_bcast, sizeof(bw_frame.hdr.addr1)); // receiver
  memcpy(bw_frame.hdr.addr2, mac_own, sizeof(bw_frame.hdr.addr2)); // sender
  memcpy(bw_frame.hdr.addr3, mac_own, sizeof(bw_frame.hdr.addr3)); // filtering is BSSID
  //memcpy(bw_frame.hdr.addr4, mac_own, sizeof(bw_frame.hdr.addr4)); // n/a
  bw_frame.hdr.sequence_ctrl = 0; // filled in by esp_wifi_80211_tx()
  bw_frame.hdr.OLPC = 0x0000;
  bw_frame.hdr.LLC_DSAP = 0xAA;
  bw_frame.hdr.LLC_SSAP = 0xAA;
  bw_frame.hdr.LLC_CTRL = 0x03;
  bw_frame.hdr.organization_id = 0xE1FA73;
  bw_frame.hdr.protocol_id = 0x18;
  bw_frame.bw40 = false;
  bw_frame.primary_channel = 9;
  bw_frame.secondary_channel = WIFI_SECOND_CHAN_NONE;
  bw_frame.txpower = 40;

  // initialize the frame header
  myframe.hdr.frame_ctrl = 0x0008; // Data Frame
  myframe.hdr.duration_id = 0;
  memcpy(myframe.hdr.addr1, mac_bcast, sizeof(myframe.hdr.addr1)); // receiver
  memcpy(myframe.hdr.addr2, mac_own, sizeof(myframe.hdr.addr2)); // sender
  memcpy(myframe.hdr.addr3, mac_own, sizeof(myframe.hdr.addr3)); // filtering is BSSID
  //memcpy(myframe.hdr.addr4, mac_own, sizeof(myframe.hdr.addr4)); // n/a
  myframe.hdr.sequence_ctrl = 0; // filled in by esp_wifi_80211_tx()
  myframe.hdr.OLPC = 0x0000;
  myframe.hdr.LLC_DSAP = 0xAA;
  myframe.hdr.LLC_SSAP = 0xAA;
  myframe.hdr.LLC_CTRL = 0x03;
  myframe.hdr.organization_id = 0xE1FA73;
  myframe.hdr.protocol_id = 0x17;
  //myframe.hdr.payload = "Hello world this is a test";
  
  // Sample data
  strncpy(myframe.str, "Hello world this is a test...", sizeof(myframe.str));

  ESP_ERROR_CHECK( esp_wifi_stop() );  
  vTaskDelay(100);

  SerialT.printf("phase,rate,bytes,pdr,throughput_kBps,txpower,bw40,prim_channel\n");

  int phase = 0;
  while (true) {
    
    //power
    for(int i=0; i<sizeof(powerlevels); i++){
      int txpower= powerlevels[i];
      send_bandwidth(false, 9, WIFI_SECOND_CHAN_NONE, txpower); 
      for (int index=0; index < sizeof(rates); index++) {
        //if (index >= 11 && index <= 13) continue;
        //if (index >= 24) continue;
        phase++;
        measure_throughput(phase, index);
        }
      
      send_bandwidth(true, 9, WIFI_SECOND_CHAN_ABOVE, txpower); 
      for (int index=14; index < sizeof(rates); index++) {
        //if (index >= 11 && index <= 13) continue;
        //if (index >= 24) continue;
        phase++;
        measure_throughput(phase, index);
        }
      }
    }    
}




void loop() {
  
  // Send a custom 802.11 action frame with the message payload
  // Encrypt the message
  // encrypt((uint8_t *) to_encrypt, strlen(to_encrypt), &encrypted, &encrypted_len);

}