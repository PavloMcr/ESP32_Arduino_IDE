#include "FS.h"
#include "SD.h"
#include "SPI.h"
#include <Wire.h>
#include "RTClib.h"
#include <Adafruit_GFX.h>
#include <Adafruit_SH110X.h>
#include <ESP32Time.h>
#include <time.h>
#include <sys/time.h>
#include "RTClib.h"
#include "nvs_flash.h"
#include "freertos/event_groups.h"
#include "esp_wifi.h"
#include <map>
#include "esp_private/wifi.h"

static const char* TAG="sneha";


QueueHandle_t wifisd_queue;

TaskHandle_t wifireceiver_task;
TaskHandle_t wifisender_task;

//For SDcard
#define SCK1  36
#define MISO1  37
#define MOSI1  35
#define CS  3

SPIClass spi1 = SPIClass(HSPI);
Adafruit_SH1107 display = Adafruit_SH1107(64, 128, &Wire);

// Time sync
ESP32Time rtc;
RTC_PCF8523 etc;

static EventGroupHandle_t wifi_event_group;

static void event_handler(
  void *arg, esp_event_base_t event_base,
  int32_t event_id, void *event_data)
{
  Serial.printf("wifi event: %i\n", event_id);
}

struct wifi_ieee80211_data 
{  
  uint16_t frame_ctrl;
  uint16_t duration_id;
  uint8_t addr1[6]; /* receiver address */
  uint8_t addr2[6]; /* sender address */
  uint8_t addr3[6]; /* filtering address */
  uint16_t sequence_ctrl;
  uint8_t addr4[6]; /* optional */
  uint8_t payload[0]; /* network data ended with 4 bytes csum (CRC32) */

  // https://mrncciew.com/2014/09/27/cwap-mac-header-frame-control/
  int version() const { return (frame_ctrl >> 0) & 3; }
  int type() const { return (frame_ctrl >> 2) & 3; }
  int subtype() const { return (frame_ctrl >> 4) & 0xF; }
  int flags() const { return (frame_ctrl >> 8) & 0xFF; }

  // https://mrncciew.com/2014/11/01/cwap-mac-header-sequence-control/
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
  //uint8_t action;
  //uint8_t elements[0]; /* network data ended with 4 bytes csum (CRC32) */
  uint8_t organization_identifier[3]; // 0x18fe34
  //uint8_t random_values[4];
  //uint8_t element_id;                 // 0xdd
  //uint8_t plength;                     //
  //uint8_t organization_identifier2[3]; // 0x18fe34
  //uint8_t ptype;                       // 4
  //uint8_t pversion;
  uint8_t body[0];
  
  // https://mrncciew.com/2014/09/27/cwap-mac-header-frame-control/
  int version() const { return (frame_ctrl >> 0) & 3; }
  int type() const { return (frame_ctrl >> 2) & 3; }
  int subtype() const { return (frame_ctrl >> 4) & 0xF; }
  int flags() const { return (frame_ctrl >> 8) & 0xFF; }

  // https://mrncciew.com/2014/11/01/cwap-mac-header-sequence-control/
  int fragment() const { return (sequence_ctrl >> 0) & 0xF; }
  int sequence() const { return (sequence_ctrl >> 4) & 0xFFF; }
} __attribute__ ((packed));

struct my_frame_t 
{
  wifi_ieee80211_action hdr;
  char str[250];
  char fcs[4];
};

uint8_t mac_bcast[6] = {0xF4,0x12,0xFA,0xE3,0x59,0xB0}; // Node M0N8R8
uint8_t mac_own[6];

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

struct Txbuf
{
  uint8_t txpwr;
  uint16_t br; //bitrate
  uint16_t sequence;
  uint16_t pkt_size;
  uint32_t sec;
  uint32_t usec;  
} __attribute__ ((packed));

void process_promisc(void *buf, wifi_promiscuous_pkt_type_t type)
{
  const wifi_promiscuous_pkt_t* pkt = (const wifi_promiscuous_pkt_t*)buf;
  const wifi_ieee80211_data *hdr = (const wifi_ieee80211_data *)pkt->payload;
  if (hdr->version() == 0 && hdr->type() == WIFI_PKT_MGMT && hdr->subtype() == 0xD) {
    auto frame = (const wifi_ieee80211_action *)hdr;
    // check if vendor specific category (127) and our action type (142)
    if (frame->category == 127 ) { // && frame->action == 142
      int len= pkt->rx_ctrl.sig_len - sizeof(wifi_ieee80211_action) - 4; // FCS is 4 bytes CRC
            
      struct timeval tms;
      gettimeofday(&tms, NULL);
      time_t t = time(NULL);

      Rxbuf buf;
      buf.rssi = pkt->rx_ctrl.rssi;
      buf.noise = pkt->rx_ctrl.noise_floor;
      memcpy(buf.source, hdr->addr2, 6);    
      buf.channel = pkt->rx_ctrl.channel;
      buf.dummy = 0;
      buf.sec = t;
      buf.usec = tms.tv_usec;
      buf.sequence = frame->sequence_ctrl >> 4; // without fragment, always 0
      buf.pkt_size = pkt->rx_ctrl.sig_len;

      if (xQueueSend(wifisd_queue, &buf, 0) != pdTRUE) {
        // TODO raise the red alert light, queue overrun should not happen
      } 
 
    }
  }
}



void setup_display()
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

void setup_sdcard()
{
  spi1.begin(SCK1, MISO1, MOSI1, CS);
  if (!SD.begin(CS,spi1,40000000)) {
    ESP_LOGI(TAG,"Card Mount Failed");
    while(1){};
  }  
  uint64_t cardSize = SD.cardSize() / (1024 * 1024);
  ESP_LOGI(TAG,"SD Card Size: %lluMB\n", cardSize);
  ESP_LOGI(TAG,"Total space: %lluMB\n", SD.totalBytes() / (1024 * 1024));
  ESP_LOGI(TAG,"Used space: %lluMB\n", SD.usedBytes() / (1024 * 1024));
}

void setup_time()
{
  if (! etc.begin()) {
    Serial.println("Couldn't find ERTC");
    //Serial.flush();
    while (1) delay(10);
  }

  if (! etc.initialized() || etc.lostPower()) {
    Serial.print("ERTC is NOT initialized, let's set the time!");
    etc.adjust(DateTime(F(__DATE__), F(__TIME__)));
  }
  etc.start();
  DateTime now = etc.now();
  rtc.setTime(now.second(), now.minute(), now.hour(), now.day(), now.month(), now.year());
}

void setup_wifi() {
 esp_err_t ret = nvs_flash_init();
  if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
      //ESP_ERROR_CHECK(nvs_flash_erase());
      ret = nvs_flash_init();
  } 
  ESP_ERROR_CHECK( ret );

  Serial.println("initializing WiFi");
  ESP_ERROR_CHECK(esp_netif_init());
  wifi_event_group = xEventGroupCreate();
  ESP_ERROR_CHECK( esp_event_loop_create_default() );
  //ESP_ERROR_CHECK( esp_event_loop_init(&event_handler, NULL) );
  esp_event_handler_instance_t instance_any_id;
  ESP_ERROR_CHECK(esp_event_handler_instance_register(
    WIFI_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL, &instance_any_id));

  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK(esp_wifi_init(&cfg));
  wifi_country_t wifi_country = {.cc="DE", .schan = 1, .nchan = 13};
  ESP_ERROR_CHECK( esp_wifi_set_country(&wifi_country) ); /* set country for channel range [1, 13] */
  ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM) );
  //ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL) );
  
  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA) );

//  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
//  wifi_config_t ap_config;
//  strncpy((char*)ap_config.ap.ssid, "esp32-beaconspam", 32);
//  ap_config.ap.ssid_len = 0;
//  strncpy((char*)ap_config.ap.password, "dummypassword", 16);
//  ap_config.ap.channel = 13;
//  ap_config.ap.authmode = WIFI_AUTH_WPA2_PSK;
//  ap_config.ap.ssid_hidden = 1;
//  ap_config.ap.max_connection = 4;
//  ap_config.ap.beacon_interval = 60000;
//  ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap_config));

  // sniff traffic
  esp_wifi_set_promiscuous(false);
  esp_wifi_set_promiscuous_rx_cb(&process_promisc);
  wifi_promiscuous_filter_t filter;
  filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT; //+ WIFI_PROMIS_FILTER_MASK_CTRL ; //+ WIFI_PROMIS_FILTER_MASK_DATA + WIFI_PROMIS_FILTER_MASK_DATA_MPDU + WIFI_PROMIS_FILTER_MASK_DATA_AMPDU; // WIFI_PROMIS_FILTER_MASK_MGMT + WIFI_PROMIS_FILTER_MASK_CTRL + WIFI_PROMIS_FILTER_MASK_DATA + WIFI_PROMIS_FILTER_MASK_MISC + WIFI_PROMIS_FILTER_MASK_DATA_MPDU + WIFI_PROMIS_FILTER_MASK_DATA_AMPDU + WIFI_PROMIS_FILTER_MASK_FCSFAIL;
  ESP_ERROR_CHECK( esp_wifi_set_promiscuous_filter(&filter) );
  filter.filter_mask = WIFI_PROMIS_CTRL_FILTER_MASK_ALL;
  ESP_ERROR_CHECK( esp_wifi_set_promiscuous_ctrl_filter(&filter) );

  ESP_ERROR_CHECK( esp_wifi_start() );  
  ESP_ERROR_CHECK( esp_wifi_set_protocol(WIFI_IF_STA, WIFI_PROTOCOL_11B|WIFI_PROTOCOL_11G|WIFI_PROTOCOL_11N|WIFI_PROTOCOL_LR) );
  ESP_ERROR_CHECK(esp_wifi_set_bandwidth(WIFI_IF_STA, WIFI_BW_HT20));
  ESP_ERROR_CHECK(esp_wifi_set_channel(13, WIFI_SECOND_CHAN_NONE));
  ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));
  esp_read_mac(mac_own, ESP_MAC_WIFI_STA); // SOFTAP);

}


char basepath[100];

void setup() {
  
  Serial.begin(115200);
  setup_display();
  setup_sdcard();
  setup_time();
  setup_wifi();

  snprintf(basepath, 100, "/%x%x%x%x%x%x", mac_own[0], mac_own[1], mac_own[2], mac_own[3], mac_own[4], mac_own[5]);
  SD.mkdir(basepath);
  SD.mkdir(String(basepath)+"/wifirx");
  SD.mkdir(String(basepath)+"/wifitx");

  delay(500);

  //Queue initialising for Sd
  wifisd_queue = xQueueCreate(200, sizeof(Rxbuf)); 
  if(wifisd_queue == NULL){
    ESP_LOGI(TAG,"Error creating the queue");
  } 

  xTaskCreatePinnedToCore(
                    &wifisd_receiver_handler,   /* Task function. */
                    "wifireceiver_task",     /* name of task. */
                    10000,       /* Stack size of task */
                    NULL,        /* parameter of the task */
                    1,           /* priority of the task */
                    &wifireceiver_task,      /* Task handle to keep track of created task */
                    1);          /* pin task to core 1 */
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

uint64_t mac2int(uint8_t* addr) {
  uint64_t mac = 0;
  mac = (mac << 8) + addr[0];
  mac = (mac << 8) + addr[1];
  mac = (mac << 8) + addr[2];
  mac = (mac << 8) + addr[3];
  mac = (mac << 8) + addr[4];
  mac = (mac << 8) + addr[5];
  return mac;
}


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


void wifisd_receiver_handler( void * pvParameters ){
  
  int flushcount = 0; 
  File dataFile;
  int file_hour = 0;
  
  while(true){
    Rxbuf buf; 
    xQueueReceive(wifisd_queue, &buf, portMAX_DELAY);

    // look up the statistics for the sender mac or create a new entry
    auto mac = mac2int(buf.source);
    auto iter = stats.find(mac);
    StaStatistics* stat;
    if (iter == stats.end()) {
      stat = new StaStatistics(mac);
      stats.insert(std::make_pair(mac,stat));
      
      stat->measurement_begin = millis();
      stat->measurement_pkts = 1;
      stat->measurement_pkts_missing = 0;
      stat->measurement_size = buf.pkt_size;
      stat->last_sequence = buf.sequence;
    } else {
      stat = iter->second;
      
      stat->measurement_pkts += 1;
      stat->measurement_size += buf.pkt_size;

      // New sequence should be one above last sequence, except when we lost packets inbetween.
      // The arithmetic accounts for the 16bit rollover of the sequence number.
      // This code does not account for restarts of the sender, that is if the sequence jumps back to 0 without rollover.
      // In that case, the pkts_missing would be unreasonable high. We could detect this by making assumptions about the packet send rate.
      stat->measurement_pkts_missing = uint16_t(buf.sequence - stat->last_sequence) - 1;

      stat->last_sequence = buf.sequence;
    }

    // update statistics
    stat->rcv_count++;
    stat->rssi = buf.rssi;
    stat->noise = buf.noise;

    // calculate PDR and Throughput every 10s
    uint64_t measurement_now = millis();
    uint64_t elapsed = uint64_t(measurement_now - stat->measurement_begin);
    if (elapsed >= 10*1000) {
      stat->pdr = float(stat->measurement_pkts)/float(stat->measurement_pkts + stat->measurement_pkts_missing); // pdr = received / expected
      stat->kbitspersec = float(stat->measurement_size*8) / float(elapsed) *1000/1000;  // converted from bytes to bits, ms to sec, bps to kbps

      stat->measurement_begin = measurement_now;
      stat->measurement_pkts = 0;
      stat->measurement_pkts_missing = 0;
      stat->measurement_size = 0;
      stat->last_sequence = buf.sequence;      

      //NEW CODE
      Serial.printf("%i\n",stat->pdr);
    }
    
    struct tm timeinfo;
    time_t unix_sec = buf.sec; // implicit type conversion
    localtime_r(&unix_sec, &timeinfo);

    if (dataFile && file_hour != timeinfo.tm_hour) {
      dataFile.close();
    }
    
    if (!dataFile) {
      file_hour = timeinfo.tm_hour;
      char s[51];
      strftime(s, 50, "%Y%m%d_%H%M%S", &timeinfo);
      char filename[100];
      snprintf(filename, 100, "%s/wifirx/%s.bin", basepath, s);
      dataFile = SD.open(filename, FILE_WRITE);
    }
    
    if (dataFile) {
      dataFile.write(reinterpret_cast<uint8_t*>(&buf), sizeof(Rxbuf));
    }
    
    flushcount++;
    if (flushcount == 50) {
      dataFile.flush();
      flushcount = 0;
    }
  }

  dataFile.close();  
}

void wifisd_sender_handler( void * pvParameters )
{ 
  int flushcount = 0; 
  File dataFile;
  int file_hour = 0;

  // initialize the frame header
  my_frame_t myframe;
  myframe.hdr.frame_ctrl = 0xD0; //Action frame mgmt packet
  myframe.hdr.duration_id = 0;
  memcpy(myframe.hdr.addr1, mac_bcast, sizeof(myframe.hdr.addr1)); // receiver
  memcpy(myframe.hdr.addr2, mac_own, sizeof(myframe.hdr.addr2)); // sender
  memcpy(myframe.hdr.addr3, mac_own, sizeof(myframe.hdr.addr3)); // filtering is BSSID
  myframe.hdr.sequence_ctrl = 0; // filled in by esp_wifi_80211_tx()
  myframe.hdr.category = 127;
  //myframe.hdr.action = 142;
  //strncpy(myframe.str, "Hello world this is sneha speaking...", sizeof(myframe.str));
  myframe.hdr.organization_identifier[0]= 0x11; // 0x18fe34
  myframe.hdr.organization_identifier[1]= 0x11; // 0x18fe34
  myframe.hdr.organization_identifier[2]= 0x11; // 0x18fe34

  //myframe.hdr.body[0];
  strncpy(myframe.str, "Hello world this is sneha speaking...", sizeof(myframe.str));
  
  // timer for periodic 1s intervals
  TickType_t xLastWakeTime = xTaskGetTickCount();
  const TickType_t xFrequency = pdMS_TO_TICKS(1000); // once per second

  while (true) {
    vTaskDelayUntil( &xLastWakeTime, xFrequency );

    // take timestamp
    struct timeval tms;
    gettimeofday(&tms, NULL);
    time_t t = time(NULL);

    //ESP_ERROR_CHECK( esp_wifi_config_80211_tx_rate(WIFI_IF_STA, WIFI_PHY_RATE_54M) );
    ESP_ERROR_CHECK( esp_wifi_config_80211_tx_rate(WIFI_IF_STA, WIFI_PHY_RATE_MCS0_SGI) );

    // send burst of 8 packets
    for (int i=0; i < 7; i++) {
      // send packet
      // TODO make packet size configurable, we need large frames. MTU is 1500 bytes including headers
      esp_wifi_set_max_tx_power(40); // 8*0.25dBm is the minimum power, 80*0.25=20dBm would be the maximum
      //esp_err_t res = esp_wifi_80211_tx(WIFI_IF_STA, &myframe, sizeof(myframe), false);
      esp_err_t res = esp_wifi_80211_tx(WIFI_IF_STA, &myframe, sizeof(myframe), false);
      //esp_err_t res = esp_wifi_internal_tx(WIFI_IF_STA, &myframe, sizeof(myframe)-4);
      ESP_ERROR_CHECK_WITHOUT_ABORT(res);
        
      if (res == 0) {
        myframe.hdr.sequence_ctrl += (1<<4);
        // TODO what to do when packet send failed?
        //packetsent++;
      }
    }
    
    Txbuf buf;
    buf.txpwr = 8; // TODO should not be hardcoded
    buf.br = 0; // TODO needs to be queried
    buf.sequence = myframe.hdr.sequence_ctrl;
    buf.pkt_size = sizeof(myframe);
    buf.sec = t;
    buf.usec = tms.tv_usec;


    struct tm timeinfo;
    time_t unix_sec = buf.sec; // implicit type conversion
    localtime_r(&unix_sec, &timeinfo);

    if (dataFile && file_hour != timeinfo.tm_hour) {
      dataFile.close();
    }
    
    if (!dataFile) {
      file_hour = timeinfo.tm_hour;
      char s[51];
      strftime(s, 50, "%Y%m%d_%H%M%S", &timeinfo);
      char filename[100];
      snprintf(filename, 100, "%s/wifitx/%s.bin", basepath, s);
      dataFile = SD.open(filename, FILE_WRITE);
    }
    
    if (dataFile) {
      dataFile.write(reinterpret_cast<uint8_t*>(&buf), sizeof(Txbuf)); 
    }
    
    flushcount++;
    if (flushcount == 50) {
      dataFile.flush();
      flushcount = 0;
    }
  }
  dataFile.close();
  
}

int disp_pos=0;

void loop() {
  // put your main code here, to run repeatedly:
  delay(1000);
  display.clearDisplay();
  display.setCursor(0,0);

  int idx = 0;
  int linec = 0;
  for (auto it = stats.begin(); it != stats.end(); it++, idx++) {
    if (idx < disp_pos) continue;
    auto stat = it->second;

    display.print("NodeID:");
    display.print(stat->mac & 0xFFFF, HEX);  // last two bytes of the MAC address
    display.print('\n');
    display.print("rssi:");
    display.print(stat->rssi);
    display.print("dBm ");
    display.print("ns:");
    display.print(stat->noise);
    display.print("dBm ");
    display.print("rcvd:");
    display.print(stat->rcv_count);
    display.print(' ');
    display.print("PDR:");
    display.print(int(stat->pdr*100));
    display.print("% ");
    display.print("Thr:");
    display.print(stat->kbitspersec);
    display.print("kbps ");
    display.println();
    disp_pos++;
    linec++;
    if (linec == 4) break;
  }
  if (idx >= stats.size()-1) disp_pos = 0;
  
  display.display();
}
