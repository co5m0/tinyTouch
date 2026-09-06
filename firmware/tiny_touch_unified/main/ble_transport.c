#include "ble_transport.h"

#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "esp_log.h"
#include "host/ble_hs.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "os/os_mbuf.h"
#include "services/gap/ble_svc_gap.h"
#include "services/gatt/ble_svc_gatt.h"

#include "touch_pin_hid.h"

static const char *TAG = "ble_transport";

static uint8_t own_addr_type;
static uint16_t active_connection = BLE_HS_CONN_HANDLE_NONE;
static uint16_t tx_value_handle;
static char rx_line[640];
static size_t rx_line_length;

/* Canonical UUIDs:
 * service: 54a10000-7469-6e79-746f-756368000001
 * RX:      54a10000-7469-6e79-746f-756368000002
 * TX:      54a10000-7469-6e79-746f-756368000003
 */
static const ble_uuid128_t service_uuid = BLE_UUID128_INIT(
    0x01, 0x00, 0x00, 0x68, 0x63, 0x75, 0x6f, 0x74,
    0x79, 0x6e, 0x69, 0x74, 0x00, 0x00, 0xa1, 0x54);
static const ble_uuid128_t rx_uuid = BLE_UUID128_INIT(
    0x02, 0x00, 0x00, 0x68, 0x63, 0x75, 0x6f, 0x74,
    0x79, 0x6e, 0x69, 0x74, 0x00, 0x00, 0xa1, 0x54);
static const ble_uuid128_t tx_uuid = BLE_UUID128_INIT(
    0x03, 0x00, 0x00, 0x68, 0x63, 0x75, 0x6f, 0x74,
    0x79, 0x6e, 0x69, 0x74, 0x00, 0x00, 0xa1, 0x54);

static void consume_rx_bytes(const uint8_t *data, size_t length) {
  for (size_t i = 0; i < length; i++) {
    uint8_t value = data[i];
    if (value == '\r') continue;
    if (value == '\n') {
      rx_line[rx_line_length] = '\0';
      if (rx_line_length &&
          (strncmp(rx_line, "PW ", 3) == 0 || strncmp(rx_line, "PW2 ", 4) == 0)) {
        if (!touch_pin_hid_submit_response(rx_line)) {
          ESP_LOGW(TAG, "BLE password response was rejected");
        }
      }
      rx_line_length = 0;
      continue;
    }
    if (rx_line_length + 1 < sizeof(rx_line)) {
      rx_line[rx_line_length++] = (char)value;
    } else {
      ESP_LOGW(TAG, "discarding oversized BLE line");
      rx_line_length = 0;
    }
  }
}

static int gatt_access(uint16_t conn_handle, uint16_t attr_handle,
                       struct ble_gatt_access_ctxt *ctxt, void *arg) {
  (void)conn_handle;
  (void)attr_handle;
  (void)arg;
  if (ctxt->op != BLE_GATT_ACCESS_OP_WRITE_CHR) return BLE_ATT_ERR_UNLIKELY;

  uint8_t chunk[256];
  uint16_t offset = 0;
  uint16_t total = OS_MBUF_PKTLEN(ctxt->om);
  while (offset < total) {
    uint16_t wanted = total - offset;
    if (wanted > sizeof(chunk)) wanted = sizeof(chunk);
    int rc = os_mbuf_copydata(ctxt->om, offset, wanted, chunk);
    if (rc != 0) return BLE_ATT_ERR_UNLIKELY;
    consume_rx_bytes(chunk, wanted);
    offset += wanted;
  }
  return 0;
}

static const struct ble_gatt_chr_def gatt_characteristics[] = {
    {
        .uuid = &rx_uuid.u,
        .access_cb = gatt_access,
        .flags = BLE_GATT_CHR_F_WRITE | BLE_GATT_CHR_F_WRITE_NO_RSP,
    },
    {
        .uuid = &tx_uuid.u,
        .access_cb = gatt_access,
        .val_handle = &tx_value_handle,
        .flags = BLE_GATT_CHR_F_NOTIFY,
    },
    {0},
};

static const struct ble_gatt_svc_def gatt_services[] = {
    {
        .type = BLE_GATT_SVC_TYPE_PRIMARY,
        .uuid = &service_uuid.u,
        .characteristics = gatt_characteristics,
    },
    {0},
};

static void start_advertising(void);

static int gap_event(struct ble_gap_event *event, void *arg) {
  (void)arg;
  switch (event->type) {
    case BLE_GAP_EVENT_CONNECT:
      if (event->connect.status == 0) {
        active_connection = event->connect.conn_handle;
        rx_line_length = 0;
        ESP_LOGI(TAG, "BLE host connected");
      } else {
        start_advertising();
      }
      return 0;
    case BLE_GAP_EVENT_DISCONNECT:
      active_connection = BLE_HS_CONN_HANDLE_NONE;
      rx_line_length = 0;
      ESP_LOGI(TAG, "BLE host disconnected");
      start_advertising();
      return 0;
    case BLE_GAP_EVENT_ADV_COMPLETE:
      start_advertising();
      return 0;
    default:
      return 0;
  }
}

static void start_advertising(void) {
  struct ble_hs_adv_fields fields;
  memset(&fields, 0, sizeof(fields));
  fields.flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;
  fields.uuids128 = (ble_uuid128_t *)&service_uuid;
  fields.num_uuids128 = 1;
  fields.uuids128_is_complete = 1;
  int rc = ble_gap_adv_set_fields(&fields);
  if (rc != 0) {
    ESP_LOGE(TAG, "setting advertising fields failed: %d", rc);
    return;
  }

  struct ble_hs_adv_fields response;
  memset(&response, 0, sizeof(response));
  const char *name = ble_svc_gap_device_name();
  response.name = (uint8_t *)name;
  response.name_len = strlen(name);
  response.name_is_complete = 1;
  rc = ble_gap_adv_rsp_set_fields(&response);
  if (rc != 0) {
    ESP_LOGE(TAG, "setting scan response failed: %d", rc);
    return;
  }

  struct ble_gap_adv_params params;
  memset(&params, 0, sizeof(params));
  params.conn_mode = BLE_GAP_CONN_MODE_UND;
  params.disc_mode = BLE_GAP_DISC_MODE_GEN;
  rc = ble_gap_adv_start(own_addr_type, NULL, BLE_HS_FOREVER, &params, gap_event, NULL);
  if (rc != 0 && rc != BLE_HS_EALREADY) {
    ESP_LOGE(TAG, "starting advertising failed: %d", rc);
  }
}

static void on_sync(void) {
  int rc = ble_hs_util_ensure_addr(0);
  assert(rc == 0);
  rc = ble_hs_id_infer_auto(0, &own_addr_type);
  assert(rc == 0);
  start_advertising();
}

static void host_task(void *arg) {
  (void)arg;
  nimble_port_run();
  nimble_port_freertos_deinit();
}

void ble_transport_start(void) {
  ESP_ERROR_CHECK(nimble_port_init());
  ble_hs_cfg.sync_cb = on_sync;
  ble_hs_cfg.sm_io_cap = BLE_HS_IO_NO_INPUT_OUTPUT;
  ble_hs_cfg.sm_bonding = 0;
  ble_hs_cfg.sm_mitm = 0;
  ble_hs_cfg.sm_sc = 1;

  ble_svc_gap_init();
  ble_svc_gatt_init();
  ESP_ERROR_CHECK(ble_svc_gap_device_name_set("tinyTouch"));
  int rc = ble_gatts_count_cfg(gatt_services);
  assert(rc == 0);
  rc = ble_gatts_add_svcs(gatt_services);
  assert(rc == 0);
  nimble_port_freertos_init(host_task);
}

bool ble_transport_connected(void) {
  return active_connection != BLE_HS_CONN_HANDLE_NONE;
}

bool ble_transport_send_line(const char *line) {
  if (!line || active_connection == BLE_HS_CONN_HANDLE_NONE || !tx_value_handle) return false;

  char framed[900];
  size_t length = strlen(line);
  if (length + 1 > sizeof(framed)) return false;
  memcpy(framed, line, length);
  framed[length++] = '\n';

  uint16_t mtu = ble_att_mtu(active_connection);
  size_t chunk_size = mtu > 3 ? mtu - 3 : 20;
  if (chunk_size > 256) chunk_size = 256;

  for (size_t offset = 0; offset < length; offset += chunk_size) {
    size_t count = length - offset;
    if (count > chunk_size) count = chunk_size;
    struct os_mbuf *om = ble_hs_mbuf_from_flat(framed + offset, count);
    if (!om) return false;
    int rc = ble_gatts_notify_custom(active_connection, tx_value_handle, om);
    if (rc != 0) {
      ESP_LOGW(TAG, "BLE notify failed: %d", rc);
      return false;
    }
  }
  return true;
}
