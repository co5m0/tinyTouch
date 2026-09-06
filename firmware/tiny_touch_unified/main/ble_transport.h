#pragma once

#include <stdbool.h>

void ble_transport_start(void);
bool ble_transport_connected(void);
bool ble_transport_send_line(const char *line);
