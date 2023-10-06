#ifndef SESAMI_UTIL_H
#define SESAMI_UTIL_H

#include "esp_log.h"

// Includes from framework-arduinoespressif32
#include <base64.h>
#include <WiFi.h>
#include <WiFiMulti.h>
#include <HTTPClient.h>

// Includes for AES
#include <AES_CMAC.h>
#include <AES.h>

#include <optional> // C++17

String generateRandomTag(String secret_key, uint32_t timestamp);

std::optional<String> operation_sesami(String device_uuid, String api_key, int command, String secret_key);

std::optional<String> get_sesami_status(String device_uuid, String api_key);

std::optional<String> get_sesami_history(String device_uuid, String api_key);

/**
 * Generate random tag for Sesami API
 *
 * @param secret_key The secret key used for generating the tag.
 * @param timestamp The unix timestamp in seconds used for generating the tag.
 * @return An optional string containing the generated tag if successful, otherwise std::nullopt.
 */
std::optional<String> generateRandomTag(String secret_key, uint32_t timestamp)
{
    AESTiny128 aes128;
    AES_CMAC cmac(aes128);

    uint8_t bytes_timestamp[3];
    bytes_timestamp[0] = (timestamp >> 8) & 0xFF;
    bytes_timestamp[1] = (timestamp >> 16) & 0xFF;
    bytes_timestamp[2] = (timestamp >> 24) & 0xFF;

    uint8_t key[16];
    for (int i = 0; i < 16; i++)
    {
        key[i] = 0;
        if (secret_key[2 * i] >= '0' and secret_key[2 * i] <= '9')
        {
            key[i] += (secret_key[2 * i] - '0') << 4;
        }
        else if (secret_key[2 * i] >= 'a' and secret_key[2 * i] <= 'f')
        {
            key[i] += (secret_key[2 * i] - 'a' + 10) << 4;
        }
        else if (secret_key[2 * i] >= 'A' and secret_key[2 * i] <= 'F')
        {
            key[i] += (secret_key[2 * i] - 'A' + 10) << 4;
        }
        else
        {
            ESP_LOGE("esp32_sesami_client", "Invalid secret key: %s", secret_key.c_str());
            return std::nullopt;
        }

        if (secret_key[2 * i + 1] >= '0' and secret_key[2 * i + 1] <= '9')
        {
            key[i] += (secret_key[2 * i + 1] - '0');
        }
        else if (secret_key[2 * i + 1] >= 'a' and secret_key[2 * i + 1] <= 'f')
        {
            key[i] += (secret_key[2 * i + 1] - 'a' + 10);
        }
        else if (secret_key[2 * i + 1] >= 'A' and secret_key[2 * i + 1] <= 'F')
        {
            key[i] += (secret_key[2 * i + 1] - 'A' + 10);
        }
        else
        {
            ESP_LOGE("esp32_sesami_client", "Invalid secret key: %s", secret_key.c_str());
            return std::nullopt;
        }
    }

    uint8_t output[16];

    cmac.generateMAC(output, key, bytes_timestamp, sizeof(bytes_timestamp));

    char output_hex[32];
    for (int i = 0; i < 16; i++)
    {
        sprintf(output_hex + (i * 2), "%02x", output[i]);
    }
    return String(output_hex);
}

/*
 * Operation Sesami
 */
std::optional<String> operation_sesami(uint32_t timestamp, String device_uuid, int command, String api_key, String secret_key, String history_name)
{
    String sign = generateRandomTag(secret_key, timestamp);
    String base64History = base64::encode(history_name);
    String body = String("{") +
                  String("\"cmd\":") + command + String(",") +
                  String("\"sign\":\"") + sign + String("\",") +
                  String("\"history\":\"") + base64History + String("\"}");
    String url = String("https://app.candyhouse.co/api/sesame2/") + device_uuid + String("/cmd");

    HTTPClient http;

    if (!http.begin(url))
    {
        ESP_LOGE("esp32_sesami_client", "Connection failed.\n");
        return std::nullopt;
    }

    http.addHeader("Content-Type", "application/json");
    http.addHeader("x-api-key", api_key);
    int responseCode = http.POST(body);
    String result_body = http.getString();
    http.end();

    if (responseCode != 200)
    {
        ESP_LOGE("esp32_sesami_client", "POST failed, responseCode: %d\n", responseCode);
        return std::nullopt;
    }
    else
    {
        body.replace("\\\"", "\"");
        return result_body;
    }
}

std::optional<String> get_sesami_status(String device_uuid, String api_key)
{
    HTTPClient http;

    String url = String("https://app.candyhouse.co/api/sesame2/") + device_uuid;

    if (!http.begin(url))
    {
        ESP_LOGE("esp32_sesami_client", "Connection failed.\n");
        return std::nullopt;
    }

    http.addHeader("Content-Type", "application/json");
    http.addHeader("x-api-key", api_key);
    int responseCode = http.GET();
    String body = http.getString();
    http.end();

    if (responseCode != 200)
    {
        ESP_LOGE("esp32_sesami_client", "GET failed, responseCode: %d\n", responseCode);
        return std::nullopt;
    }
    else
    {
        body.replace("\\\"", "\"");
        return body;
    }
}

std::optional<String> get_sesami_history(String device_uuid, String api_key)
{
    HTTPClient http;

    String url = String("https://app.candyhouse.co/api/sesame2/") + device_uuid + String("/history?page=0&lg=5");

    if (!http.begin(url))
    {
        ESP_LOGE("esp32_sesami_client", "Connection failed.\n");
        return std::nullopt;
    }

    http.addHeader("Content-Type", "application/json");
    http.addHeader("x-api-key", api_key);
    int responseCode = http.GET();
    String body = http.getString();
    http.end();

    if (responseCode != 200)
    {
        ESP_LOGE("esp32_sesami_client", "GET failed, responseCode: %d\n", responseCode);
        return std::nullopt;
    }
    else
    {
        body.replace("\\\"", "\"");
        return body;
    }
}

#endif // SESAMI_UTIL_H