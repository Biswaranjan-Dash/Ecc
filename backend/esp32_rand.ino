/*
  ESP32: permanent ECDH private key (SPIFFS) + GET server PEM + ECDH -> AES-GCM encrypt
  send JSON: { "pubkey":"<hex 0x04||X||Y>", "iv":"hex", "cipher":"hex", "tag":"hex" }
*/

#include <WiFi.h>
#include <HTTPClient.h>
#include <WiFiClientSecure.h>
#include "SPIFFS.h"

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecp.h"
#include "mbedtls/sha256.h"
#include "mbedtls/gcm.h"
#include "mbedtls/pk.h"

const char* ssid = "Raju Rastogi";
const char* password = "sbrs@1056";

const char* server_host = "unhawked-jamarion-noncleistogamous.ngrok-free.dev";
const String server_get_pubkey_path = "/public-key";      // returns PEM JSON e.g. {"public_key":"-----BEGIN PUBLIC KEY-----\n..."}
const String server_target_path     = "/receive-encrypted"; // replace with your endpoint that accepts encrypted payloads

// file to store private scalar
const char *PRIVFILE = "/privkey.bin"; // 32 bytes for P-256

// mbedTLS contexts
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_ecp_group grp;
mbedtls_mpi private_d;        // private scalar
mbedtls_ecp_point public_Q;   // public point

static const char *pers = "esp32_ecc_persist";

// Cached server public key and AES key (to avoid repeated fetches)
uint8_t cached_server_pub[65];
uint8_t cached_aes_key[32];
bool server_key_cached = false;
String client_pub_hex_cached = "";

// utility: hex encode
String bytesToHex(const uint8_t *buf, size_t len) {
  String s; s.reserve(len*2+1);
  for (size_t i=0;i<len;i++) {
    char tmp[3]; sprintf(tmp, "%02X", buf[i]);
    s += tmp;
  }
  return s;
}

// write private scalar to SPIFFS
bool save_private_scalar(const uint8_t *d32) {
  File f = SPIFFS.open(PRIVFILE, FILE_WRITE);
  if (!f) return false;
  size_t w = f.write(d32, 32);
  f.close();
  return w == 32;
}

// read private scalar from SPIFFS
bool read_private_scalar(uint8_t *out32) {
  if (!SPIFFS.exists(PRIVFILE)) return false;
  File f = SPIFFS.open(PRIVFILE, FILE_READ);
  if (!f) return false;
  if (f.size() != 32) { f.close(); return false; }
  size_t r = f.read(out32, 32);
  f.close();
  return r == 32;
}

// export our public key as uncompressed 0x04 || X || Y
size_t export_public_uncompressed(uint8_t *out, size_t out_size) {
  size_t olen = 0;
  int ret = mbedtls_ecp_point_write_binary(&grp, &public_Q,
                                           MBEDTLS_ECP_PF_UNCOMPRESSED, &olen,
                                           out, out_size);
  if (ret != 0) return 0;
  return olen;
}

// derive AES key = SHA256(shared_big_endian)
bool derive_aes_from_shared(mbedtls_mpi *shared, uint8_t *aes32) {
  // write shared into buffer
  uint8_t sharedbuf[32]; // P-256
  memset(sharedbuf, 0, sizeof(sharedbuf));
  if (mbedtls_mpi_size(shared) > 32) return false;
  int ret = mbedtls_mpi_write_binary(shared, sharedbuf, 32);
  if (ret != 0) return false;
  mbedtls_sha256(sharedbuf, 32, aes32, 0);
  return true;
}

// compute ECDH with server public (server_pub_bin is 65 bytes 0x04||X||Y)
bool compute_ecdh_shared_from_server_pub(const uint8_t *server_pub_bin, size_t server_pub_len, uint8_t aes_key_out[32]) {
  int ret = 0;
  mbedtls_ecp_point serverQ;
  mbedtls_mpi shared;
  mbedtls_ecp_point_init(&serverQ);
  mbedtls_mpi_init(&shared);

  // parse server public point into serverQ (must use our group)
  ret = mbedtls_ecp_point_read_binary(&grp, &serverQ, server_pub_bin, server_pub_len);
  if (ret != 0) goto cleanup;

  // compute shared = serverQ * d
  ret = mbedtls_ecdh_compute_shared(&grp, &shared, &serverQ, &private_d,
                                    mbedtls_ctr_drbg_random, &ctr_drbg);
  if (ret != 0) goto cleanup;

  // derive AES key
  if (!derive_aes_from_shared(&shared, aes_key_out)) { ret = -1; goto cleanup; }

cleanup:
  mbedtls_ecp_point_free(&serverQ);
  mbedtls_mpi_free(&shared);
  return (ret == 0);
}

// AES-GCM encrypt: outputs cipher and tag. iv_len must be 12 recommended.
bool aes_gcm_encrypt(const uint8_t *key32, const uint8_t *iv, size_t iv_len,
                     const uint8_t *plain, size_t plain_len,
                     uint8_t *cipher_out, uint8_t *tag_out, size_t tag_len=16) {
  int ret;
  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key32, 256);
  if (ret != 0) { mbedtls_gcm_free(&gcm); return false; }

  ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, plain_len,
                                  iv, iv_len, NULL, 0,
                                  plain, cipher_out,
                                  tag_len, tag_out);
  mbedtls_gcm_free(&gcm);
  return (ret == 0);
}

// parse server's JSON and extract public key bytes (uncompressed hex format)
// Server returns JSON like {"public_key":"-----BEGIN...","public_key_hex":"04ABCD..."}
bool fetch_server_pubkey_uncompressed(uint8_t *out65) {
  WiFiClientSecure client;
  client.setInsecure(); // for ngrok/test only
  HTTPClient https;
  String url = String("https://") + server_host + server_get_pubkey_path;
  if (!https.begin(client, url)) { Serial.println("HTTPS begin failed for GET"); return false; }
  int code = https.GET();
  if (code != 200) { Serial.printf("GET failed: %d\n", code); https.end(); return false; }
  String resp = https.getString();
  https.end();

  Serial.println("Server response: " + resp);

  // Parse JSON to find public_key_hex field
  int hex_start = resp.indexOf("\"public_key_hex\":\"");
  if (hex_start < 0) {
    Serial.println("public_key_hex not found in response");
    return false;
  }
  hex_start += strlen("\"public_key_hex\":\"");
  int hex_end = resp.indexOf("\"", hex_start);
  if (hex_end < 0) {
    Serial.println("public_key_hex end quote not found");
    return false;
  }
  
  String hex_key = resp.substring(hex_start, hex_end);
  Serial.println("Hex key extracted: " + hex_key);
  
  // Convert hex string to bytes (should be 130 hex chars = 65 bytes)
  if (hex_key.length() != 130) {
    Serial.printf("Invalid hex key length: %d (expected 130)\n", hex_key.length());
    return false;
  }
  
  for (int i = 0; i < 65; i++) {
    String byteStr = hex_key.substring(i*2, i*2 + 2);
    out65[i] = (uint8_t)strtol(byteStr.c_str(), NULL, 16);
  }
  
  return true;
}

// send encrypted JSON with our public key (hex) and iv/cipher/tag hex
bool post_encrypted_payload(const String &client_pub_hex, const uint8_t *iv, size_t iv_len,
                            const uint8_t *cipher, size_t cipher_len, const uint8_t *tag, size_t tag_len) {
  WiFiClientSecure client;
  client.setInsecure(); // test only
  HTTPClient https;
  String url = String("https://") + server_host + server_target_path;
  if (!https.begin(client, url)) { Serial.println("HTTPS begin failed for POST"); return false; }

  https.addHeader("Content-Type", "application/json");
  String payload = "{\"pubkey\":\"" + client_pub_hex + "\"";
  payload += ",\"iv\":\"" + bytesToHex(iv, iv_len) + "\"";
  payload += ",\"cipher\":\"" + bytesToHex(cipher, cipher_len) + "\"";
  payload += ",\"tag\":\"" + bytesToHex(tag, tag_len) + "\"}";
  int code = https.POST(payload);
  Serial.printf("POST status: %d\n", code);
  String resp = https.getString();
  Serial.println("Server resp: " + resp);
  https.end();
  return (code >= 200 && code < 300);
}

void setup() {
  Serial.begin(115200);
  delay(200);

  // SPIFFS init
  if (!SPIFFS.begin(true)) { Serial.println("SPIFFS mount failed"); while(1) delay(1000); }

  WiFi.begin(ssid, password);
  Serial.print("Connecting to WiFi");
  while (WiFi.status() != WL_CONNECTED) { Serial.print("."); delay(250); }
  Serial.println("\nWiFi connected");

  // mbedTLS init
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&ctr_drbg);
  if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                            (const unsigned char*)pers, strlen(pers)) != 0) {
    Serial.println("ctr_drbg_seed failed"); while(1) delay(1000);
  }
  mbedtls_ecp_group_init(&grp);
  mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1);
  mbedtls_mpi_init(&private_d);
  mbedtls_ecp_point_init(&public_Q);

  // Try to read private scalar from SPIFFS
  uint8_t d32[32];
  if (read_private_scalar(d32)) {
    Serial.println("Loaded existing private scalar from SPIFFS");
    // set d
    if (mbedtls_mpi_read_binary(&private_d, d32, 32) != 0) { Serial.println("mpi_read failed"); }
    // compute Q = d * G
    if (mbedtls_ecp_mul(&grp, &public_Q, &private_d, &grp.G, mbedtls_ctr_drbg_random, &ctr_drbg) != 0) {
      Serial.println("ecp_mul failed");
    }
  } else {
    // generate new keypair and persist private scalar
    Serial.println("Generating new keypair (will persist private scalar)...");
    mbedtls_ecp_keypair temp_keypair;
    mbedtls_ecp_keypair_init(&temp_keypair);
    
    if (mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, &temp_keypair, mbedtls_ctr_drbg_random, &ctr_drbg) != 0) {
      Serial.println("keygen failed"); while(1) delay(1000);
    }
    
    // export private scalar (d) to 32 bytes
    memset(d32,0,32);
    mbedtls_mpi *temp_d = &temp_keypair.MBEDTLS_PRIVATE(d);
    if (mbedtls_mpi_write_binary(temp_d, d32, 32) != 0) { Serial.println("mpi_write failed"); }
    if (!save_private_scalar(d32)) { Serial.println("Failed to save private scalar"); }
    else Serial.println("Saved private scalar to SPIFFS");
    
    // Copy to our global variables
    mbedtls_mpi_copy(&private_d, temp_d);
    mbedtls_ecp_point *temp_Q = &temp_keypair.MBEDTLS_PRIVATE(Q);
    mbedtls_ecp_copy(&public_Q, temp_Q);
    
    mbedtls_ecp_keypair_free(&temp_keypair);
  }

  // export client public key as hex (cache it globally)
  uint8_t client_pub[65];
  size_t publen = export_public_uncompressed(client_pub, sizeof(client_pub));
  client_pub_hex_cached = (publen==65) ? bytesToHex(client_pub, publen) : String("");
  Serial.print("Client pubkey hex: ");
  Serial.println(client_pub_hex_cached);

  // Fetch server pubkey once and cache it
  if (!fetch_server_pubkey_uncompressed(cached_server_pub)) {
    Serial.println("Failed to fetch or parse server public key");
    return;
  }
  Serial.print("Got server pub (hex): ");
  Serial.println(bytesToHex(cached_server_pub, 65));

  // compute shared AES key once and cache it
  if (!compute_ecdh_shared_from_server_pub(cached_server_pub, 65, cached_aes_key)) {
    Serial.println("ECDH failed");
    return;
  }
  Serial.print("Derived AES key (hex): ");
  Serial.println(bytesToHex(cached_aes_key, 32));
  
  server_key_cached = true;
  Serial.println("\n✓ Setup complete! Starting continuous transmission in loop()...\n");
}

void loop() {
  if (!server_key_cached) {
    Serial.println("Server key not cached, skipping...");
    delay(5000);
    return;
  }

  // Generate random sensor data (replace with real MAX30105 readings)
  int heart_rate = random(60, 100);
  int spo2 = random(95, 100);
  
  // Build JSON payload with correct field names
  String sample = "{\"heart rate\":" + String(heart_rate) + ",\"spo2\":" + String(spo2) + "}";
  Serial.print("Payload: ");
  Serial.println(sample);
  
  size_t plain_len = sample.length();
  const uint8_t *plain = (const uint8_t*)sample.c_str();

  // Generate random IV (12 bytes for GCM)
  uint8_t iv[12];
  if (mbedtls_ctr_drbg_random(&ctr_drbg, iv, sizeof(iv)) != 0) { 
    Serial.println("random IV failed"); 
    delay(2000);
    return; 
  }

  // Allocate cipher buffer
  uint8_t cipher[512];
  uint8_t tag[16];
  
  // Encrypt using cached AES key
  if (!aes_gcm_encrypt(cached_aes_key, iv, sizeof(iv), plain, plain_len, cipher, tag, sizeof(tag))) {
    Serial.println("AES-GCM encrypt failed");
    delay(2000);
    return;
  }

  // POST encrypted payload with cached client public key
  bool ok = post_encrypted_payload(client_pub_hex_cached, iv, sizeof(iv), cipher, plain_len, tag, sizeof(tag));
  Serial.printf("POST result: %s\n\n", ok ? "✓ OK":"✗ FAIL");
  
  // Wait 2 seconds before next transmission
  delay(2000);
}