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

const char* ssid = "YOUR_SSID";
const char* password = "YOUR_PASS";

const char* server_host = "unhawked-jamarion-noncleistogamous.ngrok-free.dev";
const String server_get_pubkey_path = "/public-key";      // returns PEM JSON e.g. {"public_key":"-----BEGIN PUBLIC KEY-----\n..."}
const String server_target_path     = "/receive-encrypted"; // replace with your endpoint that accepts encrypted payloads

// file to store private scalar
const char *PRIVFILE = "/privkey.bin"; // 32 bytes for P-256

// mbedTLS contexts
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_ecp_group grp;
mbedtls_ecp_keypair keypair; // holds our keypair (d + Q)

const char *pers = "esp32_ecc_persist";

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
  int ret = mbedtls_ecp_point_write_binary(&grp, &keypair.Q,
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
  ret = mbedtls_ecdh_compute_shared(&grp, &shared, &serverQ, &keypair.d,
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
                                  iv, iv_len, /add/ NULL, 0,
                                  plain, cipher_out,
                                  tag_len, tag_out);
  mbedtls_gcm_free(&gcm);
  return (ret == 0);
}

// parse server's JSON PEM and extract public key bytes (uncompressed)
// Assumes server returns JSON like {"public_key":"-----BEGIN PUBLIC KEY-----\n...PEM...\n-----END PUBLIC KEY-----\n"}
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

  // crude JSON parse to find the PEM block
  int start = resp.indexOf("-----BEGIN PUBLIC KEY-----");
  int end = resp.indexOf("-----END PUBLIC KEY-----");
  if (start < 0 || end < 0) return false;
  String pem = resp.substring(start, end + strlen("-----END PUBLIC KEY-----"));
  pem.trim();

  // parse PEM to mbedtls pk context
  mbedtls_pk_context pk;
  mbedtls_pk_init(&pk);
  int ret = mbedtls_pk_parse_public_key(&pk, (const unsigned char*)pem.c_str(), pem.length()+1);
  if (ret != 0) { mbedtls_pk_free(&pk); Serial.printf("pk_parse_public_key failed -0x%04X\n", -ret); return false; }

  if (mbedtls_pk_get_type(&pk) != MBEDTLS_PK_ECKEY) { mbedtls_pk_free(&pk); Serial.println("server key not EC"); return false; }

  // extract ecp point
  mbedtls_ecp_keypair *pk_ec = mbedtls_pk_ec(pk);
  size_t olen = 0;
  ret = mbedtls_ecp_point_write_binary(&grp, &pk_ec->Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &olen, out65, 65);
  mbedtls_pk_free(&pk);
  return (ret == 0 && olen == 65);
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
  mbedtls_ecp_keypair_init(&keypair);

  // Try to read private scalar from SPIFFS
  uint8_t d32[32];
  if (read_private_scalar(d32)) {
    Serial.println("Loaded existing private scalar from SPIFFS");
    // set d
    if (mbedtls_mpi_read_binary(&keypair.d, d32, 32) != 0) { Serial.println("mpi_read failed"); }
    // set group
    if (mbedtls_ecp_group_copy(&keypair.grp, &grp) != 0) { Serial.println("group copy failed"); }
    // compute Q = d * G
    if (mbedtls_ecp_mul(&keypair.grp, &keypair.Q, &keypair.d, &keypair.grp.G, mbedtls_ctr_drbg_random, &ctr_drbg) != 0) {
      Serial.println("ecp_mul failed");
    }
  } else {
    // generate new keypair and persist private scalar
    Serial.println("Generating new keypair (will persist private scalar)...");
    if (mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, &keypair, mbedtls_ctr_drbg_random, &ctr_drbg) != 0) {
      Serial.println("keygen failed"); while(1) delay(1000);
    }
    // export private scalar (d) to 32 bytes
    memset(d32,0,32);
    if (mbedtls_mpi_write_binary(&keypair.d, d32, 32) != 0) { Serial.println("mpi_write failed"); }
    if (!save_private_scalar(d32)) { Serial.println("Failed to save private scalar"); }
    else Serial.println("Saved private scalar to SPIFFS");
  }

  // export client public key as hex
  uint8_t client_pub[65];
  size_t publen = export_public_uncompressed(client_pub, sizeof(client_pub));
  String client_pub_hex = (publen==65) ? bytesToHex(client_pub, publen) : String("");
  Serial.print("Client pubkey hex: ");
  Serial.println(client_pub_hex);

  // Example flow: fetch server pubkey, do ECDH, encrypt sample payload and POST
  uint8_t server_pub[65];
  if (!fetch_server_pubkey_uncompressed(server_pub)) {
    Serial.println("Failed to fetch or parse server public key");
    return;
  }
  Serial.print("Got server pub (hex): ");
  Serial.println(bytesToHex(server_pub, 65));

  // compute shared AES key
  uint8_t aes_key[32];
  if (!compute_ecdh_shared_from_server_pub(server_pub, 65, aes_key)) {
    Serial.println("ECDH failed");
    return;
  }
  Serial.print("Derived AES key (hex): ");
  Serial.println(bytesToHex(aes_key, 32));

  // sample payload (replace with real sensor JSON)
  String sample = "{\"spo2\":97,\"hr\":72}";
  size_t plain_len = sample.length();
  uint8_t plain = (uint8_t)sample.c_str();

  // generate random IV (12 bytes)
  uint8_t iv[12];
  if (mbedtls_ctr_drbg_random(&ctr_drbg, iv, sizeof(iv)) != 0) { Serial.println("random IV failed"); return; }

  // allocate cipher buffer
  uint8_t cipher[512];
  uint8_t tag[16];
  if (!aes_gcm_encrypt(aes_key, iv, sizeof(iv), plain, plain_len, cipher, tag, sizeof(tag))) {
    Serial.println("AES-GCM encrypt failed");
    return;
  }

  // POST encrypted payload including client public key
  bool ok = post_encrypted_payload(client_pub_hex, iv, sizeof(iv), cipher, plain_len, tag, sizeof(tag));
  Serial.printf("POST result: %s\n", ok ? "OK":"FAIL");
}

void loop() {
  // Nothing here. You can move the encryption/post logic into a routine that runs after you
  // read real sensor values (MAX30105). For each reading:
  // 1) build JSON payload string
  // 2) fetch server pubkey (or cache it)
  // 3) compute ECDH-derived AES key
  // 4) AES-GCM encrypt with random IV
  // 5) POST with client pubkey hex + iv/cipher/tag
  delay(10000);
}