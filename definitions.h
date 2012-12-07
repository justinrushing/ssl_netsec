#ifndef DEFINITIONS_H
#define DEFINITIONS_H

#define TLS_EMPTY_RENEGOTIATION_INFO_SCSV 0x00ff
#define TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA 0x0088
#define TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA 0x0087
#define TLS_DHE_RSA_WITH_AES_256_CBC_SHA 0x0039


#include <iostream>
#include <vector>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>
#include <ctime>
#include <sys/time.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/rc4.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

using namespace std;
#include <time.h>
#include <vector>

typedef unsigned int uint;
typedef unsigned char uchar;

enum handshake_type {
  hello_request=0, client_hello, server_hello, certificate=11, 
  server_key_exchange, certificate_request, server_hello_done, 
  certificate_verify, client_key_exchange, finished=20
};

typedef struct {
  handshake_type msg_type;
  uint length;
  unsigned char *body;
} Handshake;

class Random
{
 public:
  uint gmt_unix_time;
  unsigned char random_bytes[28];
  uchar seed[32];
  Random() {
    RAND_bytes(random_bytes, 28); 
    gmt_unix_time = (int)time(NULL);
    seed[0] = gmt_unix_time >> 24;
    seed[1] = (gmt_unix_time << 8) >> 24;
    seed[2] = (gmt_unix_time << 16) >> 24;
    seed[3] = (gmt_unix_time << 24) >> 24;
    memcpy(seed+4, random_bytes, 28);
  }
  void reset_seed(uchar timestamp[4]) {
    memcpy(seed, timestamp, 4);
    memcpy(seed+4, random_bytes, 28);
  }
};

void debug(const char* label, uchar *data, uint size)
{
  cout << endl << label << endl;
  for(int i = 0; i < size; i++)
    printf("%x ", data[i]);
  cout << "\n\n";
}

typedef struct {
  uint version;
  uint serialNumber;
  
} Certificate;

typedef struct {
  uint max_version;
  uint min_version;
  Random random;
  uint session_id_len;
  unsigned char *session_id;
  uint cipher_suites_len;
  vector<unsigned int> cipher_suites;
  uint compression_method_len;
  uint compression_method;
} ClientHello;

void print_client_hello(ClientHello msg)
{
  cout << "Max version: " << msg.max_version;
  cout << "Min version: " << msg.min_version;
  cout << "Random struct:" << endl << "gmt_unix_time: " << msg.random.gmt_unix_time << endl;
  cout << "random_bytes: " << msg.random.random_bytes << endl;
  cout << "Session_ID len: " << msg.session_id_len << endl;
  cout << "Session_ID: " << msg.session_id << endl;
  cout << "Cipher Suites Len: " << msg.cipher_suites_len << endl;
  for(int i = 0; i < (int)msg.cipher_suites.size(); i++)
    cout << "Cipher Suite " << i << ": " << msg.cipher_suites[i] << endl;
}

ClientHello parse_client_hello(unsigned char *buffer)
{
  ClientHello ret;
  if((int)buffer[0] != 22)
  {
    cout << "Not a handshake message. Exiting" << endl;
    exit(1);
  }
  ret.max_version = (int)buffer[1];
  ret.min_version = (int)buffer[2];
  uint message_len = ((int)buffer[3] << 8) + (int)buffer[4];
  uint message_type = (int)buffer[5];
  
  message_len -= 4;
  //bytes 9,10 are redundant
  //read in the random structure
  Random rand;
  //gmt_unix_time = bytes 11..14
  rand.gmt_unix_time = ((int)buffer[11] << 24) + ((int)buffer[12] << 16) + ((int)buffer[13] << 8) + (int)buffer[14];
  //random_bytes = bytes 15..42
  strncpy((char*)rand.random_bytes, (char*)buffer+15, 28);
  ret.random = rand;
  memcpy(ret.random.seed+4, rand.random_bytes, 28);
  
  ret.session_id_len = (int)buffer[43];
  //don't care about the session_id right now, so let's move forward
  int idx = 44+ret.session_id_len;
  
  //next 2 bytes are the cipher suites len
  ret.cipher_suites_len = ((int)buffer[idx] << 8) + ((int)buffer[idx+1]);
  idx += 2;

  //next n bytes are the cipher suites
  for(int i = idx; i < (idx+ret.cipher_suites_len); i+=2)
    ret.cipher_suites.push_back(((int)buffer[i] << 8) + ((int)buffer[i+1]));

  idx += ret.cipher_suites_len;

  //print_client_hello(ret);
  return ret;
}

unsigned char content_type = 22;
unsigned char version[2] = {3, 1}; //TLS v1

int write_server_hello_packet(Random &random)
{

  ///////////////
  //SERVER HELLO MESSAGE
  ///////////////////

  //first construct the record layer packet
  //1 byte = content_type (should be 22)
  //2 bytes = TLS version (should be 3 & 2)
  //2 bytes = packet length
  //5 bytes total
  unsigned char content_type = 22;
  unsigned char version[2] = {3, 1}; //TLS v1
  unsigned char length[2] = {0, 42}; //should be 47
  unsigned char handshake_type = 2; //server hello code
  //next in the packet should be length-4 (3 bytes this time), then version again
  unsigned char redundant_len[3] = {0,0,38};
  //now we write the random structure
  random = Random();
  unsigned char unix_time[4]; //gotta convert the time to char
  unix_time[0] = random.gmt_unix_time >> 24;
  unix_time[1] = (random.gmt_unix_time << 8) >> 24;
  unix_time[2] = (random.gmt_unix_time << 16) >> 24;
  unix_time[3] = (random.gmt_unix_time << 24) >> 24;
  
  //session id len (1 byte)
  unsigned char session_id_len = 0;
  
  //now specify cipher suite
  unsigned char cipher_suite[2] = {0, 4}; //TLS_RSA_WITH_RC4_128_MD5
//TLS_RSA_WITH_AES_256_CBC_SHA 0x0035
//TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA 0x0088
  //:TLS_ECDHE_RSA_WITH_RC4_128_SHA{192,17}
  unsigned char compression_method = 0;

  //now lets write it to a file for easy reading into a buffer
  FILE *filePtr = fopen("temp", "wb");
  if(!filePtr)
  {
    cout << "Can't open file for writing. Exiting." << endl;
    exit(1);
  }
  fwrite(&content_type, 1, 1, filePtr);
  fwrite(version, 2, 1, filePtr);
  fwrite(length, 2, 1, filePtr);
  fwrite(&handshake_type, 1, 1, filePtr);
  fwrite(redundant_len, 3, 1, filePtr);
  fwrite(version, 2, 1, filePtr);
  fwrite(unix_time, 4, 1, filePtr);
  fwrite(random.random_bytes, 28, 1, filePtr);
  fwrite(&session_id_len, 1, 1, filePtr);
  fwrite(cipher_suite, 2, 1, filePtr);
  fwrite(&compression_method, 1, 1, filePtr);
  fclose(filePtr);
  return 47;
}
///////////////////////////
/////////Server Hello Message Finished
////////////////////////////

///////////////////////////
////SERVER CERTIFICATE MESSAGE
////////////////////////////

int write_server_certificate_packet()
{
  //Message Format:
  //Let len = total length of message

  //content_type(1 byte)
  //version (2 bytes)
  //cert_len+10 (2 bytes)
  //handshake_type (1 byte)
  //cert_len+6 (3 bytes)
  //cert_len+3 (3 bytes)
  //cert_len (3 bytes)
  //cert (cert_len bytes)

  FILE *filePtr = fopen("temp", "wb");

  fwrite(&content_type, 1, 1, filePtr); //content type again to start off another record layer
  fwrite(version, 2, 1, filePtr); //version again

  FILE *der = fopen("server.der", "rb");
  fseek(der, 0, SEEK_END);
  int der_size = ftell(der);
  fseek(der, 0, SEEK_SET);
  unsigned char buf[der_size];
  fread(buf, 1, der_size, der);
  fclose(der);

  //cert_len+10 bytes
  unsigned char cert_msg_len[2];
  int iCert_msg_len = der_size+10;
  cert_msg_len[1] = (iCert_msg_len << 24) >> 24;
  cert_msg_len[0] = (iCert_msg_len << 16) >> 24;
  fwrite(cert_msg_len, 2, 1, filePtr);

  //handshake_type bytes
  uchar handshake_type = 11;
  fwrite(&handshake_type, 1, 1, filePtr);

  //cert_len+6 bytes
  unsigned char certs_len[3];
  int iCerts_len = der_size + 6;
  certs_len[2] = (iCerts_len << 24) >> 24;
  certs_len[1] = (iCerts_len << 16) >> 24;
  certs_len[0] = (iCerts_len << 8) >> 24;
  fwrite(certs_len, 3, 1, filePtr);

  //cert_len+3 bytes
  unsigned char cert_len3[3];
  int iCert_len3 = der_size + 3;
  cert_len3[2] = (iCert_len3 << 24) >> 24;
  cert_len3[1] = (iCert_len3 << 16) >> 24;
  cert_len3[0] = (iCert_len3 << 8) >> 24;
  fwrite(cert_len3, 3, 1, filePtr);

  //cert_len bytes
  unsigned char cert_len[3];
  int iCert_len = der_size;
  cert_len[2] = (iCert_len << 24) >> 24;
  cert_len[1] = (iCert_len << 16) >> 24;
  cert_len[0] = (iCert_len << 8) >> 24;
  fwrite(cert_len, 3, 1, filePtr);

  //cert bytes
  fwrite(buf, der_size, 1, filePtr);
  fclose(filePtr);
  return der_size+15;
}
  /////////////////////////////
  //SERVER CERTIFICATE MESSAGE FINISHED
  /////////////////////////////

  /////////////////////////////////
  //SERVER KEY EXCHANGE MESSAGE
  /////////////////////////////////

  //Message format
  //let len = (total length of message)-5
  //content_type(1 byte)
  //version (2 bytes)
  //len (2 bytes)
  //handshake_type=12 (1 byte)
  //len-9 (3 bytes)
  
  /*fwrite(&content_type, 1, 1, filePtr);
  fwrite(version, 2, 1, filePtr);

  FILE *key_file = fopen("server.key.der", "rb");
  if(!key_file)
  {
    cout << "Couldn't open key file for reading. Exiting" << endl;
    exit(1);
  }
  fseek(key_file, 0, SEEK_END);
  int key_size = ftell(key_file);
  fseek(key_file, 0, SEEK_SET);
  
  unsigned char key[key_size];
  fread(key, key_size, 1, key_file);
  
  fclose(key_file);

  int iKey_msg_len = key_size+4;
  unsigned char key_msg_len[2];
  key_msg_len[0] = (iKey_msg_len << 16) >> 24;
  key_msg_len[1] = (iKey_msg_len << 24) >> 24;
  fwrite(key_msg_len, 2, 1, filePtr);

  unsigned char ht_key = 12;
  fwrite(&ht_key, 1, 1, filePtr);
  
  unsigned char key_len[3];
  key_len[2] = (key_size << 24) >> 24;
  key_len[1] = (key_size << 16) >> 24;
  key_len[0] = (key_size << 8) >> 24;
  fwrite(key_len, 3, 1, filePtr);

  fwrite(key, key_size, 1, filePtr);*/

  ////////////////////////////
  //SERVER KEY EXCHANGE MESSAGE FINISHED
  ////////////////////////////

  ////////////////////////////
  //SERVER HELLO DONE MESSAGE
  //////////////////////////
int write_server_done_packet()
{
  FILE *filePtr = fopen("temp", "wb");
  fwrite(&content_type, 1, 1, filePtr);
  fwrite(version, 2, 1, filePtr);
  unsigned char hello_done[2] = {0, 4};
  fwrite(hello_done, 2, 1, filePtr);
  unsigned char hello_done_type = 14;
  fwrite(&hello_done_type, 1, 1, filePtr);
  unsigned char nil = 0;
  fwrite(&nil, 1, 1, filePtr); fwrite(&nil, 1, 1, filePtr); fwrite(&nil, 1, 1, filePtr);

  ///////////////////////////
  //SERVER HELLO DONE MESSAGE FINISHED
  ////////////////////////////

  fclose(filePtr);
  filePtr = fopen("temp", "rb");
  if(!filePtr)
  {
    cout << "Can't open file for reading. Exiting." << endl;
    exit(1);
  }
  fseek(filePtr, 0, SEEK_END);
  int temp_size = ftell(filePtr);
  fseek(filePtr, 0, SEEK_SET);
  fclose(filePtr);
  return temp_size;
}

void grab_server_packet(uchar *packet, int temp_size)
{
  FILE *filePtr = fopen("temp", "rb");
  fread(packet, temp_size, 1, filePtr); //packet is now filled
  fclose(filePtr);
  system("rm temp"); //don't forget to remove temp file
}

typedef struct {
  uint content_type;
  uint max_version;
  uint min_version;
  uint msg_len;
  uint handshake_type;
  uint len;
  uint premaster_len;
  uchar enc_premaster[64];
  uchar premaster[48];
  uchar master[48];
} ClientKeyExchange;

void SSL_PRF(uchar *key, uint key_size, uchar *label, uint label_size, uchar *seed, uint seed_size, int rounds, uchar *output, uint output_size)
{
  //now calculate the master secret
  uchar md5_a[rounds][16];
  uchar sha1_a[rounds][20];
  uint md5_len[rounds];
  uint sha1_len[rounds];

  //first split up the premaster into halves
  unsigned char s1[key_size/2];
  unsigned char s2[key_size/2];

 

  memcpy(s1, key, key_size/2);
  memcpy(s2, key+(key_size/2), key_size/2);

  //now we have the seed
  
  uchar random[seed_size+label_size];
  memcpy(random, label, label_size);
  memcpy(random+label_size, seed, seed_size);
  //random = a[0]

  
  
  //calculate the md5 a values
  HMAC(EVP_md5(), s1, sizeof(s1), random, sizeof(random), md5_a[0], &md5_len[0]);
  for(int i = 0; i < (rounds-1); i++)
    HMAC(EVP_md5(), s1, sizeof(s1), md5_a[i], md5_len[i], md5_a[i+1], &md5_len[i+1]);
  
  //calculate the sha1 a values
  HMAC(EVP_sha1(), s2, sizeof(s2), random, sizeof(random), sha1_a[0], &sha1_len[0]);
  for(int i = 0;i < (rounds-1); i++)
    HMAC(EVP_sha1(), s2, sizeof(s2), sha1_a[i], sha1_len[i], sha1_a[i+1], &sha1_len[i+1]);

  uchar md5_phash[rounds*16];
  uchar sha1_phash[rounds*20];

  uint md5_phash_len[rounds];
  uint sha1_phash_len[rounds];

  uchar a_md5_seed[16+sizeof(random)];
  uchar a_sha1_seed[20+sizeof(random)];

  //calc MD5 HMAC's
  int offset = 0;
  for(int i = 0; i < rounds; i++)
  {
    memcpy(a_md5_seed, md5_a[i], md5_len[i]);
    memcpy(a_md5_seed+md5_len[i], random, sizeof(random));
  
    HMAC(EVP_md5(), s1, sizeof(s1), a_md5_seed, sizeof(a_md5_seed), md5_phash+offset, &md5_phash_len[i]);

    offset += md5_phash_len[i];
  }

  //now calc the sha1 HMAC's
  offset = 0;
  for(int i = 0; i < rounds; i++)
  {
    memcpy(a_sha1_seed, sha1_a[i], sha1_len[i]);
    memcpy(a_sha1_seed+sha1_len[i], random, sizeof(random));

    HMAC(EVP_sha1(), s2, sizeof(s2), a_sha1_seed, sizeof(a_sha1_seed), sha1_phash+offset, &sha1_phash_len[i]);

    offset += sha1_phash_len[i];
  }

  //now calc the final result!
  for(int i = 0; i < output_size; i++)
    output[i] = md5_phash[i] ^ sha1_phash[i];
}

ClientKeyExchange parse_client_key_exchange_packet(uchar *buffer, Random server_random, Random client_random)
{
  if(buffer[5] == 16) //its a client key exchange message
  {
    FILE *pre_master_file = fopen("temp_pre_master", "wb");
    for(int i = 0; i < 64; i++)
      fwrite(&buffer[i+11], 1, 1, pre_master_file);
    fclose(pre_master_file);
  }
  else {
    cout << "Not a client key exchange message. Exiting" << endl;
    exit(1);
  }
  ClientKeyExchange ret;
  ret.content_type = 22;
  ret.max_version = 3;
  ret.min_version = 1;
  ret.msg_len = 70;
  ret.handshake_type = 16;
  ret.len = 66;
  ret.premaster_len = 64;
  
  system("openssl rsautl -in temp_pre_master -out plain_premaster -inkey server.key -decrypt");
  FILE *premaster_file = fopen("plain_premaster", "rb");
  if(!premaster_file) {
    cout << "Couldnt open premaster file. Exiting" << endl;
    exit(1);
  }
  fread(ret.premaster, 48, 1, premaster_file);
  fclose(premaster_file);
  system("rm temp_pre_master");
  system("rm plain_premaster");

  uchar seed[64];
  memcpy(seed, client_random.seed, sizeof(client_random.seed));
  memcpy(seed+sizeof(client_random.seed), server_random.seed, sizeof(server_random.seed));

  uchar label[] = "master secret";

  SSL_PRF(ret.premaster, sizeof(ret.premaster), label, 13, seed, sizeof(seed), 3, ret.master, sizeof(ret.master));
 
  return ret;
}

typedef struct {
  uchar content_type;
  uchar version[2];
  uchar len[2];
  uchar msg;
}ChangeCipherSpec;

ChangeCipherSpec parse_change_cipher_spec_message(uchar *buffer)
{
  ChangeCipherSpec ret;

  ret.content_type = buffer[0];
  ret.version[0] = buffer[1];
  ret.version[1] = buffer[2];
  ret.len[0] = buffer[3];
  ret.len[1] = buffer[4];
  ret.msg = buffer[5];

  return ret;
}

typedef struct {
  uchar content_type;
  uchar version[2];
  uchar len[2];
  uchar encrypted_data[32];
  uchar data[32];
} EncryptedHSMsg;

EncryptedHSMsg parse_encrypted_handshake_message(uchar *buffer, uchar *key)
{
  EncryptedHSMsg ret;

  ret.content_type = buffer[0];
  ret.version[0] = buffer[1];
  ret.version[1] = buffer[2];
  ret.len[0] = buffer[3];
  ret.len[1] = buffer[4];

  for(int i = 0; i < 32; i++)
    ret.encrypted_data[i] = buffer[i+5];

  RC4_KEY rc4_key;
  RC4_set_key(&rc4_key, 16, key+16);

  RC4(&rc4_key, 32, ret.encrypted_data, ret.data);

  return ret;
}

typedef struct {
  uchar key_block[80];
  uchar client_write_MAC_secret[16];
  uchar server_write_MAC_secret[16];
  uchar client_write_key[16];
  uchar server_write_key[16];
  uchar client_write_IV[8];
  uchar server_write_IV[8];
} KeyBlock;

KeyBlock generate_key_block(uchar *master_key, uint master_key_size, Random server_random, Random client_random)
{
  KeyBlock ret;

  //SSL_PRF(uchar *key, uchar *label, uchar *seed, int rounds, uchar *output)

  uchar seed[64];

  memcpy(seed, server_random.seed, 32);
  memcpy(seed+32, client_random.seed, 32);

  uchar label[] = "key expansion";
  
  SSL_PRF(master_key, master_key_size, label, 13, seed, sizeof(seed), 5, ret.key_block, sizeof(ret.key_block));

  //got the key block, now just divide it up properly
  
  int offset = 0;
  memcpy(ret.client_write_MAC_secret, ret.key_block, 16);
  offset += 16;
  
  memcpy(ret.server_write_MAC_secret, ret.key_block+offset, 16);
  offset += 16;
  
  memcpy(ret.client_write_key, ret.key_block+offset, 16);
  offset += 16;
  
  memcpy(ret.server_write_key, ret.key_block+offset, 16);
  
  
  //now grab the IV's

  uchar ivs[16];
  uchar null_key = '\0';
  uchar iv_label[] = "IV block";
  SSL_PRF(&null_key, 0, iv_label, sizeof(iv_label)-1, seed, 64, 1, ivs, 16);
  
  

  return ret;
}

uint write_change_cipher_spec_packet(RC4_KEY &rc4_key, uchar *mac_secret, uint mac_secret_len, uchar *master_secret, uint master_size, uchar *final_hash, uint final_hash_len)
{
  uint ret = 0;
  FILE *temp = fopen("temp", "wb");

  uchar content_type = 20;
  uchar version[2] = {3, 1};
  uchar len[2] = {0,1};
  uchar ccs_msg = 1;

  ret += fwrite(&content_type, 1, 1, temp);
  ret += fwrite(version, 2, 1, temp)*2;
  ret += fwrite(len, 2, 1, temp)*2;
  ret += fwrite(&ccs_msg, 1, 1, temp);

  content_type = 22;
  uchar len2[2] = {0, 32};
  
  ret += fwrite(&content_type, 1, 1, temp);
  ret += fwrite(version, 2, 1, temp)*2;
  ret += fwrite(len2, 2, 1, temp)*2;
  
  uchar msg_header[9] = {22,3,1,0,16,20, 0, 0, 12};

  uchar label[] = "server finished";
  debug("master secret = ", master_secret, master_size);

  //void SSL_PRF(uchar *key, uint key_size, uchar *label, uint label_size, uchar *seed, uint seed_size, int rounds, uchar *output, uint output_size)

  uchar prf_output[20];

  uchar md5_final_hash[16];
  uchar sha1_final_hash[20];

  MD5(final_hash, final_hash_len, md5_final_hash);
  SHA1(final_hash, final_hash_len, sha1_final_hash);

  uchar ultimate_hash[36];
  memcpy(ultimate_hash, md5_final_hash, 16);
  memcpy(ultimate_hash+16, sha1_final_hash, 20);

  SSL_PRF(master_secret, master_size, label, sizeof(label)-1, ultimate_hash, 36, 1, prf_output, 20);
  
  uchar enc_data[32];
  uchar plain_data[37];

  uchar mac[16];
  uint mac_len;

  //uchar enc_prf_output[12];

  //RC4(&mac_secret_key, 14, prf_output, enc_prf_output);
  
  memcpy(plain_data, msg_header, 9);
  memcpy(plain_data+9, prf_output, 12);
  

  HMAC(EVP_md5(), mac_secret, mac_secret_len, plain_data, sizeof(plain_data)-16, mac, &mac_len);  

  memcpy(plain_data+21, mac, 16);
  
  RC4(&rc4_key, 32, plain_data+5, enc_data);

  debug("mac_secret = ", mac_secret, 16);
  debug("mac = ", mac, 16);

  ret += fwrite(enc_data, 32, 1, temp)*32;

  fclose(temp);

  return ret;
}

#endif
