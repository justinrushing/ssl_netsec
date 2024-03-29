#include "definitions.h"

void error(const char *msg)
{
  perror(msg);
  exit(1);
}

class User
{
public:
  string username, password;
  User() {username = "test"; password = "test";}
};

string substr(string input, int begin, int end)
{
  string ret = "";
  for(int i = begin; i <= end; i++)
    ret += input[i];
  return ret;
}

int main(int argc, char *argv[])
{
  User user = User();
  //SSL_library_init();
  //SSL_load_error_strings();
  
  int sockfd, newsockfd, portno;
  socklen_t clilen;
  unsigned char request[1000];
  struct sockaddr_in serv_addr, cli_addr;

  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0)
    error("ERROR opening socket");
  bzero((char *) &serv_addr, sizeof(serv_addr));
  portno = atoi(argv[1]);
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = INADDR_ANY;
  serv_addr.sin_port = htons(portno);
  if (bind(sockfd, (struct sockaddr *) &serv_addr,
	   sizeof(serv_addr)) < 0)
    error("ERROR on binding");
  listen(sockfd,5);
  clilen = sizeof(cli_addr);
  
  int n;
  FILE *file;
  char *file_contents;
  char *packet;
  file = fopen("index.html", "r");
  fseek(file, 0, SEEK_END);
  int fsize = ftell(file);
  fseek(file, 0, SEEK_SET);
  char header[] = "HTTP/1.1 200 OK\r\nKeep-Alive: timeout=5, max=100\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length:";
  char resp[strlen(header)+9];
  sprintf(resp, "%s %d\r\n\r\n", header, fsize);
  file_contents = new char[fsize];
  packet = new char[fsize+strlen(resp)+3];
  fread(file_contents, 1, fsize-1, file);
  fclose(file);

  sprintf(packet, "%s%s\r\n", resp, file_contents);

  file = fopen("login.html", "r");
  fseek(file, 0, SEEK_END);
  int login_size = ftell(file);
  fseek(file, 0, SEEK_SET);
  char login_header[] = "HTTP/1.1 200 OK\r\nKeep-Alive: timeout=5, max=100\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length:";
  
  char login_resp[strlen(login_header)+9];
  sprintf(login_resp, "%s %d\r\n\r\n", login_header, login_size);
  char *login_contents = new char[login_size];
  char *login_packet = new char[login_size+strlen(login_resp)+3];
  fread(login_contents, 1, login_size-1, file);
  fclose(file);

  sprintf(login_packet, "%s%s\r\n", login_resp, login_contents);
  
  
  while(true) {  
    bzero(request, 1000);
    
    newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
    
    if(newsockfd < 0)
      error("ERROR on accept");
    
    memset(request, '\0', 1000);
    
    n = read(newsockfd, request, 1000);
    uchar client_hello_buffer[n];
    memcpy(client_hello_buffer, request, n);
    ClientHello ch_message = parse_client_hello(request);
    
    Random rand;
    int sh_size = write_server_hello_packet(rand);
    uchar sh_message[sh_size];
    grab_server_packet(sh_message, sh_size);
    n = write(newsockfd, sh_message, sh_size);
    int cert_message_size = write_server_certificate_packet();
    uchar cert_message[cert_message_size];
    grab_server_packet(cert_message, cert_message_size);
    n = write(newsockfd, cert_message, cert_message_size);
    int server_done_size = write_server_done_packet();
    uchar server_done[server_done_size];
    grab_server_packet(server_done, server_done_size);
    n = write(newsockfd, server_done, server_done_size);
    
    memset(request, '\0', 1000);
    
    n = read(newsockfd, request, 1000);
    uchar client_key_exchange_buffer[n];
    memcpy(client_key_exchange_buffer, request, n);
    uchar tstamp[4];
    memcpy(tstamp, ch_message.random.seed, 4);
    rand.reset_seed(tstamp);
    ClientKeyExchange cke;
    cke = parse_client_key_exchange_packet(request, rand,ch_message.random);

    ChangeCipherSpec ccs;
    ccs = parse_change_cipher_spec_message(request+75);

    EncryptedHSMsg ehsm;
    ehsm = parse_encrypted_handshake_message(request+81, cke.master);

    KeyBlock key_block = generate_key_block(cke.master, sizeof(cke.master), rand, ch_message.random);
    
    RC4_KEY decrypt_key;
    RC4_set_key(&decrypt_key, 16, key_block.client_write_key);
    RC4(&decrypt_key, 32, ehsm.encrypted_data, ehsm.data);

    uchar verify[12];
    uchar mac[16];
    memcpy(verify, ehsm.data+4, 12);
    memcpy(mac, ehsm.data+16, 16);

    
    

    uchar entire_message[29];
    memcpy(entire_message+8+5, ehsm.data, 16);

    uchar record_header[] = {22, 3, 1, 0, 16};
    memcpy(entire_message+8, record_header, 5);

    uchar sequence_num[8]; memset(sequence_num, 0, 8);
    
    uchar entire_message_md5[16]; uint em_len;
      
    memcpy(entire_message, sequence_num, 8);
    HMAC(EVP_md5(), key_block.client_write_MAC_secret, 16, entire_message, 29, entire_message_md5, &em_len);
     
     
    
    
    
    

    //double check the MAC
    /*uint mac_check_size = sh_size + cert_message_size + server_done_size;
    uchar mac_check[mac_check_size];
    uint c = 0;
    memcpy(mac_check, sh_message, sh_size);
    c += sh_size;
    memcpy(mac_check+c, cert_message, cert_message_size);
    c += cert_message_size;
    memcpy(mac_check+c, server_done, server_done_size);

    uchar md5_mac_check[16];
    uchar sha1_mac_check[20];

    MD5(mac_check, mac_check_size, md5_mac_check);
    SHA1(mac_check, mac_check_size, sha1_mac_check);

    uchar mac_check_concat[36];

    memcpy(mac_check_concat, md5_mac_check, 16);
    memcpy(mac_check_concat+16, sha1_mac_check, 20);

    uchar mac_out[20];
    uchar label[] = "client finished";
    SSL_PRF(cke.master, sizeof(cke.master), label, sizeof(label)-1, mac_check_concat, 36, 1, mac_out, 20);

    debug("MAC_OUT = ", mac_out, 12);
    */
    //its a finished message, so we decrypted correctly
    if(ehsm.data[0] != 20)
    {
      cout << "message either wasn't properly decrypted or its the wrong type. exiting\n";
      exit(1);
    }

    RC4_KEY encrypt_key;
    RC4_set_key(&encrypt_key, 16, key_block.server_write_key);
    RC4_KEY server_mac_secret;
    RC4_set_key(&server_mac_secret, 16, key_block.server_write_MAC_secret);

    int total_hash_len = sizeof(client_hello_buffer)-5 + sizeof(client_key_exchange_buffer)-15;// + sh_size-5 + cert_message_size-5 + server_done_size-5;
    uchar total_hash[total_hash_len];
    uint offset = 0;
    memcpy(total_hash, client_hello_buffer+5, sizeof(client_hello_buffer)-5);
    offset += sizeof(client_hello_buffer)-5;
    //memcpy(total_hash+offset, sh_message+5, sh_size-5);
    //offset += sh_size-5;
    //memcpy(total_hash + offset, cert_message+5, cert_message_size-5);
    //offset += cert_message_size-5;
    //memcpy(total_hash+offset, server_done+5, server_done_size-5);
    //offset += server_done_size-5;
    uchar CKE[cke.msg_len];
    uchar CCS = 1;
    uchar EHSM[32];
    memcpy(CKE, client_key_exchange_buffer+5, cke.msg_len);
    memcpy(EHSM, client_key_exchange_buffer+16+cke.msg_len, 32);
    memcpy(total_hash+offset, CKE, cke.msg_len);
    offset += cke.msg_len;
    memcpy(total_hash+offset, EHSM, 32);

    
    

    uchar md5[16];
    uchar sha1[20];
    MD5(total_hash, total_hash_len, md5);
    SHA1(total_hash, total_hash_len, sha1);
    uchar ms[36];
    memcpy(ms, md5, 16);
    memcpy(ms, sha1, 20);
    uchar prfout[20];
    uchar client_finished[] = "client finished";
    SSL_PRF(cke.master, sizeof(cke.master), client_finished, sizeof(client_finished)-1, ms, 36, 1, prfout, 20);
    
    

    int sccs_size = write_change_cipher_spec_packet(encrypt_key, key_block.server_write_MAC_secret, sizeof(key_block.server_write_MAC_secret), cke.master, sizeof(cke.master), total_hash, total_hash_len);
    uchar sccs[sccs_size];
    
    grab_server_packet(sccs, sccs_size);
    debug("plaintext sent out = ", sccs, sccs_size);
    n = write(newsockfd, sccs, sccs_size);
    

    /*
    string req = string(request);
    if(req.find("/login") != string::npos) //trying to login, grab params
    {
      int end = req.size() - 1;
      int logIdx = req.find("login=");
      int passIdx = req.find("&password=");
      string user_input = substr(req, logIdx+6, passIdx-1);
      string password_input = substr(req, passIdx+10, end);
      cout << "\nUSERNAME: " << user_input << endl;
      cout << "PASSWORD: " << password_input << endl << endl;
      if(user.username == user_input && user.password == password_input) //successful!
	n = write(newsockfd, login_packet, strlen(login_packet)+1);
      else //login failed
	n = write(newsockfd, packet, strlen(packet)+1); 
    }
    else
    n = write(newsockfd, packet, strlen(packet)+1);*/
    
    close(newsockfd);
    
  }
  delete [] file_contents;
  delete [] packet;
  close(sockfd);
  return 0;
}
