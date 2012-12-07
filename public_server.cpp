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

using namespace std;

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
  int sockfd, newsockfd, portno;
  socklen_t clilen;
  char request[1000];
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
  
  while(true)
  {
    bzero(request, 1000);
    newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
    if(newsockfd < 0)
      error("ERROR on accept");
    n = read(newsockfd, request, 1000);
    cout << request;
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
      n = write(newsockfd, packet, strlen(packet)+1);
 
    close(newsockfd);
  }
  delete [] file_contents;
  delete [] packet;
  close(sockfd);
  return 0;
}
