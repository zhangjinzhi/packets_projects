#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#define PORT 9832
#define SERVER_IP "192.168.56.101"

int main()
{
  /* create a socket */
  int server_sockfd = socket(AF_INET, SOCK_STREAM, 0);
  
  struct sockaddr_in server_addr;
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);
  server_addr.sin_port = htons(PORT);
  
  /* bind with the local file */
  bind(server_sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr));
  
  /* listen */
  listen(server_sockfd, 5);
  
  char ch;
  int client_sockfd;
  struct sockaddr_in client_addr;
  socklen_t len = sizeof(client_addr);
  while(1)
  {
    printf("server waiting:\n");
    
    /* accept a connection */
    client_sockfd = accept(server_sockfd, (struct sockaddr *)&client_addr, &len);
    
    /* exchange data */
    read(client_sockfd, &ch, 1);
    printf("get char from client: %c\n", ch);
    ++ch;
    write(client_sockfd, &ch, 1);
    
    /* close the socket */
    close(client_sockfd);
  }
  
  return 0;
}
