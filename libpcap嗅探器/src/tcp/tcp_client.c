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
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  
  struct sockaddr_in address;
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = inet_addr(SERVER_IP);
  address.sin_port = htons(PORT);
  
  /* connect to the server */
  int result = connect(sockfd, (struct sockaddr *)&address, sizeof(address));
  if(result == -1)
  {
    perror("connect failed: ");
    exit(1);
  }
  
  /* exchange data */
  char ch = 'A';
  write(sockfd, &ch, 1);
  read(sockfd, &ch, 1);
  printf("get char from server: %c\n", ch);
  
  /* close the socket */
  close(sockfd);
  
  return 0;
}
