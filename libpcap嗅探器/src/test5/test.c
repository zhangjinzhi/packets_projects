#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main()
{
  /* ask pcap to find a valid device for use to sniff on */
  char * dev;   /* name of the device */ 
  char errbuf[PCAP_ERRBUF_SIZE];
  dev = pcap_lookupdev(errbuf);

  /* error checking */
  if(!dev)
  {
    printf("pcap_lookupdev() error: %s\n", errbuf);
    exit(1);
  }

  /* print out device name */
  printf("dev name: %s\n", dev);

  /* ask pcap for the network address and mask of the device */
  bpf_u_int32 netp;   /* ip */
  bpf_u_int32 maskp;  /* subnet mask */
  int ret;            /* return code */
  ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);

  if(ret == -1)
  {
    printf("pcap_lookupnet() error: %s\n", errbuf);
    exit(1);
  }

  /* get the network address in a human readable form */
  char * net;   /* dot notation of the network address */
  char * mask;  /* dot notation of the network mask */
  struct in_addr addr;

  addr.s_addr = netp;
  net = inet_ntoa(addr);

  if(!net)
  {
    perror("inet_ntoa() ip error: ");
    exit(1);
  }

  printf("ip: %s\n", net);

  /* do the same as above for the device's mask */
  addr.s_addr = maskp;
  mask = inet_ntoa(addr);
  
  if(!mask)
  {
    perror("inet_ntoa() sub mask error: ");
    exit(1);
  }
  
  printf("sub mask: %s\n", mask);

  return 0;
}
