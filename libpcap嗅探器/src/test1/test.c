#include <pcap.h>
#include <stdio.h>

int main()
{
  char errBuf[PCAP_ERRBUF_SIZE], * device;
  
  device = pcap_lookupdev(errBuf);
  
  if(device)
  {
    printf("success: device: %s\n", device);
  }
  else
  {
    printf("error: %s\n", errBuf);
  }
  
  return 0;
}
