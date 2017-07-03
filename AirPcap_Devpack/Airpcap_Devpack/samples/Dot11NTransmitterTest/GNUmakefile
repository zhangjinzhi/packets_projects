PCAP_PATH1 = ../../../../wpdpack/lib
PCAP_PATH2 = ../../../WinPcap_Devpack/lib
CFLAGS = -g -O -mno-cygwin -I ../../include -I ../.. -I ../../../../wpdpack/include -I ../../../WinPcap_Devpack/include

OBJS = Dot11NTransmitterTest.o
LIBS = -L ../../lib -L ../../ -lairpcap -L${PCAP_PATH1} -L${PCAP_PATH2} -lwpcap

all: ${OBJS}
	${CC} ${CFLAGS} -o Dot11NTransmitterTest.exe ${OBJS} ${LIBS}

clean:
	rm -f ${OBJS} Dot11NTransmitterTest.exe

.c.o:
	${CC} ${CFLAGS} -c -o $*.o $<

