PCAP_PATH1 = ../../../../wpdpack/lib
PCAP_PATH2 = ../../../WinPcap_Devpack/lib
AIRPCAP_PATH1 = ../..
AIRPCAP_PATH2 = ../../lib
CFLAGS = -g -O -mno-cygwin -I ../.. -I ../../include -I ../../../../wpdpack/include -I ../../../WinPcap_Devpack/include

OBJS = test6.o RadiotapPrint.o
LIBS = -L${PCAP_PATH1} -L${PCAP_PATH2} -L${AIRPCAP_PATH1} -L${AIRPCAP_PATH2} -lwpcap -lairpcap -lwsock32

all: ${OBJS}
	${CC} ${CFLAGS} -o test6.exe ${OBJS} ${LIBS}

clean:
	rm -f ${OBJS} test6.exe

.c.o:
	${CC} ${CFLAGS} -c -o $*.o $<
