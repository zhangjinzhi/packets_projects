CFLAGS = -g -O -mno-cygwin -I ../../include -I ../..

OBJS = test14.o
LIBS = -L ../../lib -L ../../ -lairpcap

all: ${OBJS}
	${CC} ${CFLAGS} -o HwTimestamp.exe ${OBJS} ${LIBS}

clean:
	rm -f ${OBJS} HwTimestamp.exe

.c.o:
	${CC} ${CFLAGS} -c -o $*.o $<
