CFLAGS = -g -O -mno-cygwin -I ../../include -I ../..

OBJS = test5.o RadiotapPrint.o
LIBS = -L ../../lib -L ../../ -lairpcap -lwsock32

all: ${OBJS}
	${CC} ${CFLAGS} -o test5.exe ${OBJS} ${LIBS}

clean:
	rm -f ${OBJS} test5.exe

.c.o:
	${CC} ${CFLAGS} -c -o $*.o $<
