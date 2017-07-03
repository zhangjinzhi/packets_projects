CFLAGS = -g -O -mno-cygwin -I ../../include -I ../..

OBJS = test11.o PpiPrint.o
LIBS = -L ../../lib -L ../../ -lairpcap -lwsock32

all: ${OBJS}
	${CC} ${CFLAGS} -o test11.exe ${OBJS} ${LIBS}

clean:
	rm -f ${OBJS} test11.exe

.c.o:
	${CC} ${CFLAGS} -c -o $*.o $<
