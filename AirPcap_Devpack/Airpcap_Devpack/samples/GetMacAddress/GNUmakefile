CFLAGS = -g -O -mno-cygwin -I ../../include -I ../..

OBJS = test2.o
LIBS = -L ../../lib -L ../../ -lairpcap

all: ${OBJS}
	${CC} ${CFLAGS} -o test2.exe ${OBJS} ${LIBS}

clean:
	rm -f ${OBJS} test2.exe

.c.o:
	${CC} ${CFLAGS} -c -o $*.o $<
