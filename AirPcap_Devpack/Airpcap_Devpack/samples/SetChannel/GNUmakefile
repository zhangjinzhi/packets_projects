CFLAGS = -g -O -mno-cygwin -I ../../include -I ../..

OBJS = test1.o
LIBS = -L ../../lib -L ../../ -lairpcap

all: ${OBJS}
	${CC} ${CFLAGS} -o test1.exe ${OBJS} ${LIBS}

clean:
	rm -f ${OBJS} test1.exe

.c.o:
	${CC} ${CFLAGS} -c -o $*.o $<
