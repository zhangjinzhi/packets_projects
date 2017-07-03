CFLAGS = -g -O -mno-cygwin -I ../../include -I ../..

OBJS = test4.o
LIBS = -L ../../lib -L ../../ -lairpcap

all: ${OBJS}
	${CC} ${CFLAGS} -o test4.exe ${OBJS} ${LIBS}

clean:
	rm -f ${OBJS} test4.exe

.c.o:
	${CC} ${CFLAGS} -c -o $*.o $<
