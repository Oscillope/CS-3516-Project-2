CC = gcc
CFLAGS = -Wall

all: wireview
debug: CFLAGS = -Wall -DDEBUG
debug: wireview
wireview: wireview.o
	$(CC) $(CFLAGS) -lpcap wireview.o -o wireview
wireview.o:
	$(CC) $(CFLAGS) -lpcap -c wireview.c
clean:
	rm -f *~ *.o
