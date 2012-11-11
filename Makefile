CC = gcc
CFLAGS = -Wall

all: wireview
debug: CFLAGS = -Wall -DDEBUG
debug: wireview
wireview: wireview.o
	$(CC) $(CFLAGS) wireview.o -o wireview -lpcap 
wireview.o:
	$(CC) $(CFLAGS) -c wireview.c -lpcap 
clean:
	rm -f *~ *.o
