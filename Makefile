CC = g++
CFLAGS = -Wall

all: wireview
debug: CFLAGS = -Wall -DDEBUG
debug: wireview
wireview: wireview.o
	$(CC) $(CFLAGS) wireview.o -o wireview -lpcap 
wireview.o:
	$(CC) $(CFLAGS) -c wireview.cpp -lpcap 
clean:
	rm -f *~ *.o
