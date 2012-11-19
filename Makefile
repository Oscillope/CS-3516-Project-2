CC = g++
CFLAGS = -Wall

all: wireview
debug: CFLAGS += -DDEBUG
debug: wireview
vulgar: CFLAGS += -DVULGAR
vulgar: wireview
wireview: wireview.o
	$(CC) $(CFLAGS) wireview.o -o wireview -lpcap 
wireview.o:
	$(CC) $(CFLAGS) -c wireview.cpp -lpcap 
clean:
	rm -f *~ *.o
