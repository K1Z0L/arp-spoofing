LDLIBS=-lpcap

all: arp-spoof

arp-spoof: main.o ip.o mac.o
	g++ $^ $(LDLIBS) -g -Wall -o $@

clean:
	rm -f arp-spoof *.o