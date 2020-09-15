all: dns-label

dns-label: main.cpp classifier.cpp dns.cpp flow.cpp
	g++ -o dns-label main.cpp classifier.cpp dns.cpp flow.cpp -g -lpcap -lnet

clean:
	rm -f *.o dns-label
