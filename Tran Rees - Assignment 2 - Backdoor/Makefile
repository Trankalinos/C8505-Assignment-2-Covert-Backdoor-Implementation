# make for backdoor

CC=gcc
CFLAGS=-Wall -ggdb

default: backdoor.o 
	$(CC) $(CFLAGS) backdoor.o -o backdoor -lpcap

clean:
	rm -f *.o *.bak *.out ex

covert_tcp.o: backdoor.c
	$(CC) $(CFLAGS) -O -c backdoor.c -lpcap
