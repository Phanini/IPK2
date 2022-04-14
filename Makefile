NAME=ipk-sniffer
CC=g++
CFLAGS=-Wall -Wextra -pedantic -lm -fcommon
LFLAG=-lpcap

run: ipk-sniffer.cpp
	${CC} ${CFLAGS} ipk-sniffer.cpp -o ${NAME} ${LFLAG}

.PHONY: clean
clean:
	rm -f ${NAME}

.PHONY: pack
pack: 
	zip xphanj00.zip ipk-sniffer.cpp Makefile README.md