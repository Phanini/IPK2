NAME=ipk-sniffer
CC=gcc
CFLAGS=-Wall -Wextra -pedantic -lm -fcommon
LFLAG=-lpcap

run: ipk-sniffer.c
	${CC} ${CFLAGS} ipk-sniffer.c -o ${NAME} ${LFLAG}

.PHONY: clean
clean:
	rm -f ${NAME}

.PHONY: pack
pack: 
	zip xphanj00.zip ipk-sniffer.c Makefile README.md