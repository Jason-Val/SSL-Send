
all: sender

sender: main.c secure.o
	gcc main.c secure.o `pkg-config --cflags --libs gtk+-2.0` -lcrypto -o sender

secure.o: secure.c
	gcc secure.c secure.h -lcrypto -c
