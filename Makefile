CC=gcc
OSSL=/home/kevin/opt/openssl-1.0.1c
CFLAGS=-c -Wall -g -D_GNU_SOURCE -I$(OSSL)/include
SOURCES=$(wildcard *.c)
LDFLAGS=
LIBS=-lssl -lcrypto -ldl
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=verify-cc-tls

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@ $(LIBS) -L$(OSSL)

.c.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f *.o; rm -f $(EXECUTABLE)
