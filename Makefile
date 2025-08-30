CC = gcc
CFLAGS = -Wall -Wextra -Iinclude
TARGET = bin/pktfilter
SRC = src/main.c src/capture.c

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) -lpcap

clean:
	rm -f $(TARGET)