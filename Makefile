CC = gcc
CFLAGS = -Wall -Wextra -Iinclude -I/opt/homebrew/include
TARGET = bin/pktfilter
SRC = src/main.c src/capture.c

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) -L/opt/homebrew/lib -lpcap -lmaxminddb

clean:
	rm -f $(TARGET)