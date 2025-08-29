CC = gcc
CFLAGS = -Wall -Wextra
TARGET = bin/pktfilter
SRC = src/main.c

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET)