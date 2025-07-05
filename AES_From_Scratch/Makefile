cc = gcc
CFLAGS =   -std=c11 -I./include

SRC = src/aes_ecb.c src/aes_tables.c
TEST = test/main.c

all: aes_test

aes_test: $(SRC) $(TEST)
	$(CC) $(CFLAGS) -o aes_test $(SRC) $(TEST)

clean:
	rm -f aes_test

