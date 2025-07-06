cc = gcc
CFLAGS =   -std=c11 -I./include

SRC = src/aes_ecb.c src/aes_tables.c src/aes_cbc.c
TEST = test/main.c

all: aes_cbc

aes_test: $(SRC) $(TEST)
	$(CC) $(CFLAGS) -o aes_test $(SRC) $(TEST)

clean:
	rm -f aes_cbc

