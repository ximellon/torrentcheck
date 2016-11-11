CFLAGS := -O

all: torrentcheck

clean:
	rm *.o

torrentcheck: torrentcheck.o sha1.o
	$(CC) -o $@ $^ $(CFLAGS)
