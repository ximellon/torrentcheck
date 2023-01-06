PROJECT := torrentcheck
CFLAGS := -O

all: $(PROJECT)

clean:
	rm *.o $(PROJECT)

$(PROJECT): torrentcheck.o sha1.o
	$(CC) -o $@ $^ $(CFLAGS)
