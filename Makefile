PROJECT := torrentcheck
CFLAGS := -O
OBJS := src/torrentcheck.o src/sha1.o
RM := rm -f

all: $(PROJECT)

$(PROJECT): $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@

%.c: %.o
	$(CC) -c $(CFLAGS) $^ -o $@

clean:
	$(RM) $(OBJS) $(PROJECT)
