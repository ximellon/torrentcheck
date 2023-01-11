PROJECT := torrentcheck
CFLAGS := -O -DICONV_IMPLEMENTATION
OBJS := src/torrentcheck.o src/sha1.o
RM := rm -f

all: $(PROJECT)

$(PROJECT): $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@

%.o: %.c
	$(CC) -c $(CFLAGS) $< -o $@

clean:
	$(RM) $(OBJS) $(PROJECT)
