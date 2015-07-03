QUEUE_LIB=NFQUEUE
CC=gcc
CFLAGS= -D$(QUEUE_LIB)
INCLUDES        =       
LIBS    =       -lnetfilter_queue -lnfnetlink -pthread
OBJS    =       $(shell ls *.c | sed 's/[.]c/.o/')
SRC_C   =       $(shell ls *.c)
TARGET  =       nfqueue

all: $(TARGET)

$(OBJS): $(SRC_C)
	$(CC) -c $(INCLUDES) $(SRC_C)

$(TARGET): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LIBS) 
	strip $@

$(TARGET)-static: $(OBJS)
	$(CC) -static -o $@ $(OBJS) $(LIBS)
	strip $@

clean:
	rm -f *.o *~ $(TARGET)

install:
	install -m 755 $(TARGET) /usr/bin

.PHONY: clean
