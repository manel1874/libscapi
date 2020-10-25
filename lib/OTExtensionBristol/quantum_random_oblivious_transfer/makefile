CC = /usr/bin/gcc
CFLAGS = -g -O3 -Wall -Wextra
AS = $(CC) $(CFLAGS) -c

OBJS = qot_sender.o qot_receiver.o main.o
DEPS = qot_sender.h qot_receiver.h

###################################################

all: ot_test libqokdot

libqokdot: $(OBJS)
	$(AR) -crs libqokdot.a $(OBJS)

ot_test: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^

%.o: %.c $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $<

###################################################

.PHONY: clean

clean:
	-rm -f main_exe
	-rm -f *.o
	-rm -f libqokdot.a
