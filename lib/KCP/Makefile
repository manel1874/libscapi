CPP_OPTIONS   := -Wall -O3 -std=c11 -fPIC

all::
	gcc  ikcp.c -c $(CPP_OPTIONS) -o ikcp.o
	ar rcs ikcp.a ikcp.o
	ranlib ikcp.a

clean::
	rm -f ikcp.a
	rm -f ./*.o
