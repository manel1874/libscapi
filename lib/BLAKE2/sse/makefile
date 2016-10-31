
CPP_OPTIONS   := -Wall -O3 

all:: 
	gcc  blake2b.c -c $(CPP_OPTIONS) -o blake2b.o
	gcc  blake2bp.c -c $(CPP_OPTIONS) -o blake2bp.o
	ar rcs blake2.a blake2b.o blake2bp.o
	ranlib blake2.a

clean::
	rm -f blake2.a
	rm -f ./*.o
