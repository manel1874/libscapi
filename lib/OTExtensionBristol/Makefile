LDLIBS = -lpthread -lrt

CC = g++
CFLAGS = -g -Wextra -Wall -Wno-unused-function -Wno-unused-variable -Wno-unused-but-set-variable -Wno-return-type -Wno-unused-result -Wno-non-template-friend $(LIBOPT) -O3 -pthread -maes -mpclmul -msse4.1 -msse2 -I. -fPIC
CPPFLAGS = $(CFLAGS)

TOOLS = $(patsubst %.cpp,%.o,$(wildcard Tools/*.cpp))
NETWORK = $(patsubst %.cpp,%.o,$(wildcard Networking/*.cpp))
OT = $(patsubst %.cpp,%.o,$(wildcard OT/*.cpp))
COMMON = $(TOOLS) $(NETWORK)

#LIBSIMPLEOT = SimpleOT/libsimpleot.a
LIBQOKDOT = quantum_random_oblivious_transfer/libqokdot.a


all: lib 

lib: $(COMPLETE) $(OT) $(COMMON)
	#@echo "compling simple ot..........................."
	#cd SimpleOT && make
	cd quantum_random_oblivious_transfer && make	
	@echo "compling .a ...................."
	$(AR) -crs libOTExtensionBristol.a $^ 

install:
	install -d $(libdir)
	install -d $(includedir)/OTExtensionBristol
	install -d $(includedir)/OTExtensionBristol/OT
	install -d $(includedir)/OTExtensionBristol/Tools
	install -d $(includedir)/OTExtensionBristol/Networking
	install -d $(includedir)/OTExtensionBristol/Exceptions
	install -m 0644 libOTExtensionBristol.a $(libdir)
	install -m 0644 ${LIBQOKDOT} $(libdir)
	install -m 0644 OT/*.h $(includedir)/OTExtensionBristol/OT
	install -m 0644 Tools/*.h $(includedir)/OTExtensionBristol/Tools
	install -m 0644 Networking/*.h $(includedir)/OTExtensionBristol/Networking
	install -m 0644 Exceptions/*.h $(includedir)/OTExtensionBristol/Exceptions


clean:
	cd SimpleOT && make clean
	-rm */*.o *.a

