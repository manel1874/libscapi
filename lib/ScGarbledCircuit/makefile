uname_S := $(shell sh -c 'uname -s 2>/dev/null || echo not')

# compilation options
CXX=g++
CXXFLAGS=-fPIC -maes

INSTALL_INCLUDE_DIR=$(includedir)/ScGarbledCircuit
INSTALL_LIB_DIR=$(libdir)

ifeq ($(uname_S),Linux)
	INCLUDE_ARCHIVES_START = -Wl,-whole-archive
	INCLUDE_ARCHIVES_END = -Wl,-no-whole-archive -Wl,--no-undefined
	SHARED_LIB_OPT:=-shared
	SHARED_LIB_EXT:=.so
endif

ifeq ($(uname_S),Darwin)
	INCLUDE_ARCHIVES_START=-Wl,-all_load
	INCLUDE_ARCHIVES_END=
	SHARED_LIB_OPT:=-dynamiclib
	SHARED_LIB_EXT:=.dylib
endif

# openssl dependency
SOURCES = FreeXorGarbledBooleanCircuit.cpp GarbledBooleanCircuit.cpp \
	RowReductionGarbledBooleanCircuit.cpp StandardGarbledBooleanCircuit.cpp \
	HalfGatesGarbledBooleanCircuit.cpp TedKrovetzAesNiWrapperC.cpp 
OBJ_FILES = $(SOURCES:.cpp=.o)

## targets ##

# main target - linking individual *.o files
libScGarbledCircuit$(SHARED_LIB_EXT): $(OBJ_FILES)
	$(CXX) $(SHARED_LIB_OPT) -o $@ $(OBJ_FILES)

install:
	@echo "Installing ScGarbledCircuit..."
	install -d $(INSTALL_INCLUDE_DIR)
	install -d $(INSTALL_LIB_DIR)
	install -m 0644 *.h $(INSTALL_INCLUDE_DIR)
	install -m 0644 libScGarbledCircuit$(SHARED_LIB_EXT) $(INSTALL_LIB_DIR)
	@echo "Done."

# each source file is compiled seperately before linking
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $<

clean:
	rm -f *~
	rm -f *.o
	rm -f *.so
	rm -f *.dylib