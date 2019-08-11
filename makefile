export curdir=$(shell pwd)
export builddir=$(abspath ./build)
export prefix=$(abspath ./install)
CXX=g++
uname_os := $(shell uname)
uname_arch := $(shell uname -m)
ARCH := $(shell getconf LONG_BIT)
SHARED_LIB_EXT:=.so
INCLUDE_ARCHIVES_START = -Wl,-whole-archive # linking options, we prefer our generated shared object will be self-contained.
INCLUDE_ARCHIVES_END = -Wl,-no-whole-archive 
SHARED_LIB_OPT:=-shared

export uname_os
export ARCH
export SHARED_LIB_EXT
export INCLUDE_ARCHIVES_START
export INCLUDE_ARCHIVES_END
export SHARED_LIB_OPT
export exec_prefix=$(prefix)
export includedir=$(prefix)/include
export bindir=$(exec_prefix)/bin
export libdir=$(prefix)/lib

SLib           = libscapi.a
CPP_FILES     := $(wildcard src/*/*.cpp)
CPP_FILES     += $(wildcard tools/circuits/scapiBristolConverter/*.cpp)
CPP_FILES     += $(wildcard tools/circuits/scapiNecConverter/*.cpp)
CPP_FILES     += $(wildcard src/*/*.cpp)
C_FILES       := $(wildcard src/*/*.c)
OBJ_FILES     := $(patsubst src/%.cpp,obj/%.o,$(CPP_FILES))
OBJ_FILES     += $(patsubst tools/circuits/scapiBristolConverter/%.cpp,obj/tools/scapiBristolConverter/%.o,$(CPP_FILES))
OBJ_FILES     += $(patsubst tools/circuits/scapiNecConverter/%.cpp,obj/tools/scapiNecConverter/%.o,$(CPP_FILES))
OBJ_FILES     += $(patsubst src/%.c,obj/%.o,$(C_FILES))
GCC_STANDARD = c++14

ifeq ($(uname_os), Linux)
	INC            = -Iinstall/include -Iinstall/include/OTExtensionBristol -Iinstall/include/libOTe \
	 -Iinstall/include/libOTe/cryptoTools
    LIBRARIES_DIR  = -Linstall/lib
endif
ifeq ($(uname_os), Darwin)
    INC            = -Iinstall/include -Iinstall/include/OTExtensionBristol -Iinstall/include/libOTe \
    -Iinstall/include/libOTe/cryptoTools
    LIBRARIES_DIR  = -Linstall/lib
endif

ifeq ($(uname_arch), x86_64)
	OUT_DIR        = obj obj/primitives obj/interactive_mid_protocols obj/mid_layer obj/comm obj/infra obj/cryptoInfra \
	obj/circuits obj/circuits_c obj/tools/scapiNecConverter obj/tools/scapiBristolConverter
	CPP_OPTIONS   := -g -std=$(GCC_STANDARD) $(INC) -mavx -maes -msse4.1 -mpclmul -Wall \
	-Wno-uninitialized -Wno-unused-but-set-variable -Wno-unused-function -Wno-unused-variable -Wno-unused-result \
	-Wno-sign-compare -Wno-parentheses -Wno-ignored-attributes -O3 -fPIC
endif
ifeq ($(uname_arch), armv7l)
	OUT_DIR        = obj obj/primitives obj/interactive_mid_protocols obj/mid_layer obj/comm obj/infra obj/cryptoInfra \
	obj/tools/scapiNecConverter obj/tools/scapiBristolConverter
	CPP_OPTIONS   := -g -std=$(GCC_STANDARD) $(INC) -mfpu=neon -Wall -Wno-narrowing -Wno-uninitialized \
	-Wno-unused-but-set-variable -Wno-unused-function -Wno-unused-variable -Wno-unused-result \
	-Wno-sign-compare -Wno-parentheses -Wno-ignored-attributes -O3 -fPIC
endif
ifeq ($(uname_arch), aarch64)
	OUT_DIR        = obj obj/primitives obj/interactive_mid_protocols obj/mid_layer obj/comm obj/infra obj/cryptoInfra \
	obj/tools/scapiNecConverter obj/tools/scapiBristolConverter
	CPP_OPTIONS   := -g -std=$(GCC_STANDARD) $(INC) -Wall -Wno-narrowing -Wno-uninitialized \
	-Wno-unused-but-set-variable -Wno-unused-function -Wno-unused-variable -Wno-unused-result \
	-Wno-sign-compare -Wno-parentheses -Wno-ignored-attributes -O3 -fPIC
endif

$(COMPILE.cpp) = g++ -c $(CPP_OPTIONS) -o $@ $<

LD_FLAGS =

all: libs libscapi tests

ifeq ($(GCC_STANDARD), c++11)
ifeq ($(uname_os), Linux)
ifeq ($(uname_arch), x86_64)
    libs: compile-ntl compile-blake compile-otextension-bristol compile-kcp
endif
ifeq ($(uname_arch), armv7l)
    libs:  compile-ntl compile-kcp
endif
ifeq ($(uname_arch), aarch64)
    libs:  compile-ntl compile-kcp
endif
endif # Linux c++11

ifeq ($(uname_os), Darwin)
    libs:  compile-ntl compile-blake compile-kcp
endif # Darwin c++11
endif # c++11

##### c++14 #####
ifeq ($(GCC_STANDARD), c++14)
ifeq ($(uname_os), Linux)
ifeq ($(uname_arch), x86_64)
    libs: compile-ntl compile-blake compile-libote compile-otextension-bristol compile-kcp
endif
ifeq ($(uname_arch), aarch64)
    libs:  compile-ntl compile-kcp
endif
endif # Linux c++14
ifeq ($(uname_os), Darwin)
    libs:  compile-libote compile-ntl compile-blake
endif # Darwin c++14
endif

libscapi: directories $(SLib)
directories: $(OUT_DIR)

$(OUT_DIR):
	mkdir -p $(OUT_DIR)

$(SLib): $(OBJ_FILES)
	ar ru $@ $^ 
	ranlib $@

tests: compile-tests

obj/circuits_c/%.o: src/circuits_c/%.c
	gcc -fPIC -mavx -maes -mpclmul -DRDTSC -DTEST=AES128  -O3 -c -o $@ $<
obj/circuits/%.o: src/circuits/%.cpp
	g++ -c $(CPP_OPTIONS) -o $@ $<
obj/comm/%.o: src/comm/%.cpp
	g++ -c $(CPP_OPTIONS) -o $@ $<
obj/commClient/%.o: src/commClient/%.cpp
	g++ -c $(CPP_OPTIONS) -o $@ $<
obj/infra/%.o: src/infra/%.cpp
	g++ -c $(CPP_OPTIONS) -o $@ $< 	 
obj/interactive_mid_protocols/%.o: src/interactive_mid_protocols/%.cpp
	g++ -c $(CPP_OPTIONS) -o $@ $< 	 
obj/primitives/%.o: src/primitives/%.cpp
	g++ -c $(CPP_OPTIONS) -o $@ $< 	 
obj/mid_layer/%.o: src/mid_layer/%.cpp
	g++ -c $(CPP_OPTIONS) -o $@ $<
obj/cryptoInfra/%.o: src/cryptoInfra/%.cpp
	g++ -c $(CPP_OPTIONS) -o $@ $<
obj/tools/scapiNecConverter/%.o: tools/circuits/scapiNecConverter/%.cpp
	g++ -c $(CPP_OPTIONS) -o $@ $<
obj/tools/scapiBristolConverter/%.o: tools/circuits/scapiBristolConverter/%.cpp
	g++ -c $(CPP_OPTIONS) -o $@ $<

#### libs compilation ####
compile-ntl:
	echo "Compiling the NTL library..."
	mkdir -p $(builddir)/NTL
	cp -r lib/NTL/. $(builddir)/NTL
	chmod 777 $(builddir)/NTL/src/configure
	cd $(builddir)/NTL/src/ && ./configure CXX=$(CXX)
	$(MAKE) -C $(builddir)/NTL/src/
	$(MAKE) -C $(builddir)/NTL/src/ PREFIX=$(prefix) install
	@touch compile-ntl

compile-blake:
	@echo "Compiling the BLAKE2 library"
	@mkdir -p $(builddir)/BLAKE2/
	@cp -r lib/BLAKE2/sse/. $(builddir)/BLAKE2
	@$(MAKE) -C $(builddir)/BLAKE2
	@$(MAKE) -C $(builddir)/BLAKE2 BUILDDIR=$(builddir)  install
	@touch compile-blake

# Support only in c++14
compile-libote:
	@echo "Compiling libOTe library..."
	@cp -r lib/libOTe $(builddir)/libOTe
ifeq ($(uname_os), Darwin)
	@cd $(builddir)/libOTe/cryptoTools/thirdparty/miracl/source && bash linux64 && cd ../../../../../../
endif
	@cmake $(builddir)/libOTe/CMakeLists.txt -DCMAKE_BUILD_TYPE=Release -DLIBSCAPI_ROOT=$(PWD)
	@$(MAKE) -C $(builddir)/libOTe/
	@cp $(builddir)/libOTe/lib/*.a install/lib/
	@mv install/lib/liblibOTe.a install/lib/libOTe.a
	$(info$(shell mkdir -p install/include/libOTe))
	@cd $(builddir)/libOTe/ && find . -name "*.h" -type f |xargs -I {} cp --parents {} $(PWD)/install/include/libOTe
ifeq ($(uname_os), Linux)
	@cp -r $(builddir)/libOTe/cryptoTools/cryptoTools/gsl $(PWD)/install/include/libOTe/cryptoTools/cryptoTools
endif
ifeq ($(uname_os), Darwin)
	@cp -R $(builddir)/libOTe/cryptoTools/cryptoTools/gsl $(PWD)/install/include/libOTe/cryptoTools/cryptoTools
endif
	@cp $(builddir)/libOTe/cryptoTools/thirdparty/miracl/source/libmiracl.a install/lib
	@touch compile-libote

compile-otextension-bristol:
	@echo "Compiling the OtExtension malicious Bristol library..."
	@cp -r lib/OTExtensionBristol $(builddir)/OTExtensionBristol
	@$(MAKE) -C $(builddir)/OTExtensionBristol CXX=$(CXX)
	@$(MAKE) -C $(builddir)/OTExtensionBristol CXX=$(CXX) install
	@touch compile-otextension-bristol

compile-kcp:
	@echo "Compiling the KCP library"
	@mkdir -p $(builddir)/KCP
	@cp -r lib/KCP/ $(builddir)/
	@$(MAKE) -C $(builddir)/KCP
	@mkdir -p install/include/KCP
	@cp -r $(builddir)/KCP/*.h install/include/KCP
	@mv $(builddir)/KCP/ikcp.a install/lib
	@touch compile-kcp

#### Tests compilation ####
.PHONY: compile-tests
compile-tests:
	@rm -rf tests/CMakeCache.txt tests/CMakeFiles/ tests/cmake_install.cmake
	@cmake -DSCAPI_BASE_DIR=$(curdir) ./tests/CMakeLists.txt
	@$(MAKE) -C tests/
	@cd tests && ./ScapiTests
	@rm -rf build

#### cleanning objects ####
clean-ntl:
	@echo "Cleaning the ntl build dir..."
	@rm -rf $(builddir)/NTL
	@rm -f compile-ntl

clean-blake:
	@echo "Cleaning blake library"
	@rm -rf $(builddir)/BLAKE2
	@rm -f compile-blake

clean-libote:
	@echo "Cleaning libOTe library"
	@rm -rf $(builddir)/libOTe/
	@rm -f compile-libote

clean-otextension-bristol:
	@echo "Cleaning the otextension malicious bristol build dir..."
	@rm -rf $(builddir)/OTExtensionBristol
	@rm -f compile-otextension-bristol

clean-kcp:
	@echo "Cleaning KCP library"
	@rm -rf $(builddir)/KCP/
	@rm -f compile-kcp

clean-cpp:
	@echo "cleaning .obj files"
	@rm -rf $(OUT_DIR)
	@echo "cleaning lib"
	@rm -f $(SLib)
	@rm -f tests/ScapiTests

clean-install:
	@rm -rf install

clean: clean-ntl clean-blake clean-libote clean-otextension-bristol clean-kcp clean-cpp clean-install

