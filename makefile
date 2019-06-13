export curdir=$(abspath)
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
C_FILES       := $(wildcard src/*/*.c)
OBJ_FILES     := $(patsubst src/%.cpp,obj/%.o,$(CPP_FILES))
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
	OUT_DIR        = obj obj/primitives obj/interactive_mid_protocols obj/mid_layer obj/comm obj/infra obj/cryptoInfra obj/circuits obj/circuits_c
	CPP_OPTIONS   := -g -std=$(GCC_STANDARD) $(INC) -mavx -maes -msse4.1 -mpclmul -Wall \
	-Wno-uninitialized -Wno-unused-but-set-variable -Wno-unused-function -Wno-unused-variable -Wno-unused-result \
	-Wno-sign-compare -Wno-parentheses -Wno-ignored-attributes -O3 -fPIC
endif
ifeq ($(uname_arch), aarch64)
	OUT_DIR        = obj obj/primitives obj/interactive_mid_protocols obj/mid_layer obj/comm obj/infra obj/cryptoInfra
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
    libs: compile-ntl compile-blake compile-emp-tool compile-emp-ot compile-emp-m2pc \
     compile-otextension-bristol compile-kcp
endif
ifeq ($(uname_arch), aarch64)
    libs:  compile-ntl compile-kcp
endif
endif # Linux c++11

ifeq ($(uname_os), Darwin)
    libs:  compile-ntl compile-blake compile-emp-tool compile-emp-ot compile-emp-m2pc \
    compile-kcp
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
	cd ./tests; ./tests.exe

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

prepare-emp:
	@mkdir -p $(builddir)/EMP
	@cp -r lib/EMP/relic $(builddir)/EMP/relic
	@cmake -DALIGN=16 -DARCH=X64 -DARITH=curve2251-sse -DCHECK=off -DFB_POLYN=251 \
	-DFB_METHD="INTEG;INTEG;QUICK;QUICK;QUICK;QUICK;LOWER;SLIDE;QUICK" -DFB_PRECO=on -DFB_SQRTF=off \
	-DEB_METHD="PROJC;LODAH;COMBD;INTER" -DEC_METHD="CHAR2" \
	-DCOMP="-O3 -funroll-loops -fomit-frame-pointer -march=native -msse4.2 -mpclmul \
	-Wno-unused-function -Wno-unused-variable -Wno-return-type -Wno-discarded-qualifiers" \
	-DTIMER=CYCLE -DWITH="MD;DV;BN;FB;EB;EC" -DWSIZE=64 $(builddir)/EMP/relic/CMakeLists.txt \
	-DCMAKE_INSTALL_PREFIX=$(prefix)
	@cd $(builddir)/EMP/relic && $(MAKE)
	@cd $(builddir)/EMP/relic && $(MAKE) install
	@touch prepare-emp

compile-emp-tool:prepare-emp
	@cp -r lib/EMP/emp-tool $(builddir)/EMP/emp-tool
	@cd $(builddir)/EMP/emp-tool
	@cmake -D CMAKE_CXX_FLAGS="-Wno-unused-function -Wno-unused-variable -Wno-return-type" \
	$(builddir)/EMP/emp-tool/CMakeLists.txt \
	-DCMAKE_INSTALL_PREFIX=$(prefix) -DRELIC_INCLUDE_DIR=$(prefix)/include -DRELIC_LIBRARY=$(prefix)/lib
	@cd $(builddir)/EMP/emp-tool/ && $(MAKE)
	@cd $(builddir)/EMP/emp-tool/ && $(MAKE) install
	@touch compile-emp-tool

compile-emp-ot:compile-emp-tool
	@cp -r lib/EMP/emp-ot $(builddir)/EMP/emp-ot
	@cd $(builddir)/EMP/emp-ot
	@cmake -D CMAKE_CXX_FLAGS="-Wno-unused-function -Wno-unused-variable -Wno-return-type" \
	$(builddir)/EMP/emp-ot/CMakeLists.txt \
	-DCMAKE_INSTALL_PREFIX=$(prefix) -DRELIC_INCLUDE_DIR=$(prefix)/include -DRELIC_LIBRARY=$(prefix)/lib \
	-DEMP-TOOL_INCLUDE_DIR=$(prefix)/include -DEMP-TOOL_LIBRARIES=$(prefix)/lib -DCMAKE_INSTALL_PREFIX=$(prefix)
	@cd $(builddir)/EMP/emp-ot/ && $(MAKE)
	@cd $(builddir)/EMP/emp-ot/ && $(MAKE) install
	@touch compile-emp-ot

compile-emp-m2pc:
	@cp -r lib/EMP/emp-m2pc $(builddir)/EMP/emp-m2pc
	@cd $(builddir)/EMP/emp-m2pc
	@cmake -D CMAKE_CXX_FLAGS="-Wno-unused-function -Wno-unused-variable -Wno-return-type" \
	$(builddir)/EMP/emp-m2pc/CMakeLists.txt \
	-DCMAKE_INSTALL_PREFIX=$(prefix)
	@cd $(builddir)/EMP/emp-m2pc/ && $(MAKE)
	@touch compile-emp-m2pc

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
ifeq ($(uname_os), Linux)
ifeq ($(uname_arch), x86_64)
	g++ -std=c++14 -mavx -maes -msse4.1 -mpclmul -mbmi2 -I/usr/include/openssl  -Iinstall/include -o tests/tests.exe \
	 tests/tests.cpp tests/interactiveMidProtocolsTests.cpp libscapi.a -lpthread -Linstall/lib \
	  -lboost_system -lboost_thread -lssl -lntl -lgmp -lcrypto -ldl -lz -Wno-narrowing;
endif
ifeq ($(uname_arch), aarch64)
	g++ -std=c++14 -I/usr/include/openssl  -Iinstall/include -o tests/tests.exe \
	 tests/tests.cpp tests/interactiveMidProtocolsTests.cpp libscapi.a -lpthread -Linstall/lib \
	  -lboost_system -lboost_thread -lssl -lntl -lgmp -lcrypto -ldl -lz -Wno-narrowing;
endif
endif

ifeq ($(uname_os), Darwin)
	g++ -std=c++14 -mavx -maes -msse4.1 -mpclmul -mbmi2 $(INC) -o tests/tests.exe \
	 tests/tests.cpp tests/interactiveMidProtocolsTests.cpp libscapi.a -Linstall/lib \
	  install/lib/libboost_system.a install/lib/libboost_thread.a install/lib/libssl.a install/lib/libcrypto.a install/lib/libntl.a -lgmp \
	  -ldl -lz -Wno-inconsistent-missing-override -Wno-expansion-to-defined -Wno-string-plus-int \
	  -Wno-mismatched-new-delete -Wno-delete-non-virtual-dtor -Wno-tautological-constant-out-of-range-compare
endif
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

clean-emp:
	@echo "Cleaning EMP library"
	@rm -rf $(builddir)/EMP/
	@rm -f prepare-emp compile-emp-tool compile-emp-ot compile-emp-m2pc

clean-emp-tool:
	@echo "Cleaning EMP tool library"
	@rm -rf $(builddir)/EMP/emp-tool
	@rm -rf $(builddir)/EMP/emp-ot
	@rm -rf $(builddir)/EMP/emp-m2pc
	@rm -f compile-emp-tool compile-emp-ot compile-emp-m2pc

clean-emp-ot:
	@echo "Cleaning EMP ot library"
	@rm -rf $(builddir)/EMP/emp-ot
	@rm -rf $(builddir)/EMP/emp-m2pc
	@rm -f compile-emp-ot compile-emp-m2pc

clean-emp-m2pc:
	@echo "Cleaning EMP m2pc library"
	@rm -rf $(builddir)/EMP/emp-m2pc
	@rm -f compile-emp-m2pc

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

clean-install:
	@rm -rf install

clean: clean-ntl  clean-emp clean-blake clean-emp clean-libote clean-otextension-bristol clean-kcp \
 clean-cpp clean-install

