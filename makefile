export builddir=$(abspath ./build)
export prefix=$(abspath ./install)
CXX=g++
uname_S := $(shell sh -c 'uname -s 2>/dev/null || echo not')
ARCH := $(shell getconf LONG_BIT)
SHARED_LIB_EXT:=.so
INCLUDE_ARCHIVES_START = -Wl,-whole-archive # linking options, we prefer our generated shared object will be self-contained.
INCLUDE_ARCHIVES_END = -Wl,-no-whole-archive 
SHARED_LIB_OPT:=-shared

export uname_S
export ARCH
export SHARED_LIB_EXT
export INCLUDE_ARCHIVES_START
export INCLUDE_ARCHIVES_END
export SHARED_LIB_OPT
export exec_prefix=$(prefix)
export includedir=$(prefix)/include
export bindir=$(exec_prefix)/bin
export libdir=$(prefix)/lib

SLib           = scapi.a
CPP_FILES     := $(wildcard src/*/*.cpp)
C_FILES     := $(wildcard src/*/*.c)
OBJ_FILES     := $(patsubst src/%.cpp,obj/%.o,$(CPP_FILES))
OBJ_FILES     += $(patsubst src/%.c,obj/%.o,$(C_FILES))
OUT_DIR        = obj obj/mid_layer obj/circuits obj/comm obj/infra obj/interactive_mid_protocols obj/primitives obj/circuits_c
INC            = -I$(HOME)/boost_1_64_0 -Ilib -Iinstall/include -Ilib/OTExtensionBristol
CPP_OPTIONS   := -std=c++11 $(INC)  -maes -mpclmul -Wall -Wno-unused-function -Wno-unused-variable -fPIC -O3
$(COMPILE.cpp) = g++ -c $(CPP_OPTIONS) -o $@ $<
LINKER_OPTIONS = $(INCLUDE_ARCHIVES_START) install/lib/libOTExtensionBristol.a install/lib/libsimpleot.a install/lib/libntl.a install/lib/libmiracl.a install/lib/libblake2.a -lpthread -lgmp -lcrypto -lssl -lboost_system -lboost_thread -lOTExtension -lMaliciousOTExtension -ldl $(INCLUDE_ARCHIVES_END)
LIBRARIES_DIR  = -L$(HOME)/boost_1_64_0/stage/lib -Linstall/lib
LD_FLAGS = 

all: libs libscapi
libs: compile-emp-tool compile-emp-ot compile-emp-m2pc compile-ntl compile-blake compile-miracl compile-otextension compile-otextension-malicious compile-otextension-bristol
libscapi: directories $(SLib)
directories: $(OUT_DIR)

$(OUT_DIR):
	mkdir -p $(OUT_DIR)

$(SLib): $(OBJ_FILES)
	ar ru $@ $^ 
	ranlib $@

obj/circuits/%.o: src/circuits/%.cpp
	g++ -c $(CPP_OPTIONS) -o $@ $< 	 
obj/circuits_c/%.o: src/circuits_c/%.c
	gcc -fPIC -mavx -maes -mpclmul -DRDTSC -DTEST=AES128  -O3 -c -o $@ $< 
obj/comm/%.o: src/comm/%.cpp
	g++ -c $(CPP_OPTIONS) -o $@ $< 	 
obj/infra/%.o: src/infra/%.cpp
	g++ -c $(CPP_OPTIONS) -o $@ $< 	 
obj/interactive_mid_protocols/%.o: src/interactive_mid_protocols/%.cpp
	g++ -c $(CPP_OPTIONS) -o $@ $< 	 
obj/primitives/%.o: src/primitives/%.cpp
	g++ -c $(CPP_OPTIONS) -o $@ $< 	 
obj/mid_layer/%.o: src/mid_layer/%.cpp
	g++ -c $(CPP_OPTIONS) -o $@ $<
 

tests:: all
	$(Program)

prepare-emp:
	@mkdir -p $(builddir)/EMP
	@cp -r lib/EMP/. $(builddir)/EMP
	@cmake -DALIGN=16 -DARCH=X64 -DARITH=curve2251-sse -DCHECK=off -DFB_POLYN=251 -DFB_METHD="INTEG;INTEG;QUICK;QUICK;QUICK;QUICK;LOWER;SLIDE;QUICK" -DFB_PRECO=on -DFB_SQRTF=off -DEB_METHD="PROJC;LODAH;COMBD;INTER" -DEC_METHD="CHAR2" -DCOMP="-O3 -funroll-loops -fomit-frame-pointer -march=native -msse4.2 -mpclmul" -DTIMER=CYCLE -DWITH="MD;DV;BN;FB;EB;EC" -DWORD=64 $(builddir)/EMP/relic/CMakeLists.txt
	@cd $(builddir)/EMP/relic && $(MAKE)
	@cd $(builddir)/EMP/relic && $(MAKE) install
	@touch prepare-emp

compile-emp-tool:prepare-emp
	@cd $(builddir)/EMP/emp-tool
	@cmake $(builddir)/EMP/emp-tool/CMakeLists.txt 
	@cd $(builddir)/EMP/emp-tool/ && $(MAKE)
	@cd $(builddir)/EMP/emp-tool/ && $(MAKE) install
	@touch compile-emp-tool

compile-emp-ot:prepare-emp
	@cd $(builddir)/EMP/emp-ot
	@cmake $(builddir)/EMP/emp-ot/CMakeLists.txt 
	@cd $(builddir)/EMP/emp-ot/ && $(MAKE)
	@cd $(builddir)/EMP/emp-ot/ && $(MAKE) install
	@touch compile-emp-ot

compile-emp-m2pc:compile-emp-ot compile-emp-tool
	@cd $(builddir)/EMP/emp-m2pc
	@cmake $(builddir)/EMP/emp-m2pc/CMakeLists.txt 
	@cd $(builddir)/EMP/emp-m2pc/ && $(MAKE)
	@touch compile-emp-m2pc

compile-blake:
	@echo "Compiling the BLAKE2 library"
	@mkdir -p $(builddir)/BLAKE2/
	@cp -r lib/BLAKE2/sse/. $(builddir)/BLAKE2
	@$(MAKE) -C $(builddir)/BLAKE2
	@$(MAKE) -C $(builddir)/BLAKE2 BUILDDIR=$(builddir)  install
#	@ cp $(builddir)/BLAKE2/libblake2.a install/lib/
	@touch compile-blake

compile-ntl:
	@echo "Compiling the NTL library..."
	@mkdir -p $(builddir)/NTL
	@cp -r lib/NTL/unix/. $(builddir)/NTL
	@chmod 777 $(builddir)/NTL/src/configure
	@cd $(builddir)/NTL/src/ && ./configure CXX=$(CXX)
	@$(MAKE) -C $(builddir)/NTL/src/
	@$(MAKE) -C $(builddir)/NTL/src/ PREFIX=$(prefix) install
	@touch compile-ntl

prepare-miracl:
	@echo "Copying the miracl source files into the miracl build dir..."
	@mkdir -p $(builddir)/$(MIRACL_DIR)
	@find lib/Miracl/ -type f -exec cp '{}' $(builddir)/$(MIRACL_DIR)/ \;
	@rm -f $(builddir)/$(MIRACL_DIR)/mirdef.h
	@rm -f $(builddir)/$(MIRACL_DIR)/mrmuldv.c
	@cp -r lib/MiraclCompilation/* $(builddir)/$(MIRACL_DIR)/

compile-miracl:
	@$(MAKE) prepare-miracl MIRACL_DIR=Miracl
	@echo "Compiling the Miracl library (C)..."
	@$(MAKE) -C $(builddir)/Miracl MIRACL_TARGET_LANG=c
	@echo "Installing the Miracl library..."
	@$(MAKE) -C $(builddir)/Miracl MIRACL_TARGET_LANG=c install
	@touch compile-miracl

compile-miracl-cpp:
	@$(MAKE) prepare-miracl MIRACL_DIR=MiraclCPP CXX=$(CXX)
	@echo "Compiling the Miracl library (C++)..."
	@$(MAKE) -C $(builddir)/MiraclCPP MIRACL_TARGET_LANG=cpp CXX=$(CXX)
	@echo "Installing the Miracl library..."
	@$(MAKE) -C $(builddir)/MiraclCPP MIRACL_TARGET_LANG=cpp CXX=$(CXX) install
	@touch compile-miracl-cpp

compile-otextension: compile-miracl-cpp
	@echo "Compiling the OtExtension library..."
	@cp -r lib/OTExtension $(builddir)/OTExtension
	@$(MAKE) -C $(builddir)/OTExtension CXX=$(CXX)
	@$(MAKE) -C $(builddir)/OTExtension CXX=$(CXX) SHARED_LIB_EXT=$(SHARED_LIB_EXT) install
	@touch compile-otextension
	
compile-otextension-malicious: compile-miracl-cpp
	@echo "Compiling the OtExtension malicious library..."
	@cp -r lib/MaliciousOTExtension $(builddir)/MaliciousOTExtension
	@$(MAKE) -C $(builddir)/MaliciousOTExtension CXX=$(CXX)
	@$(MAKE) -C $(builddir)/MaliciousOTExtension CXX=$(CXX) SHARED_LIB_EXT=$(SHARED_LIB_EXT) install
	@touch compile-otextension-malicious

compile-otextension-bristol: 
	@echo "Compiling the OtExtension malicious Bristol library..."
	@cp -r lib/OTExtensionBristol $(builddir)/OTExtensionBristol
	@$(MAKE) -C $(builddir)/OTExtensionBristol CXX=$(CXX)
	@$(MAKE) -C $(builddir)/OTExtensionBristol CXX=$(CXX) install
	@touch compile-otextension-bristol

clean-miracl:
	@echo "Cleaning the miracl build dir..."
	@rm -rf $(builddir)/Miracl
	@rm -f compile-miracl

clean-miracl-cpp:
	@echo "Cleaning the miracl build dir..."
	@rm -rf $(builddir)/MiraclCPP
	@rm -f compile-miracl-cpp

clean-otextension:
	@echo "Cleaning the otextension build dir..."
	@rm -rf $(builddir)/OTExtension
	@rm -f compile-otextension
	
clean-otextension-malicious:
	@echo "Cleaning the otextension malicious build dir..."
	@rm -rf $(builddir)/MaliciousOTExtension
	@rm -f compile-otextension-malicious

clean-otextension-bristol:
	@echo "Cleaning the otextension malicious bristol build dir..."
	@rm -rf $(builddir)/OTExtensionBristol
	@rm -f compile-otextension-bristol

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
	@rm -rf $(builddir)/EMP
	@rm -f prepare-emp compile-emp-tool compile-emp-ot compile-emp-m2pc

clean-cpp:
	@echo "cleaning .obj files"
	@rm -rf $(OUT_DIR)
	@echo "cleaning lib"
	@rm -f $(SLib)

clean-install:
	@rm -rf install/*

clean: clean-emp clean-otextension-bristol clean-otextension-malicious clean-otextension clean-ntl clean-blake clean-miracl clean-miracl-cpp clean-cpp clean-install
