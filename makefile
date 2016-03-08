export builddir=$(abspath ./build)
export prefix=$(abspath ./install)
CXX=g++
uname_S := $(shell sh -c 'uname -s 2>/dev/null || echo not')
ARCH := $(shell getconf LONG_BIT)
export uname_S
export ARCH

SLib           = scapi.a
CPP_FILES     := $(wildcard src/*/*.cpp)
OBJ_FILES     := $(patsubst src/%.cpp,obj/%.o,$(CPP_FILES))
OUT_DIR        = obj obj/circuits obj/comm obj/infra obj/interactive_mid_protocols obj/primitives
INC            = -I../boost_1_60_0 -Ilib -Iinstall/include 
CPP_OPTIONS   := -std=c++11 $(INC)  -maes -mpclmul -DBOOST_LOG_DYN_LINK
$(COMPILE.cpp) = g++ -c $(CPP_OPTIONS) -o $@ $<

all:: directories $(SLib)

directories: $(OUT_DIR)

$(OUT_DIR):
	mkdir -p $(OUT_DIR)

$(SLib): compile-miracl compile-miracl-cpp $(OBJ_FILES)
	ar ru $@ $^ 
	ranlib $@

obj/circuits/%.o: src/circuits/%.cpp
	g++ -c $(CPP_OPTIONS) -o $@ $< 	 
obj/comm/%.o: src/comm/%.cpp
	g++ -c $(CPP_OPTIONS) -o $@ $< 	 
obj/infra/%.o: src/infra/%.cpp
	g++ -c $(CPP_OPTIONS) -o $@ $< 	 
obj/interactive_mid_protocols/%.o: src/interactive_mid_protocols/%.cpp
	g++ -c $(CPP_OPTIONS) -o $@ $< 	 
obj/primitives/%.o: src/primitives/%.cpp
	g++ -c $(CPP_OPTIONS) -o $@ $< 	 

tests:: all
	$(Program)

prepare-miracl::
	@echo "Copying the miracl source files into the miracl build dir..."
	@mkdir -p $(builddir)/$(MIRACL_DIR)
	@find lib/Miracl/ -type f -exec cp '{}' $(builddir)/$(MIRACL_DIR)/ \;
	@rm -f $(builddir)/$(MIRACL_DIR)/mirdef.h
	@rm -f $(builddir)/$(MIRACL_DIR)/mrmuldv.c
	@cp -r lib/MiraclCompilation/* $(builddir)/$(MIRACL_DIR)/

compile-miracl::
	@$(MAKE) prepare-miracl MIRACL_DIR=Miracl
	@echo "Compiling the Miracl library (C)..."
	@$(MAKE) -C $(builddir)/Miracl MIRACL_TARGET_LANG=c
	@echo "Installing the Miracl library..."
	@$(MAKE) -C $(builddir)/Miracl MIRACL_TARGET_LANG=c install
	@touch compile-miracl

compile-miracl-cpp::
	@$(MAKE) prepare-miracl MIRACL_DIR=MiraclCPP CXX=$(CXX)
	@echo "Compiling the Miracl library (C++)..."
	@$(MAKE) -C $(builddir)/MiraclCPP MIRACL_TARGET_LANG=cpp CXX=$(CXX)
	@echo "Installing the Miracl library..."
	@$(MAKE) -C $(builddir)/MiraclCPP MIRACL_TARGET_LANG=cpp CXX=$(CXX) install
	@touch compile-miracl-cpp

clean-miracl:
	@echo "Cleaning the miracl build dir..."
	@rm -rf $(builddir)/Miracl
	@rm -f compile-miracl

clean-miracl-cpp:
	@echo "Cleaning the miracl build dir..."
	@rm -rf $(builddir)/MiraclCPP
	@rm -f compile-miracl-cpp

clean-cpp:
	@echo "cleaning .obj files"
	@rm -rf $(OUT_DIR)
	@echo "cleaning lib"
	@rm -f $(SLib)

clean-install:
	@rm -rf install/*

clean: clean-miracl clean-miracl-cpp clean-cpp clean-install
